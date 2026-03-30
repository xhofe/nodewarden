import { Env, User, ProfileResponse, DEFAULT_DEV_SECRET } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { LIMITS } from '../config/limits';
import { isTotpEnabled, verifyTotpToken } from '../utils/totp';
import { createRecoveryCode, recoveryCodeEquals } from '../utils/recovery-code';
import { base64UrlToBytes, bytesToBase64Url, parseClientData, readAuthenticatorCounter, verifyAssertionSignature } from '../utils/passkey';
import { buildAccountKeys } from '../utils/user-decryption';

function looksLikeEncString(value: string): boolean {
  if (!value) return false;
  const firstDot = value.indexOf('.');
  if (firstDot <= 0 || firstDot === value.length - 1) return false;
  const payload = value.slice(firstDot + 1);
  const parts = payload.split('|');
  // Bitwarden encrypted payloads should have at least IV + ciphertext.
  return parts.length >= 2;
}

/**
 * Validate KDF parameters according to Bitwarden minimum requirements.
 * Returns an error message if invalid, or null if OK.
 */
function validateKdfParams(kdfType: number | undefined, kdfIterations: number | undefined, kdfMemory?: number | undefined, kdfParallelism?: number | undefined): string | null {
  const type = kdfType ?? 0;
  if (type === 0) {
    // PBKDF2-SHA256: minimum 100 000 iterations
    if (typeof kdfIterations === 'number' && kdfIterations < 100_000) {
      return 'PBKDF2 iterations must be at least 100000';
    }
  } else if (type === 1) {
    // Argon2id: iterations >= 2, memory >= 16 MiB, parallelism >= 1
    if (typeof kdfIterations === 'number' && kdfIterations < 2) {
      return 'Argon2id iterations must be at least 2';
    }
    if (typeof kdfMemory === 'number' && kdfMemory < 16) {
      return 'Argon2id memory must be at least 16 MiB';
    }
    if (typeof kdfParallelism === 'number' && kdfParallelism < 1) {
      return 'Argon2id parallelism must be at least 1';
    }
  }
  return null;
}

function normalizeTotpSecret(input: string): string {
  const raw = String(input || '').toUpperCase();
  let out = '';
  for (const char of raw) {
    if (char === ' ' || char === '\t' || char === '\n' || char === '\r' || char === '-') continue;
    out += char;
  }
  while (out.endsWith('=')) {
    out = out.slice(0, -1);
  }
  return out;
}

function normalizeRecoveryCodeInput(input: string): string {
  return String(input || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
}

function normalizeMasterPasswordHint(input: string | null | undefined): string | null {
  const normalized = String(input || '').trim();
  return normalized ? normalized : null;
}

function jwtSecretUnsafeReason(env: Env): 'missing' | 'default' | 'too_short' | null {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret) return 'missing';
  if (secret === DEFAULT_DEV_SECRET) return 'default';
  if (secret.length < LIMITS.auth.jwtSecretMinLength) return 'too_short';
  return null;
}

async function verifyUserSecret(
  auth: AuthService,
  user: User,
  secret: string | null | undefined
): Promise<boolean> {
  const normalized = String(secret || '').trim();
  if (!normalized) return false;
  return auth.verifyPassword(normalized, user.masterPasswordHash, user.email);
}

function toProfile(user: User, env: Env): ProfileResponse {
  void env;
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    emailVerified: true,
    premium: true,
    premiumFromOrganization: false,
    usesKeyConnector: false,
    masterPasswordHint: user.masterPasswordHint,
    culture: 'en-US',
    twoFactorEnabled: !!user.totpSecret,
    key: user.key,
    privateKey: user.privateKey,
    accountKeys: buildAccountKeys(user),
    securityStamp: user.securityStamp || user.id,
    organizations: [],
    providers: [],
    providerOrganizations: [],
    forcePasswordReset: false,
    avatarColor: null,
    creationDate: user.createdAt,
    verifyDevices: user.verifyDevices,
    role: user.role,
    status: user.status,
    object: 'profile',
  };
}

interface PasskeyAssertionRequest {
  id?: string;
  rawId?: string;
  response?: {
    clientDataJSON?: string;
    authenticatorData?: string;
    signature?: string;
  };
  type?: string;
}

function getPasskeyOriginAndRpId(request: Request): { origin: string; rpId: string } {
  const url = new URL(request.url);
  return { origin: url.origin, rpId: url.hostname };
}

function randomPasskeyChallenge(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToBase64Url(bytes);
}

// POST /api/accounts/register
// - First user becomes admin.
// - Any subsequent user must provide a valid inviteCode.
export async function handleRegister(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);

  const unsafe = jwtSecretUnsafeReason(env);
  if (unsafe) {
    const message = unsafe === 'missing'
      ? 'JWT_SECRET is not set'
      : unsafe === 'default'
        ? 'JWT_SECRET is using the default/sample value. Please change it.'
        : 'JWT_SECRET must be at least 32 characters';
    return errorResponse(message, 400);
  }

  let body: {
    email?: string;
    name?: string;
    masterPasswordHash?: string;
    key?: string;
    kdf?: number;
    kdfIterations?: number;
    kdfMemory?: number;
    kdfParallelism?: number;
    inviteCode?: string;
    masterPasswordHint?: string;
    keys?: {
      publicKey?: string;
      encryptedPrivateKey?: string;
    };
  };

  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = body.email?.toLowerCase().trim();
  const name = body.name?.trim() || email;
  const masterPasswordHash = body.masterPasswordHash;
  const key = body.key;
  const privateKey = body.keys?.encryptedPrivateKey;
  const publicKey = body.keys?.publicKey;
  const inviteCode = (body.inviteCode || '').trim();
  const masterPasswordHint = normalizeMasterPasswordHint(body.masterPasswordHint);

  if (!email || !masterPasswordHash || !key) {
    return errorResponse('Email, masterPasswordHash, and key are required', 400);
  }
  if (!email.includes('@') || email.length < 3) {
    return errorResponse('Invalid email address', 400);
  }
  if (!privateKey || !publicKey) {
    return errorResponse('Private key and public key are required', 400);
  }
  if (!looksLikeEncString(key)) {
    return errorResponse('key is not a valid encrypted string', 400);
  }
  if (!looksLikeEncString(privateKey)) {
    return errorResponse('encryptedPrivateKey is not a valid encrypted string', 400);
  }
  if (masterPasswordHint && masterPasswordHint.length > 120) {
    return errorResponse('masterPasswordHint must be 120 characters or fewer', 400);
  }

  const kdfErr = validateKdfParams(body.kdf, body.kdfIterations, body.kdfMemory, body.kdfParallelism);
  if (kdfErr) return errorResponse(kdfErr, 400);

  const now = new Date().toISOString();
  const auth = new AuthService(env);
  const serverHash = await auth.hashPasswordServer(masterPasswordHash, email);

  const user: User = {
    id: generateUUID(),
    email,
    name: name || email,
    masterPasswordHint,
    masterPasswordHash: serverHash,
    key,
    privateKey,
    publicKey,
    kdfType: body.kdf ?? 0,
    kdfIterations: body.kdfIterations ?? LIMITS.auth.defaultKdfIterations,
    kdfMemory: body.kdfMemory,
    kdfParallelism: body.kdfParallelism,
    securityStamp: generateUUID(),
    role: 'user',
    status: 'active',
    verifyDevices: true,
    totpSecret: null,
    totpRecoveryCode: null,
    createdAt: now,
    updatedAt: now,
  };

  const userCount = await storage.getUserCount();
  if (userCount === 0) {
    user.role = 'admin';
    const created = await storage.createFirstUser(user);
    if (!created) {
      return errorResponse('Registration is temporarily unavailable, retry once', 409);
    }
    await storage.setRegistered();
    await storage.createAuditLog({
      id: generateUUID(),
      actorUserId: user.id,
      action: 'user.register.first_admin',
      targetType: 'user',
      targetId: user.id,
      metadata: JSON.stringify({ email: user.email }),
      createdAt: now,
    });
    return jsonResponse({ success: true, role: user.role }, 200);
  }

  if (!inviteCode) {
    return errorResponse('Invite code is required', 403);
  }

  try {
    await storage.createUser(user);
  } catch (error) {
    const msg = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
    if (msg.includes('unique') || msg.includes('constraint')) {
      return errorResponse('Email already registered', 409);
    }
    throw error;
  }

  const inviteMarked = await storage.markInviteUsed(inviteCode, user.id);
  if (!inviteMarked) {
    await storage.deleteUserById(user.id);
    return errorResponse('Invite code is invalid or expired', 403);
  }

  await storage.createAuditLog({
    id: generateUUID(),
    actorUserId: user.id,
    action: 'user.register.invite',
    targetType: 'user',
    targetId: user.id,
    metadata: JSON.stringify({ email: user.email, inviteCode }),
    createdAt: now,
  });

  return jsonResponse({ success: true, role: user.role }, 200);
}

// POST /api/accounts/password-hint
export async function handleGetPasswordHint(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const clientIdentifier = getClientIdentifier(request);
  if (!clientIdentifier) {
    return errorResponse('Client IP is required', 403);
  }

  let body: { email?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = String(body.email || '').trim().toLowerCase();
  if (!email) {
    return errorResponse('Email is required', 400);
  }

  const rateLimit = new RateLimitService(env.DB);
  const minuteBudget = await rateLimit.consumeBudgetWithWindow(
    `${clientIdentifier}:password-hint`,
    LIMITS.rateLimit.passwordHintRequestsPerMinute,
    60
  );
  if (!minuteBudget.allowed) {
    return new Response(
      JSON.stringify({
        error: 'Too many requests',
        error_description: `Rate limit exceeded. Try again in ${minuteBudget.retryAfterSeconds || 60} seconds.`,
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(minuteBudget.retryAfterSeconds || 60),
          'X-RateLimit-Remaining': '0',
        },
      }
    );
  }

  const hourlyBudget = await rateLimit.consumeBudgetWithWindow(
    `${clientIdentifier}:password-hint-hour`,
    LIMITS.rateLimit.passwordHintRequestsPerHour,
    60 * 60
  );
  if (!hourlyBudget.allowed) {
    return new Response(
      JSON.stringify({
        error: 'Too many requests',
        error_description: `Rate limit exceeded. Try again in ${hourlyBudget.retryAfterSeconds || 3600} seconds.`,
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(hourlyBudget.retryAfterSeconds || 3600),
          'X-RateLimit-Remaining': '0',
        },
      }
    );
  }

  const user = await storage.getUser(email);
  const hint = user?.status === 'active' ? normalizeMasterPasswordHint(user.masterPasswordHint) : null;
  return jsonResponse({
    object: 'passwordHint',
    hasHint: !!hint,
    masterPasswordHint: hint,
  });
}

// GET /api/accounts/profile
export async function handleGetProfile(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);
  return jsonResponse(toProfile(user, env));
}

// PUT /api/accounts/profile
export async function handleUpdateProfile(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: {
    masterPasswordHint?: string | null;
  };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const masterPasswordHint = normalizeMasterPasswordHint(body.masterPasswordHint);
  if (masterPasswordHint && masterPasswordHint.length > 120) {
    return errorResponse('masterPasswordHint must be 120 characters or fewer', 400);
  }

  user.masterPasswordHint = masterPasswordHint;
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);

  return jsonResponse(toProfile(user, env));
}

// PUT/POST /api/accounts/verify-devices
export async function handleSetVerifyDevices(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: {
    secret?: string;
    masterPasswordHash?: string;
    verifyDevices?: boolean;
  };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (typeof body.verifyDevices !== 'boolean') {
    return errorResponse('verifyDevices must be true or false', 400);
  }

  const verified = await verifyUserSecret(auth, user, body.secret || body.masterPasswordHash);
  if (!verified) {
    return errorResponse('User verification failed.', 400);
  }

  user.verifyDevices = body.verifyDevices;
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);

  return new Response(null, { status: 200 });
}

// POST /api/accounts/keys
export async function handleSetKeys(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);

  if (!user) {
    return errorResponse('User not found', 404);
  }

  let body: {
    masterPasswordHash?: string;
    key?: string;
    encryptedPrivateKey?: string;
    publicKey?: string;
  };

  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  // Require password verification before allowing key replacement.
  if (!body.masterPasswordHash) {
    return errorResponse('masterPasswordHash is required', 400);
  }
  const passwordValid = await auth.verifyPassword(body.masterPasswordHash, user.masterPasswordHash, user.email);
  if (!passwordValid) {
    return errorResponse('Invalid password', 400);
  }

  if (body.key && !looksLikeEncString(body.key)) {
    return errorResponse('key is not a valid encrypted string', 400);
  }
  if (body.encryptedPrivateKey && !looksLikeEncString(body.encryptedPrivateKey)) {
    return errorResponse('encryptedPrivateKey is not a valid encrypted string', 400);
  }

  if (body.key) user.key = body.key;
  if (body.encryptedPrivateKey) user.privateKey = body.encryptedPrivateKey;
  if (body.publicKey) user.publicKey = body.publicKey;
  user.updatedAt = new Date().toISOString();

  await storage.saveUser(user);

  return handleGetProfile(request, env, userId);
}

// POST/PUT /api/accounts/password
export async function handleChangePassword(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: {
    masterPasswordHash?: string;
    currentPasswordHash?: string;
    newMasterPasswordHash?: string;
    key?: string;
    newKey?: string;
    encryptedPrivateKey?: string;
    newEncryptedPrivateKey?: string;
    publicKey?: string;
    newPublicKey?: string;
    kdf?: number;
    kdfIterations?: number;
    kdfMemory?: number;
    kdfParallelism?: number;
  };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const currentHash = body.currentPasswordHash || body.masterPasswordHash;
  if (!currentHash) return errorResponse('Current password hash is required', 400);
  const valid = await auth.verifyPassword(currentHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  if (!body.newMasterPasswordHash) {
    return errorResponse('newMasterPasswordHash is required', 400);
  }
  const nextKey = body.newKey || body.key;
  const nextPrivateKey = body.newEncryptedPrivateKey || body.encryptedPrivateKey;
  const nextPublicKey = body.newPublicKey || body.publicKey;
  if (nextKey && !looksLikeEncString(nextKey)) {
    return errorResponse('new key is not a valid encrypted string', 400);
  }
  if (nextPrivateKey && !looksLikeEncString(nextPrivateKey)) {
    return errorResponse('new encryptedPrivateKey is not a valid encrypted string', 400);
  }

  const kdfErr = validateKdfParams(body.kdf ?? user.kdfType, body.kdfIterations, body.kdfMemory, body.kdfParallelism);
  if (kdfErr) return errorResponse(kdfErr, 400);

  user.masterPasswordHash = await auth.hashPasswordServer(body.newMasterPasswordHash, user.email);
  if (nextKey) user.key = nextKey;
  if (nextPrivateKey) user.privateKey = nextPrivateKey;
  if (nextPublicKey) user.publicKey = nextPublicKey;
  if (typeof body.kdf === 'number') user.kdfType = body.kdf;
  if (typeof body.kdfIterations === 'number') user.kdfIterations = body.kdfIterations;
  if (typeof body.kdfMemory === 'number') user.kdfMemory = body.kdfMemory;
  if (typeof body.kdfParallelism === 'number') user.kdfParallelism = body.kdfParallelism;
  user.securityStamp = generateUUID();
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);
  await storage.deleteRefreshTokensByUserId(user.id);
  await storage.createAuditLog({
    id: generateUUID(),
    actorUserId: user.id,
    action: 'user.password.change',
    targetType: 'user',
    targetId: user.id,
    metadata: JSON.stringify({ email: user.email }),
    createdAt: user.updatedAt,
  });

  return new Response(null, { status: 200 });
}

// GET /api/accounts/totp
export async function handleGetTotpStatus(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  return jsonResponse({
    enabled: !!user.totpSecret,
    object: 'twoFactor',
  });
}

// PUT /api/accounts/totp
// enable: { enabled: true, secret: "...", token: "123456" }
// disable: { enabled: false, masterPasswordHash: "..." }
export async function handleSetTotpStatus(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: { enabled?: boolean; secret?: string; token?: string; masterPasswordHash?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (body.enabled === true) {
    const normalizedSecret = normalizeTotpSecret(body.secret || '');
    if (!isTotpEnabled(normalizedSecret)) {
      return errorResponse('Invalid TOTP secret', 400);
    }
    if (!body.token) {
      return errorResponse('TOTP token is required', 400);
    }
    const verified = await verifyTotpToken(normalizedSecret, body.token);
    if (!verified) {
      return errorResponse('Invalid TOTP token', 400);
    }
    user.totpSecret = normalizedSecret;
    if (!user.totpRecoveryCode) {
      user.totpRecoveryCode = createRecoveryCode();
    }
    user.updatedAt = new Date().toISOString();
    await storage.saveUser(user);
    await storage.deleteRefreshTokensByUserId(user.id);
    return jsonResponse({ enabled: true, recoveryCode: user.totpRecoveryCode, object: 'twoFactor' });
  }

  if (body.enabled === false) {
    if (!body.masterPasswordHash) {
      return errorResponse('masterPasswordHash is required to disable TOTP', 400);
    }
    const valid = await auth.verifyPassword(body.masterPasswordHash, user.masterPasswordHash, user.email);
    if (!valid) return errorResponse('Invalid password', 400);

    user.totpSecret = null;
    user.updatedAt = new Date().toISOString();
    await storage.saveUser(user);
    await storage.deleteRefreshTokensByUserId(user.id);
    return jsonResponse({ enabled: false, object: 'twoFactor' });
  }

  return errorResponse('enabled must be true or false', 400);
}

// POST /api/accounts/totp/recovery-code
export async function handleGetTotpRecoveryCode(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: Record<string, string | undefined>;
  try {
    const contentType = request.headers.get('content-type') || '';
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const currentHash = String(body.masterPasswordHash || body.master_password_hash || body.password || '').trim();
  if (!currentHash) return errorResponse('masterPasswordHash is required', 400);
  const valid = await auth.verifyPassword(currentHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  if (!user.totpRecoveryCode) {
    user.totpRecoveryCode = createRecoveryCode();
    user.updatedAt = new Date().toISOString();
    await storage.saveUser(user);
  }

  return jsonResponse({
    code: user.totpRecoveryCode,
    object: 'twoFactorRecover',
  });
}

// POST /identity/accounts/recover-2fa
// Disable TOTP by recovery code + password, then rotate recovery code.
export async function handleRecoverTwoFactor(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const rateLimit = new RateLimitService(env.DB);

  let body: Record<string, string | undefined>;
  try {
    const contentType = request.headers.get('content-type') || '';
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = String(body.email || body.username || '').trim().toLowerCase();
  const masterPasswordHash = String(body.masterPasswordHash || body.password || '').trim();
  const recoveryCode = normalizeRecoveryCodeInput(String(body.recoveryCode || body.twoFactorToken || body.recovery_code || ''));
  const clientIdentifier = getClientIdentifier(request);
  if (!clientIdentifier) {
    return errorResponse('Client IP is required', 403);
  }
  const recoverLimitKey = `${clientIdentifier}:recover-2fa:${email || 'unknown'}`;

  const recoverAttemptCheck = await rateLimit.checkLoginAttempt(recoverLimitKey);
  if (!recoverAttemptCheck.allowed) {
    return errorResponse(
      `Too many failed recovery attempts. Try again in ${Math.ceil((recoverAttemptCheck.retryAfterSeconds || 60) / 60)} minutes.`,
      429
    );
  }

  if (!email || !masterPasswordHash || !recoveryCode) {
    return errorResponse('Email, masterPasswordHash and recoveryCode are required', 400);
  }

  const user = await storage.getUser(email);
  if (!user || user.status !== 'active') {
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse('Invalid credentials or recovery code', 400);
  }

  const validPassword = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!validPassword) {
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse('Invalid credentials or recovery code', 400);
  }

  if (!recoveryCodeEquals(recoveryCode, user.totpRecoveryCode)) {
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse('Invalid credentials or recovery code', 400);
  }

  user.totpSecret = null;
  user.totpRecoveryCode = createRecoveryCode();
  user.securityStamp = generateUUID();
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);
  await storage.deleteRefreshTokensByUserId(user.id);
  await rateLimit.clearLoginAttempts(recoverLimitKey);

  return jsonResponse({
    success: true,
    twoFactorEnabled: false,
    newRecoveryCode: user.totpRecoveryCode,
    object: 'twoFactorRecovery',
  });
}

// GET /api/accounts/passkeys
export async function handleListPasskeys(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const rows = await storage.listPasskeysByUserId(userId);
  return jsonResponse({
    object: 'list',
    data: rows.map((row) => ({
      id: row.id,
      name: row.name,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      lastUsedAt: row.lastUsedAt,
      transports: row.transports ? row.transports.split(',').filter(Boolean) : [],
      object: 'passkey',
    })),
  });
}

// POST /api/accounts/passkeys/register/options
export async function handlePasskeyRegisterOptions(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);
  const { origin, rpId } = getPasskeyOriginAndRpId(request);
  const challenge = randomPasskeyChallenge();
  const challengeId = await storage.createPasskeyChallenge('register', challenge, user.id, origin, rpId, 5 * 60 * 1000);
  const existing = await storage.listPasskeysByUserId(user.id);
  return jsonResponse({
    challengeId,
    publicKey: {
      challenge,
      rp: { id: rpId, name: 'NodeWarden' },
      user: {
        id: bytesToBase64Url(new TextEncoder().encode(user.id)),
        name: user.email,
        displayName: user.name || user.email,
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      timeout: 60000,
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      attestation: 'none',
      excludeCredentials: existing.map((item) => ({ id: item.credentialId, type: 'public-key' })),
    },
  });
}

// POST /api/accounts/passkeys/register/verify
export async function handlePasskeyRegisterVerify(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  let body: { challengeId?: string; name?: string; credential?: any; vaultEncKey?: string; vaultMacKey?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const challengeData = await storage.consumePasskeyChallenge(String(body.challengeId || ''), 'register');
  if (!challengeData || challengeData.userId !== userId) return errorResponse('Challenge expired', 400);

  const credential = body.credential || {};
  const response = credential.response || {};
  const clientData = parseClientData(String(response.clientDataJSON || ''));
  if (!clientData || clientData.challenge !== challengeData.challenge || clientData.origin !== challengeData.origin || clientData.type !== 'webauthn.create') {
    return errorResponse('Invalid passkey registration response', 400);
  }

  const credentialId = String(credential.id || credential.rawId || '').trim();
  const publicKeySpki = String(response.publicKey || '').trim();
  const algorithm = Number(response.publicKeyAlgorithm || -7);
  const name = String(body.name || '').trim().slice(0, 64) || 'Passkey';
  if (!credentialId || !publicKeySpki || !body.vaultEncKey || !body.vaultMacKey) {
    return errorResponse('Missing passkey fields', 400);
  }
  const current = await storage.listPasskeysByUserId(userId);
  if (current.length >= 5) return errorResponse('At most 5 passkeys are allowed', 400);

  try {
    await storage.createPasskey({
      userId,
      credentialId,
      publicKeySpki,
      algorithm,
      counter: readAuthenticatorCounter(String(response.authenticatorData || '')),
      transports: Array.isArray(response.transports) ? response.transports.join(',') : null,
      name,
      rpId: challengeData.rpId,
      vaultEncKey: String(body.vaultEncKey),
      vaultMacKey: String(body.vaultMacKey),
    });
  } catch (error) {
    const msg = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
    if (msg.includes('unique')) return errorResponse('This passkey is already registered', 409);
    throw error;
  }

  return jsonResponse({ success: true, object: 'passkey' });
}

// PUT /api/accounts/passkeys/:id
export async function handlePasskeyRename(request: Request, env: Env, userId: string, passkeyId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  let body: { name?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  const name = String(body.name || '').trim().slice(0, 64);
  if (!name) return errorResponse('Name is required', 400);
  const updated = await storage.updatePasskeyName(userId, passkeyId, name);
  if (!updated) return errorResponse('Passkey not found', 404);
  return jsonResponse({ success: true });
}

// DELETE /api/accounts/passkeys/:id
export async function handlePasskeyDelete(request: Request, env: Env, userId: string, passkeyId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const deleted = await storage.deletePasskey(userId, passkeyId);
  if (!deleted) return errorResponse('Passkey not found', 404);
  return new Response(null, { status: 204 });
}

// POST /api/accounts/passkeys/unlock/options
export async function handlePasskeyUnlockOptions(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const { origin, rpId } = getPasskeyOriginAndRpId(request);
  const challenge = randomPasskeyChallenge();
  const challengeId = await storage.createPasskeyChallenge('unlock', challenge, userId, origin, rpId, 5 * 60 * 1000);
  return jsonResponse({ challengeId, challenge, rpId, timeout: 60000, userVerification: 'preferred' });
}

// POST /api/accounts/passkeys/unlock/verify
export async function handlePasskeyUnlockVerify(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  let body: { challengeId?: string; credential?: PasskeyAssertionRequest };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  const challengeData = await storage.consumePasskeyChallenge(String(body.challengeId || ''), 'unlock');
  if (!challengeData || challengeData.userId !== userId) return errorResponse('Challenge expired', 400);

  const credential = body.credential || {};
  const response = credential.response || {};
  const clientData = parseClientData(String(response.clientDataJSON || ''));
  if (!clientData || clientData.challenge !== challengeData.challenge || clientData.origin !== challengeData.origin || clientData.type !== 'webauthn.get') {
    return errorResponse('Invalid passkey assertion', 400);
  }

  const passkey = await storage.getPasskeyByCredentialId(String(credential.id || credential.rawId || ''));
  if (!passkey || passkey.userId !== userId) return errorResponse('Passkey not found', 404);
  const verified = await verifyAssertionSignature({
    algorithm: passkey.algorithm,
    publicKeySpkiB64: passkey.publicKeySpki,
    authenticatorDataB64u: String(response.authenticatorData || ''),
    clientDataJSONB64u: String(response.clientDataJSON || ''),
    signatureB64u: String(response.signature || ''),
  });
  if (!verified) return errorResponse('Invalid passkey signature', 400);
  const nextCounter = readAuthenticatorCounter(String(response.authenticatorData || ''));
  if (passkey.counter > 0 && nextCounter > 0 && nextCounter <= passkey.counter) {
    return errorResponse('Passkey counter check failed', 400);
  }
  await storage.touchPasskeyUsage(passkey.id, nextCounter || passkey.counter);
  return jsonResponse({ symEncKey: passkey.vaultEncKey, symMacKey: passkey.vaultMacKey });
}

// GET /api/accounts/revision-date
export async function handleGetRevisionDate(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const revisionDate = await storage.getRevisionDate(userId);

  // Return as milliseconds timestamp (Bitwarden format)
  const timestamp = new Date(revisionDate).getTime();
  return jsonResponse(timestamp);
}

// POST /api/accounts/verify-password
export async function handleVerifyPassword(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);

  if (!user) {
    return errorResponse('User not found', 404);
  }

  let body: { masterPasswordHash?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.masterPasswordHash) {
    return errorResponse('masterPasswordHash is required', 400);
  }

  const valid = await auth.verifyPassword(body.masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) {
    return errorResponse('Invalid password', 400);
  }

  return new Response(null, { status: 200 });
}
