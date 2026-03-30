export function base64UrlToBytes(value: string): Uint8Array {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function bytesToBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function normalizeTransport(transports?: readonly AuthenticatorTransport[] | null): string[] {
  if (!Array.isArray(transports)) return [];
  return transports.map((item) => String(item));
}

export async function createPasskeyCredential(options: any): Promise<any> {
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...options.publicKey,
    challenge: base64UrlToBytes(options.publicKey.challenge),
    user: {
      ...options.publicKey.user,
      id: base64UrlToBytes(options.publicKey.user.id),
    },
    excludeCredentials: Array.isArray(options.publicKey.excludeCredentials)
      ? options.publicKey.excludeCredentials.map((item: any) => ({ ...item, id: base64UrlToBytes(item.id) }))
      : [],
  };

  const created = await navigator.credentials.create({ publicKey });
  const credential = created as PublicKeyCredential;
  const response = credential.response as AuthenticatorAttestationResponse;
  const publicKeyBytes = response.getPublicKey();
  const publicKeyAlgorithm = response.getPublicKeyAlgorithm();

  return {
    id: credential.id,
    type: credential.type,
    rawId: bytesToBase64Url(credential.rawId),
    response: {
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      attestationObject: bytesToBase64Url(response.attestationObject),
      publicKey: publicKeyBytes ? btoa(String.fromCharCode(...new Uint8Array(publicKeyBytes))) : '',
      publicKeyAlgorithm,
      authenticatorData: response.getAuthenticatorData ? bytesToBase64Url(response.getAuthenticatorData()) : '',
      transports: normalizeTransport(response.getTransports?.()),
    },
  };
}

export async function getPasskeyAssertion(options: {
  challenge: string;
  rpId: string;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
  allowCredentials?: Array<{ id: string; type?: string }>;
}): Promise<any> {
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: base64UrlToBytes(options.challenge),
    rpId: options.rpId,
    timeout: options.timeout,
    userVerification: options.userVerification,
    allowCredentials: Array.isArray(options.allowCredentials)
      ? options.allowCredentials.map((item) => ({ id: base64UrlToBytes(item.id), type: 'public-key' as PublicKeyCredentialType }))
      : undefined,
  };
  const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential;
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    type: credential.type,
    rawId: bytesToBase64Url(credential.rawId),
    response: {
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      authenticatorData: bytesToBase64Url(response.authenticatorData),
      signature: bytesToBase64Url(response.signature),
      userHandle: response.userHandle ? bytesToBase64Url(response.userHandle) : null,
    },
  };
}
