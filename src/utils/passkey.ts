export function bytesToBase64Url(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(value: string): Uint8Array {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function parseClientData(clientDataJsonB64u: string): { challenge: string; origin: string; type: string } | null {
  try {
    const decoded = new TextDecoder().decode(base64UrlToBytes(clientDataJsonB64u));
    const parsed = JSON.parse(decoded) as { challenge?: string; origin?: string; type?: string };
    if (!parsed?.challenge || !parsed?.origin || !parsed?.type) return null;
    return { challenge: parsed.challenge, origin: parsed.origin, type: parsed.type };
  } catch {
    return null;
  }
}

export function readAuthenticatorCounter(authenticatorDataB64u: string): number {
  const data = base64UrlToBytes(authenticatorDataB64u);
  if (data.length < 37) return 0;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return view.getUint32(33, false);
}

export async function verifyAssertionSignature(args: {
  algorithm: number;
  publicKeySpkiB64: string;
  authenticatorDataB64u: string;
  clientDataJSONB64u: string;
  signatureB64u: string;
}): Promise<boolean> {
  const algo = Number(args.algorithm);
  if (algo !== -7) return false;

  const publicKey = await crypto.subtle.importKey(
    'spki',
    Uint8Array.from(atob(args.publicKeySpkiB64), (c) => c.charCodeAt(0)),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );

  const authData = base64UrlToBytes(args.authenticatorDataB64u);
  const clientData = base64UrlToBytes(args.clientDataJSONB64u);
  const clientHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientData));
  const signed = new Uint8Array(authData.length + clientHash.length);
  signed.set(authData, 0);
  signed.set(clientHash, authData.length);

  const signature = base64UrlToBytes(args.signatureB64u);
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, signed);
}
