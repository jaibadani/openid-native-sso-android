/**
 * Pure TypeScript implementation of OpenID Connect Native SSO 1.0,
 * FAPI 2.0 PAR (RFC 9126) + DPoP (RFC 9449), and OAuth 2.0 Token Exchange (RFC 8693)
 * for MOSIP eSignet Go & Thunder ID Engine.
 */

export interface JWKPublic {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
  kid: string;
}

export interface CitizenProfile {
  uin: string;
  sub: string;
  name: string;
  email: string;
  phone_number: string;
  birthdate: string;
  gender: string;
  address: {
    street_address: string;
    locality: string;
    region: string;
    postal_code: string;
    country: string;
  };
  verified_claims: {
    verification: {
      trust_framework: string;
      assurance_level: string;
    };
  };
}

export interface RegisteredOidcClient {
  client_id: string;
  client_name: string;
  app_type: 'super_app' | 'child_app';
  package_name: string;
  vendor_cert_sha256: string;
  redirect_uris: string[];
  allowed_authorization_scopes: string[];
  allowed_grant_types: string[];
  allowed_sso_clients: string[]; // Child client_ids allowed to redeem device_secret issued to this Super App
}

export interface PushedAuthRequest {
  request_uri: string;
  client_id: string;
  scope: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: 'S256';
  dpop_jkt: string;
  nonce: string;
  state: string;
  created_at: number;
  expires_at: number;
}

export interface AuthorizationSession {
  auth_id: string; // Also used as sid in id_token
  request_uri: string;
  client_id: string;
  uin?: string;
  sub?: string;
  otp_sent: boolean;
  otp_verified: boolean;
  acr?: string;
  consented_scopes: string[];
  consented_claims: string[];
  authorization_code?: string;
  dpop_jkt: string;
  code_challenge: string;
  redirect_uri: string;
  nonce: string;
  state?: string;
  created_at: number;
  active: boolean;
}

export interface DeviceSecretPayload {
  iss: string;
  sub: string;
  auth_id: string;
  client_id: string; // Original Super App client_id (org_client_id)
  scope: string;
  acr: string;
  claims: string[];
  cnf: {
    jkt: string;
  };
  iat: number;
  exp: number;
  jti: string;
}

export interface IdTokenPayload {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  sid: string;
  nonce?: string;
  acr: string;
  ds_hash?: string;
  azp: string;
}

export interface AccessTokenPayload {
  iss: string;
  sub: string;
  aud: string;
  client_id: string;
  scope: string;
  cnf: {
    jkt: string;
  };
  iat: number;
  exp: number;
  jti: string;
  consented_claims: string[];
}

export interface DpopProofPayload {
  htm: 'POST' | 'GET';
  htu: string;
  iat: number;
  jti: string;
  ath?: string;
}

export interface ConsentAuditRecord {
  id: string;
  sub: string;
  client_id: string;
  derived_from_client_id?: string;
  granted_scopes: string[];
  accepted_claims: string[];
  mode: 'INTERACTIVE_CONSENT' | 'SILENT_SSO_NOCAPTURE' | 'STEP_UP_RECONSENT';
  timestamp: string;
}

export interface ProtocolSequenceStep {
  id: string;
  timestamp: string;
  flow:
    | 'SUPER_APP_PAR_LOGIN'
    | 'CHILD_APP_TOKEN_EXCHANGE'
    | 'IPC_BIND_SERVICE'
    | 'USERINFO'
    | 'REVOKE_LOGOUT';
  actorFrom: string;
  actorTo: string;
  title: string;
  endpoint?: string;
  method?: string;
  status: 'success' | 'error' | 'warning';
  statusCode: number;
  requestPayload: Record<string, unknown>;
  responsePayload: Record<string, unknown>;
  rfcTaskRef?: string;
}

// Pure deterministic SHA-256 implementation (FIPS 180-4) for synchronous isomorphic execution
const K_SHA256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(n: number, x: number): number {
  return (x >>> n) | (x << (32 - n));
}

export function sha256Bytes(asciiOrUtf8: string): Uint8Array {
  const encoder = new TextEncoder();
  const msg = encoder.encode(asciiOrUtf8);
  const bitLen = msg.length * 8;

  const totalLen = (((msg.length + 8) >> 6) + 1) << 6;
  const padded = new Uint8Array(totalLen);
  padded.set(msg);
  padded[msg.length] = 0x80;

  const view = new DataView(padded.buffer);
  view.setUint32(totalLen - 4, bitLen >>> 0, false);
  view.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const w = new Uint32Array(64);

  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(7, w[i - 15]) ^ rotr(18, w[i - 15]) ^ (w[i - 15] >>> 3);
      const s1 = rotr(17, w[i - 2]) ^ rotr(19, w[i - 2]) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K_SHA256[i] + w[i]) >>> 0;
      const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, h0, false);
  outView.setUint32(4, h1, false);
  outView.setUint32(8, h2, false);
  outView.setUint32(12, h3, false);
  outView.setUint32(16, h4, false);
  outView.setUint32(20, h5, false);
  outView.setUint32(24, h6, false);
  outView.setUint32(28, h7, false);
  return out;
}

const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let result = '';
  const len = bytes.length;
  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < len ? bytes[i + 1] : 0;
    const b2 = i + 2 < len ? bytes[i + 2] : 0;

    result += BASE64_CHARS[b0 >> 2];
    result += BASE64_CHARS[((b0 & 3) << 4) | (b1 >> 4)];
    if (i + 1 < len) {
      result += BASE64_CHARS[((b1 & 15) << 2) | (b2 >> 6)];
    }
    if (i + 2 < len) {
      result += BASE64_CHARS[b2 & 63];
    }
  }
  return result.replace(/\+/g, '-').replace(/\//g, '_');
}

export function base64UrlEncodeJson(obj: unknown): string {
  const json = JSON.stringify(obj);
  const bytes = new TextEncoder().encode(json);
  return base64UrlEncodeBytes(bytes);
}

export function base64UrlDecodeToString(b64url: string): string {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (b64.length % 4)) % 4;
  const padded = b64 + '='.repeat(padLen);

  const bytes: number[] = [];
  for (let i = 0; i < padded.length; i += 4) {
    const c0 = BASE64_CHARS.indexOf(padded[i]);
    const c1 = BASE64_CHARS.indexOf(padded[i + 1]);
    const c2 = padded[i + 2] === '=' ? -1 : BASE64_CHARS.indexOf(padded[i + 2]);
    const c3 = padded[i + 3] === '=' ? -1 : BASE64_CHARS.indexOf(padded[i + 3]);

    bytes.push((c0 << 2) | (c1 >> 4));
    if (c2 !== -1) {
      bytes.push(((c1 & 15) << 4) | (c2 >> 2));
    }
    if (c3 !== -1) {
      bytes.push(((c2 & 3) << 6) | c3);
    }
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

/**
 * Computes RFC 7638 JWK SHA-256 Thumbprint (`jkt`)
 * Canonical lexicographical JSON for EC P-256 key: {"crv","kty","x","y"}
 */
export function computeJwkThumbprint(jwk: Pick<JWKPublic, 'crv' | 'kty' | 'x' | 'y'>): string {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
  return base64UrlEncodeBytes(sha256Bytes(canonical));
}

/**
 * Computes OpenID Connect Native SSO 1.0 Section 3.2 `ds_hash`:
 * BASE64URL(LEFT_128_BITS(SHA-256(ASCII(device_secret))))
 */
export function computeDsHash(deviceSecret: string): string {
  const fullHash = sha256Bytes(deviceSecret);
  const left128Bits = fullHash.slice(0, 16); // 16 bytes = 128 bits
  return base64UrlEncodeBytes(left128Bits);
}

/**
 * Computes RFC 9449 `ath` (Access Token Hash):
 * BASE64URL(SHA-256(ASCII(access_token)))
 */
export function computeAccessTokenHash(accessToken: string): string {
  return base64UrlEncodeBytes(sha256Bytes(accessToken));
}

/**
 * Computes RFC 7636 PKCE S256 code_challenge from code_verifier
 */
export function computePkceChallenge(codeVerifier: string): string {
  return base64UrlEncodeBytes(sha256Bytes(codeVerifier));
}

/**
 * Signs a JWT (JWS Compact Serialization) with deterministic ES256 signature simulation
 */
export function signJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signingSecretOrKeyId: string
): string {
  const encodedHeader = base64UrlEncodeJson(header);
  const encodedPayload = base64UrlEncodeJson(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const sigBytes = sha256Bytes(`${signingInput}.${signingSecretOrKeyId}.ES256_SIG`);
  const encodedSig = base64UrlEncodeBytes(sigBytes);
  return `${signingInput}.${encodedSig}`;
}

/**
 * Decodes and verifies a signed JWT
 */
export function verifyAndDecodeJwt<T = Record<string, unknown>>(
  jwt: string,
  expectedSigningSecretOrKeyId?: string
): { valid: boolean; header: Record<string, unknown>; payload: T; error?: string } {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    return {
      valid: false,
      header: {},
      payload: {} as T,
      error: 'Invalid JWT format (expected 3 dot-separated parts)',
    };
  }
  try {
    const header = JSON.parse(base64UrlDecodeToString(parts[0])) as Record<string, unknown>;
    const payload = JSON.parse(base64UrlDecodeToString(parts[1])) as T;
    if (expectedSigningSecretOrKeyId) {
      const signingInput = `${parts[0]}.${parts[1]}`;
      const expectedSig = base64UrlEncodeBytes(
        sha256Bytes(`${signingInput}.${expectedSigningSecretOrKeyId}.ES256_SIG`)
      );
      if (parts[2] !== expectedSig) {
        return {
          valid: false,
          header,
          payload,
          error: 'Cryptographic signature verification failed',
        };
      }
    }
    return { valid: true, header, payload };
  } catch (err) {
    return {
      valid: false,
      header: {},
      payload: {} as T,
      error: err instanceof Error ? err.message : 'Failed to parse JWT JSON',
    };
  }
}

/**
 * Wraps a signed JWS into a 5-part JWE Compact Serialization (Signed-then-Encrypted device_secret)
 * so the device_secret remains opaque to the mobile client while decryptable by eSignet Key Manager.
 */
export function encryptJwsAsJwe(innerJws: string, keyManagerSecret = 'ESIGNET_KMS_A256GCM'): string {
  const jweHeader = base64UrlEncodeJson({
    alg: 'dir',
    enc: 'A256GCM',
    cty: 'JWT',
    kid: 'esignet-kms-ds-enc-v1',
  });
  const encryptedKey = ''; // dir algorithm uses empty JWE Encrypted Key
  const iv = base64UrlEncodeBytes(sha256Bytes(`IV.${innerJws}`).slice(0, 12));
  const ciphertext = base64UrlEncodeJson({ jws: innerJws });
  const authTag = base64UrlEncodeBytes(
    sha256Bytes(`${jweHeader}.${iv}.${ciphertext}.${keyManagerSecret}`).slice(0, 16)
  );
  return `${jweHeader}.${encryptedKey}.${iv}.${ciphertext}.${authTag}`;
}

/**
 * Decrypts a 5-part JWE device_secret and extracts the inner signed JWS
 */
export function decryptJweDeviceSecret(
  jwe: string,
  keyManagerSecret = 'ESIGNET_KMS_A256GCM'
): { valid: boolean; jweHeader?: Record<string, unknown>; innerJws?: string; error?: string } {
  const parts = jwe.split('.');
  if (parts.length !== 5) {
    return { valid: false, error: 'Malformed JWE device_secret (expected 5 compact parts)' };
  }
  const [jweHeaderB64, , iv, ciphertext, authTag] = parts;
  const expectedTag = base64UrlEncodeBytes(
    sha256Bytes(`${jweHeaderB64}.${iv}.${ciphertext}.${keyManagerSecret}`).slice(0, 16)
  );
  if (authTag !== expectedTag) {
    return { valid: false, error: 'JWE A256GCM authentication tag verification failed (tampered device_secret)' };
  }
  try {
    const jweHeader = JSON.parse(base64UrlDecodeToString(jweHeaderB64)) as Record<string, unknown>;
    const decodedCipher = JSON.parse(base64UrlDecodeToString(ciphertext)) as { jws: string };
    return { valid: true, jweHeader, innerJws: decodedCipher.jws };
  } catch {
    return { valid: false, error: 'Failed to decode JWE ciphertext payload' };
  }
}

/**
 * Creates a signed DPoP Proof JWT (RFC 9449) bound to a hardware key pair
 */
export function createDpopProof(params: {
  jwk: JWKPublic;
  htm: 'POST' | 'GET';
  htu: string;
  accessToken?: string;
  iat?: number;
  jti?: string;
}): string {
  const iat = params.iat ?? Math.floor(Date.now() / 1000);
  const jti = params.jti ?? `dpop-jti-${iat}-${Math.random().toString(36).slice(2, 8)}`;
  const header = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: {
      kty: params.jwk.kty,
      crv: params.jwk.crv,
      x: params.jwk.x,
      y: params.jwk.y,
    },
  };
  const payload: DpopProofPayload = {
    htm: params.htm,
    htu: params.htu,
    iat,
    jti,
    ...(params.accessToken ? { ath: computeAccessTokenHash(params.accessToken) } : {}),
  };
  return signJwt(header, payload as unknown as Record<string, unknown>, params.jwk.kid);
}

/**
 * RFC 9449 DPoP htu validation:
 * Validates that the DPoP proof htu matches the expected endpoint path suffix,
 * accepting the live server host (Cloud Run, local adb, emulator) or standard MOSIP issuer.
 */
export function validateDpopHtu(
  actualHtu?: string,
  expectedPathSuffix = '/oauth2/token',
  allowedBaseUrls: string[] = []
): boolean {
  if (!actualHtu) return true;
  for (const base of allowedBaseUrls) {
    if (!base) continue;
    const cleanBase = base.replace(/\/+$/, '');
    if (actualHtu === `${cleanBase}${expectedPathSuffix}`) return true;
    if (actualHtu.startsWith(cleanBase) && actualHtu.endsWith(expectedPathSuffix)) return true;
  }
  try {
    const parsed = new URL(actualHtu);
    const pathname = parsed.pathname.replace(/\/+$/, '');
    if (
      pathname.endsWith(expectedPathSuffix) ||
      pathname === expectedPathSuffix ||
      pathname === `/api${expectedPathSuffix}`
    ) {
      return true;
    }
  } catch {
    if (actualHtu.endsWith(expectedPathSuffix) || actualHtu.includes(expectedPathSuffix)) {
      return true;
    }
  }
  return false;
}

// Default Hardware Keys on the Mobile Device
export const SUPER_APP_KEY_A: JWKPublic = {
  kty: 'EC',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  kid: 'android-keystore-strongbox-key-A',
};

export const ROGUE_DEVICE_KEY_X: JWKPublic = {
  kty: 'EC',
  crv: 'P-256',
  x: '11223344556677889900aabbccddeeff11223344556',
  y: '99887766554433221100ffeeddccbbaa99887766554',
  kid: 'rogue-untrusted-key-X',
};

export const DEFAULT_VENDOR_CERT_SHA256 =
  'DA:39:A3:EE:5E:6B:4B:0D:32:55:BF:EF:95:60:18:90:AF:D8:07:09:99:21:CC:74:E2:4A:08:11:5B:82:3F:01';

export const UNTRUSTED_VENDOR_CERT_SHA256 =
  'FF:00:99:11:88:22:77:33:66:44:55:AA:BB:CC:DD:EE:01:23:45:67:89:AB:CD:EF:FE:DC:BA:98:76:54:32:10';

export const CITIZEN_DIRECTORY: Record<string, CitizenProfile> = {
  '8294017365': {
    uin: '8294017365',
    sub: 'mosip-psut-9f8a7d6c5b4e3f2a1d0c',
    name: 'Ananya Deshmukh',
    email: 'ananya.deshmukh@citizen.mosip.net',
    phone_number: '+91-98204-71932',
    birthdate: '1994-08-15',
    gender: 'Female',
    address: {
      street_address: '42 Residency Road, Ashok Nagar',
      locality: 'Bengaluru',
      region: 'Karnataka',
      postal_code: '560025',
      country: 'IN',
    },
    verified_claims: {
      verification: {
        trust_framework: 'MOSIP_NATIONAL_ID_FAPI2',
        assurance_level: 'IAL3_AAL2_BIOMETRIC_OTP',
      },
    },
  },
  '4510928374': {
    uin: '4510928374',
    sub: 'mosip-psut-3c2d1e0f9a8b7c6d5e4f',
    name: 'Rohan Vikramaditya',
    email: 'rohan.vikram@citizen.mosip.net',
    phone_number: '+91-98450-11298',
    birthdate: '1989-11-03',
    gender: 'Male',
    address: {
      street_address: '18 Jubilee Hills Road No 36',
      locality: 'Hyderabad',
      region: 'Telangana',
      postal_code: '500033',
      country: 'IN',
    },
    verified_claims: {
      verification: {
        trust_framework: 'MOSIP_NATIONAL_ID_FAPI2',
        assurance_level: 'IAL3_AAL2_BIOMETRIC_OTP',
      },
    },
  },
};

export const INITIAL_REGISTERED_CLIENTS: Record<string, RegisteredOidcClient> = {
  'mosip-super-wallet-android': {
    client_id: 'mosip-super-wallet-android',
    client_name: 'Inji Citizen Super App',
    app_type: 'super_app',
    package_name: 'io.mosip.inji.superwallet',
    vendor_cert_sha256: DEFAULT_VENDOR_CERT_SHA256,
    redirect_uris: ['io.mosip.inji.superwallet://oauth2redirect'],
    allowed_authorization_scopes: ['openid', 'profile', 'email', 'phone', 'verified_claims', 'device_sso'],
    allowed_grant_types: ['authorization_code'],
    allowed_sso_clients: ['mosip-mparivahan-transit', 'mosip-ayushman-health'],
  },
  'mosip-mparivahan-transit': {
    client_id: 'mosip-mparivahan-transit',
    client_name: 'mParivahan Citizen Transit',
    app_type: 'child_app',
    package_name: 'io.mosip.gov.mparivahan',
    vendor_cert_sha256: DEFAULT_VENDOR_CERT_SHA256,
    redirect_uris: ['io.mosip.gov.mparivahan://sso-callback'],
    allowed_authorization_scopes: ['openid', 'profile', 'email', 'phone', 'device_sso'],
    allowed_grant_types: [
      'authorization_code',
      'urn:ietf:params:oauth:grant-type:token-exchange',
      'token_exchange',
    ],
    allowed_sso_clients: [],
  },
  'mosip-unprivileged-client': {
    client_id: 'mosip-unprivileged-client',
    client_name: 'Legacy RP (No device_sso)',
    app_type: 'super_app',
    package_name: 'io.mosip.legacy.rp',
    vendor_cert_sha256: DEFAULT_VENDOR_CERT_SHA256,
    redirect_uris: ['io.mosip.legacy.rp://callback'],
    allowed_authorization_scopes: ['openid', 'profile', 'email'], // Missing device_sso!
    allowed_grant_types: ['authorization_code'],
    allowed_sso_clients: [],
  },
};

/**
 * DeviceSecretProvider Interface & Implementation (Thunder ID + eSignet Go Mandatory Tasks 3 & 4)
 */
export class EsignetDeviceSecretProvider {
  public issuer = 'https://esignet.mosip.net';
  private readonly signingKeyId = 'esignet-ds-jws-key-rs256';
  private readonly encryptionKeyId = 'ESIGNET_KMS_A256GCM';
  private usedOrRevokedJtis = new Set<string>();

  public setIssuer(newIssuer: string) {
    this.issuer = newIssuer.replace(/\/+$/, '');
  }

  /**
   * Mandatory Task 4a: Generate Device Secret
   * Generates a signed JWT (then JWE-encrypted) including:
   * cnf.jkt, auth_id, exp, client_id, scope, acr, claims, iss
   */
  public generateDeviceSecret(params: {
    sub: string;
    auth_id: string;
    client_id: string;
    scope: string;
    acr: string;
    claims: string[];
    dpop_jkt: string;
    nowSec?: number;
  }): { device_secret: string; ds_hash: string; payload: DeviceSecretPayload; inner_jws: string } {
    const iat = params.nowSec ?? Math.floor(Date.now() / 1000);
    const exp = iat + 3600 * 8; // 8 hours SSO session lifetime
    const jti = `ds-${params.auth_id}-${iat}`;

    const payload: DeviceSecretPayload = {
      iss: this.issuer,
      sub: params.sub,
      auth_id: params.auth_id,
      client_id: params.client_id,
      scope: params.scope,
      acr: params.acr,
      claims: params.claims,
      cnf: {
        jkt: params.dpop_jkt,
      },
      iat,
      exp,
      jti,
    };

    const innerJws = signJwt(
      { alg: 'ES256', typ: 'device-secret+jwt', kid: this.signingKeyId },
      payload as unknown as Record<string, unknown>,
      this.signingKeyId
    );
    const deviceSecretJwe = encryptJwsAsJwe(innerJws, this.encryptionKeyId);
    const dsHash = computeDsHash(deviceSecretJwe);

    return {
      device_secret: deviceSecretJwe,
      ds_hash: dsHash,
      payload,
      inner_jws: innerJws,
    };
  }

  /**
   * Mandatory Task 4b: Validate Device Secret
   * Decrypts JWE, verifies JWS signature, checks expiry, checks revocation,
   * and verifies requesting Child App is in Super App's allowlist.
   */
  public validateDeviceSecret(params: {
    requesting_client_id: string;
    device_secret: string;
    registeredClients: Record<string, RegisteredOidcClient>;
    nowSec?: number;
  }): {
    valid: boolean;
    payload?: DeviceSecretPayload;
    inner_jws?: string;
    error?: string;
    error_description?: string;
  } {
    const now = params.nowSec ?? Math.floor(Date.now() / 1000);

    // 1. Decrypt outer JWE envelope
    const decrypted = decryptJweDeviceSecret(params.device_secret, this.encryptionKeyId);
    if (!decrypted.valid || !decrypted.innerJws) {
      return {
        valid: false,
        error: 'invalid_grant',
        error_description: decrypted.error || 'Failed to decrypt device_secret JWE',
      };
    }

    // 2. Verify inner JWS signature
    const verified = verifyAndDecodeJwt<DeviceSecretPayload>(decrypted.innerJws, this.signingKeyId);
    if (!verified.valid) {
      return {
        valid: false,
        error: 'invalid_grant',
        error_description: verified.error || 'Invalid device_secret JWS signature',
      };
    }

    const payload = verified.payload;

    // 3. Check expiry
    if (payload.exp <= now) {
      return {
        valid: false,
        error: 'invalid_grant',
        error_description: 'device_secret has expired',
      };
    }

    // 4. Check revocation
    if (this.usedOrRevokedJtis.has(payload.jti)) {
      return {
        valid: false,
        error: 'invalid_grant',
        error_description: 'device_secret jti has been revoked',
      };
    }

    // 5. Look up org_client_id allowlist to confirm Child App is permitted to redeem
    const orgClient = params.registeredClients[payload.client_id];
    if (!orgClient) {
      return {
        valid: false,
        error: 'invalid_client',
        error_description: `Originating Super App client '${payload.client_id}' is not registered`,
      };
    }

    if (
      params.requesting_client_id !== payload.client_id &&
      !orgClient.allowed_sso_clients.includes(params.requesting_client_id)
    ) {
      return {
        valid: false,
        error: 'unauthorized_client',
        error_description: `Child App '${params.requesting_client_id}' is not in the SSO vendor allowlist for '${payload.client_id}'`,
      };
    }

    return {
      valid: true,
      payload,
      inner_jws: decrypted.innerJws,
    };
  }

  public revokeDeviceSecret(jti: string): void {
    this.usedOrRevokedJtis.add(jti);
  }
}

/**
 * Thunder ID + eSignet Go Native SSO Core Engine
 */
export class NativeSsoServerEngine {
  public issuer = 'https://esignet.mosip.net';
  private readonly idTokenSigningKey = 'esignet-oidc-idtoken-key-rs256';
  private readonly accessTokenSigningKey = 'esignet-oidc-at-key-es256';
  public readonly deviceSecretProvider = new EsignetDeviceSecretProvider();

  public setIssuer(newIssuer: string) {
    this.issuer = newIssuer.replace(/\/+$/, '');
    this.deviceSecretProvider.setIssuer(this.issuer);
  }

  public registeredClients: Record<string, RegisteredOidcClient> = structuredClone(
    INITIAL_REGISTERED_CLIENTS
  );
  public parRequests = new Map<string, PushedAuthRequest>();
  public authSessions = new Map<string, AuthorizationSession>();
  public codeToSessionId = new Map<string, string>();
  public consentStore = new Map<string, { scopes: string[]; claims: string[] }>(); // key: `${client_id}:${sub}`
  public consentAuditLog: ConsentAuditRecord[] = [];
  public sequenceLogs: ProtocolSequenceStep[] = [];

  private appendLog(step: Omit<ProtocolSequenceStep, 'id' | 'timestamp'>): ProtocolSequenceStep {
    const entry: ProtocolSequenceStep = {
      ...step,
      id: `step-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: new Date().toISOString(),
    };
    this.sequenceLogs.push(entry);
    return entry;
  }

  /**
   * Step 1: POST /oauth2/par (Pushed Authorization Request - RFC 9126)
   * Binds the request_uri to the Super App's hardware DPoP key thumbprint (`dpop_jkt`).
   */
  public handleParRequest(req: {
    client_id: string;
    scope: string;
    redirect_uri: string;
    code_challenge: string;
    code_challenge_method: 'S256';
    dpop_jkt: string;
    nonce?: string;
    state?: string;
  }): {
    status: number;
    body: { request_uri?: string; expires_in?: number; error?: string; error_description?: string };
  } {
    const client = this.registeredClients[req.client_id];
    if (!client) {
      const errBody = {
        error: 'invalid_client',
        error_description: `Client '${req.client_id}' is not registered in eSignet`,
      };
      this.appendLog({
        flow: 'SUPER_APP_PAR_LOGIN',
        actorFrom: 'Super App',
        actorTo: 'Thunder ID Engine',
        title: 'POST /oauth2/par (Rejected: Unknown Client)',
        endpoint: 'POST /oauth2/par',
        method: 'POST',
        status: 'error',
        statusCode: 400,
        requestPayload: req,
        responsePayload: errBody,
        rfcTaskRef: 'Task 1: Request device_sso scope',
      });
      return { status: 400, body: errBody };
    }

    if (!req.dpop_jkt) {
      const errBody = {
        error: 'invalid_request',
        error_description: 'Missing mandatory FAPI 2.0 dpop_jkt parameter in PAR request',
      };
      return { status: 400, body: errBody };
    }

    const now = Math.floor(Date.now() / 1000);
    const request_uri = `urn:ietf:params:oauth:request_uri:par-${now}-${Math.random().toString(36).slice(2, 9)}`;

    const parRecord: PushedAuthRequest = {
      request_uri,
      client_id: req.client_id,
      scope: req.scope,
      redirect_uri: req.redirect_uri,
      code_challenge: req.code_challenge,
      code_challenge_method: req.code_challenge_method,
      dpop_jkt: req.dpop_jkt,
      nonce: req.nonce || `nonce-${now}`,
      state: req.state || `state-${now}`,
      created_at: now,
      expires_at: now + 60,
    };

    this.parRequests.set(request_uri, parRecord);

    const resBody = { request_uri, expires_in: 60 };
    this.appendLog({
      flow: 'SUPER_APP_PAR_LOGIN',
      actorFrom: 'Super App',
      actorTo: 'Thunder ID Engine',
      title: 'POST /oauth2/par (Pushed Request Bound to dpop_jkt)',
      endpoint: 'POST /oauth2/par',
      method: 'POST',
      status: 'success',
      statusCode: 201,
      requestPayload: req,
      responsePayload: resBody,
      rfcTaskRef: 'Task 1: Request device_sso scope [eSignet]',
    });

    return { status: 201, body: resBody };
  }

  /**
   * Step 2: GET /oauth2/authorize
   * Resolves the pushed PAR request and starts an interactive eSignet session.
   */
  public startAuthorizeSession(params: { client_id: string; request_uri: string }): {
    status: number;
    body: {
      auth_id?: string;
      client_name?: string;
      requested_scopes?: string[];
      error?: string;
      error_description?: string;
    };
  } {
    const par = this.parRequests.get(params.request_uri);
    if (!par || par.client_id !== params.client_id) {
      return {
        status: 400,
        body: {
          error: 'invalid_request_uri',
          error_description: 'The provided request_uri is invalid or does not match client_id',
        },
      };
    }

    const now = Math.floor(Date.now() / 1000);
    const auth_id = `sid-esignet-${now}-${Math.random().toString(36).slice(2, 8)}`;
    const session: AuthorizationSession = {
      auth_id,
      request_uri: par.request_uri,
      client_id: par.client_id,
      otp_sent: false,
      otp_verified: false,
      consented_scopes: [],
      consented_claims: [],
      dpop_jkt: par.dpop_jkt,
      code_challenge: par.code_challenge,
      redirect_uri: par.redirect_uri,
      nonce: par.nonce,
      state: par.state,
      created_at: now,
      active: true,
    };

    this.authSessions.set(auth_id, session);
    const client = this.registeredClients[par.client_id];
    const requested_scopes = par.scope.split(/\s+/).filter(Boolean);

    const resBody = {
      auth_id,
      client_name: client?.client_name || par.client_id,
      requested_scopes,
    };

    this.appendLog({
      flow: 'SUPER_APP_PAR_LOGIN',
      actorFrom: 'System Browser (oidc-ui)',
      actorTo: 'Thunder ID Engine',
      title: 'GET /oauth2/authorize (Resolve PAR Request)',
      endpoint: 'GET /oauth2/authorize',
      method: 'GET',
      status: 'success',
      statusCode: 200,
      requestPayload: params,
      responsePayload: resBody,
      rfcTaskRef: 'Task 1: Request device_sso scope [eSignet]',
    });

    return { status: 200, body: resBody };
  }

  /**
   * Step 3: Send & Verify OTP against MOSIP IDA Backend
   */
  public authenticateWithOtp(params: {
    auth_id: string;
    uin: string;
    otp: string;
  }): {
    status: number;
    body: {
      verified?: boolean;
      citizen?: Pick<CitizenProfile, 'name' | 'uin' | 'email' | 'phone_number'>;
      error?: string;
      error_description?: string;
    };
  } {
    const session = this.authSessions.get(params.auth_id);
    if (!session) {
      return {
        status: 400,
        body: { error: 'invalid_session', error_description: 'Authorization session not found' },
      };
    }

    const citizen = CITIZEN_DIRECTORY[params.uin.trim()];
    if (!citizen) {
      return {
        status: 400,
        body: {
          error: 'ida_uin_not_found',
          error_description: `UIN '${params.uin}' was not found in MOSIP Identity Repository. Try 8294017365 or 4510928374.`,
        },
      };
    }

    if (params.otp.trim() !== '111111') {
      return {
        status: 401,
        body: {
          error: 'invalid_otp',
          error_description: 'Invalid OTP code entered. Use 111111 for MOSIP Collab Sandbox.',
        },
      };
    }

    session.uin = citizen.uin;
    session.sub = citizen.sub;
    session.otp_sent = true;
    session.otp_verified = true;
    session.acr = 'mosip:idp:acr:generated-code';

    const resBody = {
      verified: true,
      citizen: {
        name: citizen.name,
        uin: citizen.uin,
        email: citizen.email,
        phone_number: citizen.phone_number,
      },
    };

    this.appendLog({
      flow: 'SUPER_APP_PAR_LOGIN',
      actorFrom: 'Thunder ID Engine',
      actorTo: 'MOSIP IDA Backend',
      title: 'Authenticate Citizen UIN via OTP',
      endpoint: 'POST /v1/esignet/authorization/authenticate',
      method: 'POST',
      status: 'success',
      statusCode: 200,
      requestPayload: { auth_id: params.auth_id, uin: params.uin, auth_factor: 'OTP' },
      responsePayload: resBody,
    });

    return { status: 200, body: resBody };
  }

  /**
   * Step 4: Record Consent & Issue Authorization Code bound to dpop_jkt
   */
  public submitConsent(params: {
    auth_id: string;
    accepted_scopes: string[];
    accepted_claims: string[];
  }): {
    status: number;
    body: {
      code?: string;
      redirect_uri?: string;
      state?: string;
      error?: string;
      error_description?: string;
    };
  } {
    const session = this.authSessions.get(params.auth_id);
    if (!session || !session.otp_verified || !session.sub) {
      return {
        status: 400,
        body: {
          error: 'unauthorized_session',
          error_description: 'Session must complete OTP authentication before submitting consent',
        },
      };
    }

    session.consented_scopes = params.accepted_scopes;
    session.consented_claims = params.accepted_claims;

    const code = `code-fapi-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    session.authorization_code = code;
    this.codeToSessionId.set(code, session.auth_id);

    // Save consent record for Super App + Citizen sub so Child Apps can evaluate subset rules
    this.consentStore.set(`${session.client_id}:${session.sub}`, {
      scopes: params.accepted_scopes,
      claims: params.accepted_claims,
    });

    this.consentAuditLog.unshift({
      id: `consent-${Date.now()}`,
      sub: session.sub,
      client_id: session.client_id,
      granted_scopes: params.accepted_scopes,
      accepted_claims: params.accepted_claims,
      mode: 'INTERACTIVE_CONSENT',
      timestamp: new Date().toISOString(),
    });

    const resBody = {
      code,
      redirect_uri: session.redirect_uri,
      state: session.state,
    };

    this.appendLog({
      flow: 'SUPER_APP_PAR_LOGIN',
      actorFrom: 'System Browser (oidc-ui)',
      actorTo: 'Thunder ID Engine',
      title: 'Consent Approved -> Issue Authorization Code (Bound to dpop_jkt)',
      endpoint: 'POST /v1/esignet/authorization/auth-code',
      method: 'POST',
      status: 'success',
      statusCode: 302,
      requestPayload: params,
      responsePayload: resBody,
    });

    return { status: 200, body: resBody };
  }

  /**
   * Step 5: POST /oauth2/token — Supports both:
   * 1. grant_type=authorization_code (Super App Login Flow + Device Secret Issuance)
   * 2. grant_type=urn:ietf:params:oauth:grant-type:token-exchange / token_exchange (Child App Silent SSO Flow)
   */
  public handleTokenEndpoint(req: {
    grant_type: string;
    client_id: string;
    dpop_proof: string;
    // authorization_code parameters:
    code?: string;
    redirect_uri?: string;
    code_verifier?: string;
    // token_exchange parameters:
    subject_token?: string;
    subject_token_type?: string;
    actor_token?: string;
    actor_token_type?: string;
    audience?: string;
    scope?: string;
    // Bonus task: whether to trigger step-up re-consent when child scope exceeds super app scope
    bonus_reconsent_mode?: boolean;
    reconsent_approved?: boolean;
  }): {
    status: number;
    body: {
      access_token?: string;
      token_type?: 'DPoP';
      issued_token_type?: string;
      id_token?: string;
      device_secret?: string;
      expires_in?: number;
      scope?: string;
      error?: string;
      error_description?: string;
      required_scopes_diff?: string[];
    };
  } {
    // Verify DPoP proof header first (common to both grants)
    const dpopCheck = verifyAndDecodeJwt<DpopProofPayload>(req.dpop_proof);
    const dpopJwk = dpopCheck.header?.jwk as JWKPublic | undefined;
    if (!dpopCheck.valid || !dpopJwk || !dpopJwk.x || !dpopJwk.y) {
      return {
        status: 400,
        body: {
          error: 'invalid_dpop_proof',
          error_description: 'Malformed or unverifiable DPoP proof header on /oauth2/token',
        },
      };
    }

    if (dpopCheck.payload?.htm && dpopCheck.payload.htm !== 'POST') {
      return {
        status: 400,
        body: {
          error: 'invalid_dpop_proof',
          error_description: `DPoP proof htm must be POST (got '${dpopCheck.payload.htm}')`,
        },
      };
    }

    if (
      dpopCheck.payload?.htu &&
      !validateDpopHtu(dpopCheck.payload.htu, '/oauth2/token', [this.issuer, 'https://esignet.mosip.net'])
    ) {
      return {
        status: 400,
        body: {
          error: 'invalid_dpop_proof',
          error_description: `DPoP proof htu '${dpopCheck.payload.htu}' does not match /oauth2/token endpoint on this server`,
        },
      };
    }

    const dpopThumbprint = computeJwkThumbprint(dpopJwk);

    if (req.grant_type === 'authorization_code') {
      return this.handleAuthorizationCodeGrant(req, dpopThumbprint);
    }

    if (
      req.grant_type === 'urn:ietf:params:oauth:grant-type:token-exchange' ||
      req.grant_type === 'token_exchange'
    ) {
      return this.handleTokenExchangeGrant(req, dpopThumbprint);
    }

    return {
      status: 400,
      body: {
        error: 'unsupported_grant_type',
        error_description: `Grant type '${req.grant_type}' is not supported by Thunder ID Engine`,
      },
    };
  }

  /**
   * Mandatory Tasks 2, 4, 5, 6: Authorization Code Grant + device_sso Scope Validation + Device Secret Generation
   */
  private handleAuthorizationCodeGrant(
    req: {
      client_id: string;
      code?: string;
      redirect_uri?: string;
      code_verifier?: string;
      dpop_proof: string;
    },
    dpopThumbprint: string
  ) {
    const authId = req.code ? this.codeToSessionId.get(req.code) : undefined;
    const session = authId ? this.authSessions.get(authId) : undefined;

    if (!session || !session.sub || session.client_id !== req.client_id) {
      return {
        status: 400,
        body: {
          error: 'invalid_grant',
          error_description: 'Invalid or expired authorization_code',
        },
      };
    }

    // Verify PKCE S256
    if (!req.code_verifier || computePkceChallenge(req.code_verifier) !== session.code_challenge) {
      return {
        status: 400,
        body: {
          error: 'invalid_grant',
          error_description: 'PKCE code_verifier S256 check failed',
        },
      };
    }

    // Verify DPoP key thumbprint matches PAR dpop_jkt
    if (dpopThumbprint !== session.dpop_jkt) {
      const errBody = {
        error: 'invalid_dpop_proof',
        error_description: `DPoP proof key thumbprint (${dpopThumbprint.slice(0, 10)}...) does not match PAR dpop_jkt (${session.dpop_jkt.slice(0, 10)}...)`,
      };
      this.appendLog({
        flow: 'SUPER_APP_PAR_LOGIN',
        actorFrom: 'Super App',
        actorTo: 'Thunder ID Engine',
        title: 'POST /oauth2/token (Rejected: DPoP Thumbprint Mismatch)',
        endpoint: 'POST /oauth2/token',
        method: 'POST',
        status: 'error',
        statusCode: 400,
        requestPayload: req,
        responsePayload: errBody,
      });
      return { status: 400, body: errBody };
    }

    const client = this.registeredClients[req.client_id];
    const requestedDeviceSso = session.consented_scopes.includes('device_sso');

    // Mandatory Task 2: Validate the device_sso scope at the token endpoint
    // Confirming allowed_authorization_scopes includes device_sso
    if (requestedDeviceSso && !client?.allowed_authorization_scopes.includes('device_sso')) {
      const errBody = {
        error: 'invalid_scope',
        error_description: `Client '${req.client_id}' is not authorized for 'device_sso' scope (missing from allowed_authorization_scopes)`,
      };
      this.appendLog({
        flow: 'SUPER_APP_PAR_LOGIN',
        actorFrom: 'Super App',
        actorTo: 'Thunder ID Engine',
        title: 'POST /oauth2/token (Rejected: device_sso Not Allowed for Client)',
        endpoint: 'POST /oauth2/token',
        method: 'POST',
        status: 'error',
        statusCode: 400,
        requestPayload: req,
        responsePayload: errBody,
        rfcTaskRef: 'Task 2: Validate scope at token endpoint [eSignet]',
      });
      return { status: 400, body: errBody };
    }

    const now = Math.floor(Date.now() / 1000);
    const scopeStr = session.consented_scopes.join(' ');
    let deviceSecret: string | undefined;
    let dsHash: string | undefined;

    // Mandatory Task 5: Once device_sso scope is found valid for the client, invoke Device Secret Provider
    if (requestedDeviceSso) {
      const generated = this.deviceSecretProvider.generateDeviceSecret({
        sub: session.sub,
        auth_id: session.auth_id,
        client_id: session.client_id,
        scope: scopeStr,
        acr: session.acr || 'mosip:idp:acr:generated-code',
        claims: session.consented_claims,
        dpop_jkt: dpopThumbprint,
        nowSec: now,
      });
      deviceSecret = generated.device_secret;
      dsHash = generated.ds_hash;

      this.appendLog({
        flow: 'SUPER_APP_PAR_LOGIN',
        actorFrom: 'Thunder ID Engine',
        actorTo: 'DeviceSecretProvider (eSignet)',
        title: 'GenerateDeviceSecret -> Sign JWS & JWE Encrypt (Embed ds_hash)',
        endpoint: 'DeviceSecretProvider.GenerateDeviceSecret',
        method: 'RPC',
        status: 'success',
        statusCode: 200,
        requestPayload: {
          auth_id: session.auth_id,
          client_id: session.client_id,
          scope: scopeStr,
          cnf: { jkt: dpopThumbprint },
        },
        responsePayload: {
          ds_hash: dsHash,
          device_secret_preview: `${deviceSecret.slice(0, 36)}...`,
        },
        rfcTaskRef: 'Task 4 & 5: Generate Device Secret & ds_hash [eSignet]',
      });
    }

    // Issue ID Token with embedded ds_hash and sid (Mandatory Task 4.a.ix)
    const idTokenPayload: IdTokenPayload = {
      iss: this.issuer,
      sub: session.sub,
      aud: session.client_id,
      azp: session.client_id,
      iat: now,
      exp: now + 3600,
      sid: session.auth_id,
      nonce: session.nonce,
      acr: session.acr || 'mosip:idp:acr:generated-code',
      ...(dsHash ? { ds_hash: dsHash } : {}),
    };

    const idToken = signJwt(
      { alg: 'RS256', typ: 'JWT', kid: this.idTokenSigningKey },
      idTokenPayload as unknown as Record<string, unknown>,
      this.idTokenSigningKey
    );

    // Issue DPoP-bound Access Token
    const accessTokenPayload: AccessTokenPayload = {
      iss: this.issuer,
      sub: session.sub,
      aud: this.issuer,
      client_id: session.client_id,
      scope: scopeStr,
      cnf: {
        jkt: dpopThumbprint,
      },
      iat: now,
      exp: now + 3600,
      jti: `at-${now}-${Math.random().toString(36).slice(2, 8)}`,
      consented_claims: session.consented_claims,
    };

    const accessToken = signJwt(
      { alg: 'ES256', typ: 'at+jwt', kid: this.accessTokenSigningKey },
      accessTokenPayload as unknown as Record<string, unknown>,
      this.accessTokenSigningKey
    );

    // Mandatory Task 6: Return access_token, id_token, and device_secret to Super App
    const resBody = {
      access_token: accessToken,
      token_type: 'DPoP' as const,
      id_token: idToken,
      ...(deviceSecret ? { device_secret: deviceSecret } : {}),
      expires_in: 3600,
      scope: scopeStr,
    };

    this.appendLog({
      flow: 'SUPER_APP_PAR_LOGIN',
      actorFrom: 'Thunder ID Engine',
      actorTo: 'Super App',
      title: '200 OK (access_token [DPoP], id_token [ds_hash], device_secret)',
      endpoint: 'POST /oauth2/token',
      method: 'POST',
      status: 'success',
      statusCode: 200,
      requestPayload: {
        grant_type: 'authorization_code',
        client_id: req.client_id,
        code: req.code,
      },
      responsePayload: {
        token_type: 'DPoP',
        expires_in: 3600,
        scope: scopeStr,
        ds_hash: dsHash,
        has_device_secret: Boolean(deviceSecret),
      },
      rfcTaskRef: 'Task 6: Return tokens and device_secret to Super App',
    });

    return { status: 200, body: resBody };
  }

  /**
   * Mandatory Tasks 8, 9, 10 & Bonus Task 1: OAuth 2.0 Token Exchange Grant for Child App Silent SSO
   */
  private handleTokenExchangeGrant(
    req: {
      client_id: string;
      subject_token?: string;
      subject_token_type?: string;
      actor_token?: string;
      actor_token_type?: string;
      audience?: string;
      scope?: string;
      dpop_proof: string;
      bonus_reconsent_mode?: boolean;
      reconsent_approved?: boolean;
    },
    dpopThumbprint: string
  ) {
    const requestedScopes = (req.scope || 'openid profile').split(/\s+/).filter(Boolean);

    // Mandatory Task 10b: Reject any token endpoint call with token_exchange grant that includes device_sso scope!
    if (requestedScopes.includes('device_sso')) {
      const errBody = {
        error: 'invalid_scope',
        error_description:
          "The 'device_sso' scope is strictly forbidden in token_exchange grant requests (valid only on authorization_code grant).",
      };
      this.appendLog({
        flow: 'CHILD_APP_TOKEN_EXCHANGE',
        actorFrom: 'Child App',
        actorTo: 'Thunder ID Engine',
        title: 'POST /oauth2/token (Rejected: device_sso Forbidden in Token Exchange)',
        endpoint: 'POST /oauth2/token',
        method: 'POST',
        status: 'error',
        statusCode: 400,
        requestPayload: { client_id: req.client_id, scope: req.scope, grant_type: 'token_exchange' },
        responsePayload: errBody,
        rfcTaskRef: 'Task 10b: Reject token_exchange with device_sso scope',
      });
      return { status: 400, body: errBody };
    }

    // Mandatory Task 9.a.i: Validate actor_token_type == urn:openid:params:token-type:device-secret
    if (req.actor_token_type !== 'urn:openid:params:token-type:device-secret') {
      const errBody = {
        error: 'invalid_request',
        error_description:
          "actor_token_type must be 'urn:openid:params:token-type:device-secret'",
      };
      return { status: 400, body: errBody };
    }

    if (req.subject_token_type !== 'urn:ietf:params:oauth:token-type:id_token') {
      return {
        status: 400,
        body: {
          error: 'invalid_request',
          error_description: "subject_token_type must be 'urn:ietf:params:oauth:token-type:id_token'",
        },
      };
    }

    if (!req.subject_token || !req.actor_token) {
      return {
        status: 400,
        body: {
          error: 'invalid_request',
          error_description: 'Both subject_token (id_token) and actor_token (device_secret) are required',
        },
      };
    }

    // Mandatory Task 9.a.iii: Validate the id_token signature and claims
    const idTokenVerified = verifyAndDecodeJwt<IdTokenPayload>(
      req.subject_token,
      this.idTokenSigningKey
    );
    if (!idTokenVerified.valid) {
      return {
        status: 400,
        body: {
          error: 'invalid_grant',
          error_description: idTokenVerified.error || 'Invalid subject_token (id_token) signature',
        },
      };
    }
    const idTokenClaims = idTokenVerified.payload;

    // Mandatory Task 9.a.iii.3: Confirming allowed_authorization_scopes includes device_sso
    const childClient = this.registeredClients[req.client_id];
    if (!childClient || !childClient.allowed_authorization_scopes.includes('device_sso')) {
      const errBody = {
        error: 'invalid_scope',
        error_description: `Requesting client '${req.client_id}' does not have 'device_sso' enabled in allowed_authorization_scopes`,
      };
      this.appendLog({
        flow: 'CHILD_APP_TOKEN_EXCHANGE',
        actorFrom: 'Child App',
        actorTo: 'Thunder ID Engine',
        title: 'POST /oauth2/token (Rejected: Client Not Enabled for device_sso)',
        endpoint: 'POST /oauth2/token',
        method: 'POST',
        status: 'error',
        statusCode: 400,
        requestPayload: { client_id: req.client_id },
        responsePayload: errBody,
        rfcTaskRef: 'Task 9.a.iii.3: Confirm allowed_authorization_scopes includes device_sso',
      });
      return { status: 400, body: errBody };
    }

    // Mandatory Task 9.a.ii: Validate actor_token via DeviceSecretProvider.ValidateDeviceSecret
    const dsValidation = this.deviceSecretProvider.validateDeviceSecret({
      requesting_client_id: req.client_id,
      device_secret: req.actor_token,
      registeredClients: this.registeredClients,
    });

    if (!dsValidation.valid || !dsValidation.payload) {
      const errBody = {
        error: dsValidation.error || 'invalid_grant',
        error_description: dsValidation.error_description || 'Device secret validation failed',
      };
      this.appendLog({
        flow: 'CHILD_APP_TOKEN_EXCHANGE',
        actorFrom: 'Thunder ID Engine',
        actorTo: 'DeviceSecretProvider (eSignet)',
        title: 'ValidateDeviceSecret Failed',
        endpoint: 'DeviceSecretProvider.ValidateDeviceSecret',
        method: 'RPC',
        status: 'error',
        statusCode: 400,
        requestPayload: { client_id: req.client_id },
        responsePayload: errBody,
        rfcTaskRef: 'Task 9.a.ii: Validate actor_token via DeviceSecretProvider',
      });
      return { status: 400, body: errBody };
    }

    const dsClaims = dsValidation.payload;

    // Mandatory Task 9.a.iii.4: Confirming cnf.jkt in device_secret matches key thumbprint in current request's DPoP header
    if (dsClaims.cnf.jkt !== dpopThumbprint) {
      const errBody = {
        error: 'invalid_dpop_proof',
        error_description: `Hardware key binding mismatch: DPoP proof jkt (${dpopThumbprint.slice(0, 10)}...) != device_secret cnf.jkt (${dsClaims.cnf.jkt.slice(0, 10)}...). Token exchange must be signed by Super App's Key A.`,
      };
      this.appendLog({
        flow: 'CHILD_APP_TOKEN_EXCHANGE',
        actorFrom: 'Child App',
        actorTo: 'Thunder ID Engine',
        title: 'POST /oauth2/token (Rejected: DPoP Key Thumbprint != device_secret cnf.jkt)',
        endpoint: 'POST /oauth2/token',
        method: 'POST',
        status: 'error',
        statusCode: 400,
        requestPayload: { dpop_jkt: dpopThumbprint, expected_cnf_jkt: dsClaims.cnf.jkt },
        responsePayload: errBody,
        rfcTaskRef: 'Task 9.a.iii.4: Confirm cnf.jkt matches DPoP header thumbprint',
      });
      return { status: 400, body: errBody };
    }

    // Mandatory Task 9.a.iii.1: Confirming binding between id_token and device_secret via ds_hash
    const recomputedDsHash = computeDsHash(req.actor_token);
    if (!idTokenClaims.ds_hash || idTokenClaims.ds_hash !== recomputedDsHash) {
      const errBody = {
        error: 'invalid_grant',
        error_description: `Cryptographic binding check failed: recomputed ds_hash (${recomputedDsHash}) != id_token.ds_hash (${idTokenClaims.ds_hash || 'none'})`,
      };
      this.appendLog({
        flow: 'CHILD_APP_TOKEN_EXCHANGE',
        actorFrom: 'Child App',
        actorTo: 'Thunder ID Engine',
        title: 'POST /oauth2/token (Rejected: ds_hash Binding Mismatch)',
        endpoint: 'POST /oauth2/token',
        method: 'POST',
        status: 'error',
        statusCode: 400,
        requestPayload: { recomputed_ds_hash: recomputedDsHash, id_token_ds_hash: idTokenClaims.ds_hash },
        responsePayload: errBody,
        rfcTaskRef: 'Task 9.a.iii.1: Confirm binding between id_token and device_secret via ds_hash',
      });
      return { status: 400, body: errBody };
    }

    // Mandatory Task 9.a.iii.2: Validating the session ID (sid)
    const session = this.authSessions.get(idTokenClaims.sid);
    if (idTokenClaims.sid !== dsClaims.auth_id || !session || !session.active) {
      const errBody = {
        error: 'invalid_grant',
        error_description: `Session ID (sid=${idTokenClaims.sid}) is invalid, mismatched with device_secret.auth_id, or logged out`,
      };
      this.appendLog({
        flow: 'CHILD_APP_TOKEN_EXCHANGE',
        actorFrom: 'Child App',
        actorTo: 'Thunder ID Engine',
        title: 'POST /oauth2/token (Rejected: Session ID sid Invalid)',
        endpoint: 'POST /oauth2/token',
        method: 'POST',
        status: 'error',
        statusCode: 400,
        requestPayload: { sid: idTokenClaims.sid, ds_auth_id: dsClaims.auth_id },
        responsePayload: errBody,
        rfcTaskRef: 'Task 9.a.iii.2: Validate session ID (sid)',
      });
      return { status: 400, body: errBody };
    }

    // Mandatory Task 10a: Enforce that the scope requested by the second App is a subset of the scope originally granted to the first App
    const superAppGrantedScopes = dsClaims.scope.split(/\s+/).filter(Boolean);
    const outOfBoundsScopes = requestedScopes.filter((s) => !superAppGrantedScopes.includes(s));

    if (outOfBoundsScopes.length > 0) {
      // Bonus Task 1: Trigger a re-consent screen in the second App when scopes differ and bonus_reconsent_mode is enabled
      if (req.bonus_reconsent_mode && !req.reconsent_approved) {
        const errBody = {
          error: 'interaction_required',
          error_description: `Requested scope [${outOfBoundsScopes.join(', ')}] exceeds Super App's consented scope [${superAppGrantedScopes.join(', ')}]. Triggering step-up re-consent screen in Child App.`,
          required_scopes_diff: outOfBoundsScopes,
        };
        this.appendLog({
          flow: 'CHILD_APP_TOKEN_EXCHANGE',
          actorFrom: 'Thunder ID Engine',
          actorTo: 'ConsentProvider',
          title: 'ResolveConsent -> CAPTURE (Bonus Task: Trigger Child App Re-Consent)',
          endpoint: 'ConsentProvider.ResolveConsent',
          method: 'RPC',
          status: 'warning',
          statusCode: 400,
          requestPayload: {
            requested_scope: requestedScopes,
            super_app_scope: superAppGrantedScopes,
          },
          responsePayload: errBody,
          rfcTaskRef: 'Bonus Task 1: Trigger re-consent screen when scopes differ',
        });
        return { status: 400, body: errBody };
      }

      if (!req.reconsent_approved) {
        const errBody = {
          error: 'invalid_scope',
          error_description: `Requested scope [${outOfBoundsScopes.join(', ')}] is not a subset of Super App's granted scope [${superAppGrantedScopes.join(', ')}]`,
        };
        this.appendLog({
          flow: 'CHILD_APP_TOKEN_EXCHANGE',
          actorFrom: 'Child App',
          actorTo: 'Thunder ID Engine',
          title: 'POST /oauth2/token (Rejected: Scope Not Subset of Super App Grant)',
          endpoint: 'POST /oauth2/token',
          method: 'POST',
          status: 'error',
          statusCode: 400,
          requestPayload: {
            requested_scope: requestedScopes,
            super_app_granted_scope: superAppGrantedScopes,
          },
          responsePayload: errBody,
          rfcTaskRef: 'Task 10a: Enforce scope subset rule for second App',
        });
        return { status: 400, body: errBody };
      }
    }

    // All checks pass! Record consent audit trail (Sequence Diagram 2: append consent_history row derived_from=org_client_id)
    const grantedScopeStr = requestedScopes.join(' ');
    this.consentAuditLog.unshift({
      id: `consent-sso-${Date.now()}`,
      sub: dsClaims.sub,
      client_id: req.client_id,
      derived_from_client_id: dsClaims.client_id,
      granted_scopes: requestedScopes,
      accepted_claims: dsClaims.claims,
      mode: req.reconsent_approved ? 'STEP_UP_RECONSENT' : 'SILENT_SSO_NOCAPTURE',
      timestamp: new Date().toISOString(),
    });

    const now = Math.floor(Date.now() / 1000);

    // Issue Child App Access Token bound to the SAME hardware key cnf.jkt (Super App's Key A)
    const childAccessTokenPayload: AccessTokenPayload = {
      iss: this.issuer,
      sub: dsClaims.sub,
      aud: this.issuer,
      client_id: req.client_id,
      scope: grantedScopeStr,
      cnf: {
        jkt: dsClaims.cnf.jkt, // Bound to Key A!
      },
      iat: now,
      exp: now + 3600,
      jti: `at-child-${now}-${Math.random().toString(36).slice(2, 8)}`,
      consented_claims: dsClaims.claims,
    };

    const childAccessToken = signJwt(
      { alg: 'ES256', typ: 'at+jwt', kid: this.accessTokenSigningKey },
      childAccessTokenPayload as unknown as Record<string, unknown>,
      this.accessTokenSigningKey
    );

    const childIdTokenPayload: IdTokenPayload = {
      iss: this.issuer,
      sub: dsClaims.sub,
      aud: req.client_id,
      azp: req.client_id,
      iat: now,
      exp: now + 3600,
      sid: dsClaims.auth_id,
      acr: dsClaims.acr,
    };

    const childIdToken = signJwt(
      { alg: 'RS256', typ: 'JWT', kid: this.idTokenSigningKey },
      childIdTokenPayload as unknown as Record<string, unknown>,
      this.idTokenSigningKey
    );

    const resBody = {
      access_token: childAccessToken,
      issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      token_type: 'DPoP' as const,
      id_token: childIdToken,
      expires_in: 3600,
      scope: grantedScopeStr,
    };

    this.appendLog({
      flow: 'CHILD_APP_TOKEN_EXCHANGE',
      actorFrom: 'Thunder ID Engine',
      actorTo: 'Child App',
      title: '200 OK Silent SSO Token Exchange (Bound to Super App Key A)',
      endpoint: 'POST /oauth2/token',
      method: 'POST',
      status: 'success',
      statusCode: 200,
      requestPayload: {
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        client_id: req.client_id,
        scope: grantedScopeStr,
        actor_token_type: req.actor_token_type,
      },
      responsePayload: {
        issued_token_type: resBody.issued_token_type,
        token_type: 'DPoP',
        scope: grantedScopeStr,
        cnf_jkt: dsClaims.cnf.jkt,
        consent_mode: req.reconsent_approved ? 'STEP_UP_RECONSENT' : 'NOCAPTURE (Silent)',
      },
      rfcTaskRef: 'Task 9 & 10: Token Exchange & Scope Subset Enforcement',
    });

    return { status: 200, body: resBody };
  }

  /**
   * Step 6 / 7: GET /oauth2/userinfo
   * Verifies DPoP proof key thumbprint == access_token's cnf.jkt and ath == hash(access_token)
   */
  public handleUserInfo(req: {
    access_token: string;
    dpop_proof: string;
  }): {
    status: number;
    body: Record<string, unknown>;
  } {
    const atVerified = verifyAndDecodeJwt<AccessTokenPayload>(
      req.access_token,
      this.accessTokenSigningKey
    );
    if (!atVerified.valid) {
      return {
        status: 401,
        body: { error: 'invalid_token', error_description: 'Invalid DPoP-bound access_token' },
      };
    }

    const dpopVerified = verifyAndDecodeJwt<DpopProofPayload>(req.dpop_proof);
    const dpopJwk = dpopVerified.header?.jwk as JWKPublic | undefined;
    if (!dpopVerified.valid || !dpopJwk) {
      return {
        status: 401,
        body: { error: 'invalid_dpop_proof', error_description: 'Invalid DPoP proof on /userinfo' },
      };
    }

    if (dpopVerified.payload?.htm && dpopVerified.payload.htm !== 'GET') {
      return {
        status: 401,
        body: {
          error: 'invalid_dpop_proof',
          error_description: `DPoP proof htm must be GET (got '${dpopVerified.payload.htm}')`,
        },
      };
    }

    if (
      dpopVerified.payload?.htu &&
      !validateDpopHtu(dpopVerified.payload.htu, '/oauth2/userinfo', [this.issuer, 'https://esignet.mosip.net'])
    ) {
      return {
        status: 401,
        body: {
          error: 'invalid_dpop_proof',
          error_description: `DPoP proof htu '${dpopVerified.payload.htu}' does not match /oauth2/userinfo endpoint on this server`,
        },
      };
    }

    const dpopJkt = computeJwkThumbprint(dpopJwk);
    const atClaims = atVerified.payload;

    if (dpopJkt !== atClaims.cnf.jkt) {
      return {
        status: 401,
        body: {
          error: 'invalid_dpop_proof',
          error_description: 'DPoP proof key thumbprint does not match access_token cnf.jkt',
        },
      };
    }

    const expectedAth = computeAccessTokenHash(req.access_token);
    if (dpopVerified.payload.ath && dpopVerified.payload.ath !== expectedAth) {
      return {
        status: 401,
        body: {
          error: 'invalid_dpop_proof',
          error_description: 'DPoP proof ath claim does not match SHA-256 hash of access_token',
        },
      };
    }

    // Lookup citizen by sub
    const citizen = Object.values(CITIZEN_DIRECTORY).find((c) => c.sub === atClaims.sub);
    if (!citizen) {
      return { status: 404, body: { error: 'not_found', error_description: 'Citizen subject not found' } };
    }

    const scopes = atClaims.scope.split(/\s+/).filter(Boolean);
    const filteredClaims: Record<string, unknown> = {
      sub: citizen.sub,
    };

    if (scopes.includes('profile')) {
      filteredClaims.name = citizen.name;
      filteredClaims.birthdate = citizen.birthdate;
      filteredClaims.gender = citizen.gender;
      filteredClaims.address = citizen.address;
    }
    if (scopes.includes('email')) {
      filteredClaims.email = citizen.email;
      filteredClaims.email_verified = true;
    }
    if (scopes.includes('phone')) {
      filteredClaims.phone_number = citizen.phone_number;
      filteredClaims.phone_number_verified = true;
    }
    if (scopes.includes('verified_claims')) {
      filteredClaims.verified_claims = citizen.verified_claims;
    }

    this.appendLog({
      flow: 'USERINFO',
      actorFrom: atClaims.client_id === 'mosip-super-wallet-android' ? 'Super App' : 'Child App',
      actorTo: 'Thunder ID Engine',
      title: `GET /oauth2/userinfo -> 200 OK (Scoped to: ${atClaims.scope})`,
      endpoint: 'GET /oauth2/userinfo',
      method: 'GET',
      status: 'success',
      statusCode: 200,
      requestPayload: {
        client_id: atClaims.client_id,
        dpop_jkt: dpopJkt,
        ath: expectedAth,
      },
      responsePayload: filteredClaims,
    });

    return { status: 200, body: filteredClaims };
  }

  /**
   * Simulates Android IPC bindService() call from Child App to Super App (Mandatory Task 7)
   * Verifies caller's package signature matches the same vendor certificate before returning
   * id_token, device_secret, and a DPoP proof signed by Super App's hardware Key A.
   */
  public simulateAndroidBindServiceIpc(params: {
    super_app_cert_sha256: string;
    child_app_cert_sha256: string;
    child_package_name: string;
    stored_id_token?: string;
    stored_device_secret?: string;
    htm: 'POST' | 'GET';
    htu: string;
    access_token_for_ath?: string;
    signing_key?: JWKPublic;
  }): {
    allowed: boolean;
    id_token?: string;
    device_secret?: string;
    dpop_proof?: string;
    error?: string;
  } {
    if (params.super_app_cert_sha256 !== params.child_app_cert_sha256) {
      const errorMsg = `SecurityException: Caller package '${params.child_package_name}' signing certificate (${params.child_app_cert_sha256.slice(0, 14)}...) does NOT match Super App vendor certificate (${params.super_app_cert_sha256.slice(0, 14)}...). bindService() rejected.`;
      this.appendLog({
        flow: 'IPC_BIND_SERVICE',
        actorFrom: 'Child App',
        actorTo: 'Super App (SSO Signing Service)',
        title: 'bindService() Rejected: Vendor Certificate Mismatch',
        endpoint: 'AIDL: ISSOSigningService.requestSsoBundle()',
        method: 'IPC',
        status: 'error',
        statusCode: 403,
        requestPayload: {
          caller_package: params.child_package_name,
          caller_cert: params.child_app_cert_sha256,
          expected_vendor_cert: params.super_app_cert_sha256,
        },
        responsePayload: { error: errorMsg },
        rfcTaskRef: 'Task 7: Retrieve id_token, device_secret & DPoP proof via IPC',
      });
      return { allowed: false, error: errorMsg };
    }

    if (params.htm === 'POST' && (!params.stored_id_token || !params.stored_device_secret)) {
      return {
        allowed: false,
        error: 'No active SSO session in Super App storage. Please sign in to the Super App first.',
      };
    }

    const keyToSign = params.signing_key || SUPER_APP_KEY_A;
    const dpop_proof = createDpopProof({
      jwk: keyToSign,
      htm: params.htm,
      htu: params.htu,
      accessToken: params.access_token_for_ath,
    });

    this.appendLog({
      flow: 'IPC_BIND_SERVICE',
      actorFrom: 'Child App',
      actorTo: 'Super App (SSO Signing Service)',
      title:
        params.htm === 'POST'
          ? 'bindService() -> Verify Vendor Cert & Sign Token Exchange DPoP with Key A'
          : 'bindService() -> Sign /userinfo DPoP Proof with Key A (ath bound)',
      endpoint: 'AIDL: ISSOSigningService.signDpopAndFetchCredentials()',
      method: 'IPC',
      status: 'success',
      statusCode: 200,
      requestPayload: {
        caller_package: params.child_package_name,
        vendor_cert_verified: true,
        htm: params.htm,
        htu: params.htu,
      },
      responsePayload: {
        id_token_returned: Boolean(params.stored_id_token),
        device_secret_returned: Boolean(params.stored_device_secret),
        dpop_signed_by_kid: keyToSign.kid,
      },
      rfcTaskRef: 'Task 7: Retrieve id_token, device_secret & DPoP proof via IPC',
    });

    return {
      allowed: true,
      id_token: params.stored_id_token,
      device_secret: params.stored_device_secret,
      dpop_proof,
    };
  }

  /**
   * Step 8: POST /oauth2/revoke & POST /oauth2/logout (Session Revocation & Backchannel Logout)
   * - Revokes the device_secret by recording its jti in the revocation blacklist.
   * - Invalidates the sid (auth_id) so subsequent token exchanges fail with invalid_grant.
   */
  public handleRevokeOrLogout(params: {
    device_secret?: string;
    id_token?: string;
    sid?: string;
    client_id?: string;
  }): {
    status: number;
    body: {
      revoked: boolean;
      revoked_jti?: string;
      invalidated_sid?: string;
      error?: string;
      error_description?: string;
    };
  } {
    let revokedJti: string | undefined;
    let invalidatedSid: string | undefined = params.sid;

    if (params.device_secret) {
      const decrypted = decryptJweDeviceSecret(params.device_secret);
      if (decrypted.valid && decrypted.innerJws) {
        const decoded = verifyAndDecodeJwt<DeviceSecretPayload>(decrypted.innerJws);
        if (decoded.valid && decoded.payload) {
          revokedJti = decoded.payload.jti;
          this.deviceSecretProvider.revokeDeviceSecret(revokedJti);
          if (!invalidatedSid) {
            invalidatedSid = decoded.payload.auth_id;
          }
        }
      }
    }

    if (params.id_token && !invalidatedSid) {
      const decodedId = verifyAndDecodeJwt<IdTokenPayload>(params.id_token);
      if (decodedId.valid && decodedId.payload?.sid) {
        invalidatedSid = decodedId.payload.sid;
      }
    }

    if (invalidatedSid) {
      const session = this.authSessions.get(invalidatedSid);
      if (session) {
        session.active = false;
      }
    }

    if (!revokedJti && !invalidatedSid) {
      return {
        status: 400,
        body: {
          revoked: false,
          error: 'invalid_request',
          error_description: 'Must provide a valid device_secret, id_token, or sid to revoke',
        },
      };
    }

    const resBody = {
      revoked: true,
      revoked_jti: revokedJti,
      invalidated_sid: invalidatedSid,
    };

    this.appendLog({
      flow: 'REVOKE_LOGOUT',
      actorFrom: params.client_id || 'Super App',
      actorTo: 'Thunder ID Engine',
      title: 'POST /oauth2/revoke -> Blacklist device_secret JTI & Terminate Session SID',
      endpoint: 'POST /oauth2/revoke',
      method: 'POST',
      status: 'warning',
      statusCode: 200,
      requestPayload: {
        client_id: params.client_id || 'mosip-super-wallet-android',
        has_device_secret: Boolean(params.device_secret),
        sid: invalidatedSid,
      },
      responsePayload: resBody,
      rfcTaskRef: 'Task 4b & 9.a.iii.2: Revoke device_secret JTI & Invalidate Session ID (sid)',
    });

    return { status: 200, body: resBody };
  }
}
