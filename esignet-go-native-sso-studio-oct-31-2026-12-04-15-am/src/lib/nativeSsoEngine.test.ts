import test from 'node:test';
import assert from 'node:assert/strict';
import {
  NativeSsoServerEngine,
  SUPER_APP_KEY_A,
  ROGUE_DEVICE_KEY_X,
  DEFAULT_VENDOR_CERT_SHA256,
  UNTRUSTED_VENDOR_CERT_SHA256,
  computeJwkThumbprint,
  computePkceChallenge,
  computeDsHash,
  createDpopProof,
  verifyAndDecodeJwt,
  decryptJweDeviceSecret,
  type IdTokenPayload,
  type DeviceSecretPayload,
} from './nativeSsoEngine';

test('Mandatory Tasks 1-6: Super App PAR + DPoP Login issues id_token with ds_hash and signed-then-encrypted device_secret', () => {
  const engine = new NativeSsoServerEngine();
  const dpopJkt = computeJwkThumbprint(SUPER_APP_KEY_A);
  const codeVerifier = 'pkce-super-app-verifier-random-9876543210';
  const codeChallenge = computePkceChallenge(codeVerifier);

  // Task 1: PAR request with device_sso scope
  const parRes = engine.handleParRequest({
    client_id: 'mosip-super-wallet-android',
    scope: 'openid profile email device_sso',
    redirect_uri: 'io.mosip.inji.superwallet://oauth2redirect',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    dpop_jkt: dpopJkt,
  });
  assert.equal(parRes.status, 201);
  assert.ok(parRes.body.request_uri);

  // Authorize session
  const authRes = engine.startAuthorizeSession({
    client_id: 'mosip-super-wallet-android',
    request_uri: parRes.body.request_uri!,
  });
  assert.equal(authRes.status, 200);
  const authId = authRes.body.auth_id!;

  // OTP Authentication
  const otpRes = engine.authenticateWithOtp({
    auth_id: authId,
    uin: '8294017365',
    otp: '111111',
  });
  assert.equal(otpRes.status, 200);
  assert.equal(otpRes.body.verified, true);

  // Consent Approval
  const consentRes = engine.submitConsent({
    auth_id: authId,
    accepted_scopes: ['openid', 'profile', 'email', 'device_sso'],
    accepted_claims: ['name', 'email', 'phone_number', 'birthdate'],
  });
  assert.equal(consentRes.status, 200);
  const code = consentRes.body.code!;

  // Task 2, 4, 5, 6: Token endpoint with authorization_code and DPoP proof
  const dpopProof = createDpopProof({
    jwk: SUPER_APP_KEY_A,
    htm: 'POST',
    htu: 'https://esignet.mosip.net/oauth2/token',
  });

  const tokenRes = engine.handleTokenEndpoint({
    grant_type: 'authorization_code',
    client_id: 'mosip-super-wallet-android',
    code,
    redirect_uri: 'io.mosip.inji.superwallet://oauth2redirect',
    code_verifier: codeVerifier,
    dpop_proof: dpopProof,
  });

  assert.equal(tokenRes.status, 200);
  assert.ok(tokenRes.body.access_token);
  assert.ok(tokenRes.body.id_token);
  assert.ok(tokenRes.body.device_secret);

  // Verify id_token contains ds_hash and sid
  const decodedIdToken = verifyAndDecodeJwt<IdTokenPayload>(tokenRes.body.id_token!);
  assert.equal(decodedIdToken.valid, true);
  assert.equal(decodedIdToken.payload.sid, authId);
  assert.equal(decodedIdToken.payload.ds_hash, computeDsHash(tokenRes.body.device_secret!));

  // Verify device_secret JWE decrypts to JWS containing all Mandatory Task 4a claims
  const decryptedJwe = decryptJweDeviceSecret(tokenRes.body.device_secret!);
  assert.equal(decryptedJwe.valid, true);
  const decodedDs = verifyAndDecodeJwt<DeviceSecretPayload>(decryptedJwe.innerJws!);
  assert.equal(decodedDs.valid, true);
  assert.equal(decodedDs.payload.cnf.jkt, dpopJkt);
  assert.equal(decodedDs.payload.auth_id, authId);
  assert.equal(decodedDs.payload.client_id, 'mosip-super-wallet-android');
  assert.equal(decodedDs.payload.scope, 'openid profile email device_sso');
  assert.equal(decodedDs.payload.acr, 'mosip:idp:acr:generated-code');
  assert.equal(decodedDs.payload.iss, 'https://esignet.mosip.net');
  assert.ok(decodedDs.payload.exp > decodedDs.payload.iat);
});

test('Mandatory Task 2: Reject device_sso scope when client allowed_authorization_scopes does not include device_sso', () => {
  const engine = new NativeSsoServerEngine();
  const dpopJkt = computeJwkThumbprint(SUPER_APP_KEY_A);
  const codeVerifier = 'verifier-unprivileged';
  const parRes = engine.handleParRequest({
    client_id: 'mosip-unprivileged-client',
    scope: 'openid profile device_sso',
    redirect_uri: 'io.mosip.legacy.rp://callback',
    code_challenge: computePkceChallenge(codeVerifier),
    code_challenge_method: 'S256',
    dpop_jkt: dpopJkt,
  });
  const authRes = engine.startAuthorizeSession({
    client_id: 'mosip-unprivileged-client',
    request_uri: parRes.body.request_uri!,
  });
  engine.authenticateWithOtp({
    auth_id: authRes.body.auth_id!,
    uin: '8294017365',
    otp: '111111',
  });
  const consentRes = engine.submitConsent({
    auth_id: authRes.body.auth_id!,
    accepted_scopes: ['openid', 'profile', 'device_sso'],
    accepted_claims: ['name'],
  });
  const tokenRes = engine.handleTokenEndpoint({
    grant_type: 'authorization_code',
    client_id: 'mosip-unprivileged-client',
    code: consentRes.body.code!,
    code_verifier: codeVerifier,
    dpop_proof: createDpopProof({
      jwk: SUPER_APP_KEY_A,
      htm: 'POST',
      htu: 'https://esignet.mosip.net/oauth2/token',
    }),
  });
  assert.equal(tokenRes.status, 400);
  assert.equal(tokenRes.body.error, 'invalid_scope');
});

test('Mandatory Tasks 7-10 & Bonus Task 1: Child App Silent SSO via Token Exchange, IPC cert verification, DPoP key match, and scope subset rules', () => {
  const engine = new NativeSsoServerEngine();
  const dpopJkt = computeJwkThumbprint(SUPER_APP_KEY_A);
  const codeVerifier = 'verifier-super-app-main';

  // First login on Super App with scope "openid profile" (Notice "email" is NOT requested)
  const parRes = engine.handleParRequest({
    client_id: 'mosip-super-wallet-android',
    scope: 'openid profile device_sso',
    redirect_uri: 'io.mosip.inji.superwallet://oauth2redirect',
    code_challenge: computePkceChallenge(codeVerifier),
    code_challenge_method: 'S256',
    dpop_jkt: dpopJkt,
  });
  const authRes = engine.startAuthorizeSession({
    client_id: 'mosip-super-wallet-android',
    request_uri: parRes.body.request_uri!,
  });
  engine.authenticateWithOtp({
    auth_id: authRes.body.auth_id!,
    uin: '8294017365',
    otp: '111111',
  });
  const consentRes = engine.submitConsent({
    auth_id: authRes.body.auth_id!,
    accepted_scopes: ['openid', 'profile', 'device_sso'],
    accepted_claims: ['name', 'birthdate'],
  });
  const superTokens = engine.handleTokenEndpoint({
    grant_type: 'authorization_code',
    client_id: 'mosip-super-wallet-android',
    code: consentRes.body.code!,
    code_verifier: codeVerifier,
    dpop_proof: createDpopProof({
      jwk: SUPER_APP_KEY_A,
      htm: 'POST',
      htu: 'https://esignet.mosip.net/oauth2/token',
    }),
  });
  assert.equal(superTokens.status, 200);

  // Task 7: IPC bindService() rejects mismatched vendor cert
  const ipcMismatch = engine.simulateAndroidBindServiceIpc({
    super_app_cert_sha256: DEFAULT_VENDOR_CERT_SHA256,
    child_app_cert_sha256: UNTRUSTED_VENDOR_CERT_SHA256,
    child_package_name: 'com.malicious.phishing.app',
    stored_id_token: superTokens.body.id_token,
    stored_device_secret: superTokens.body.device_secret,
    htm: 'POST',
    htu: 'https://esignet.mosip.net/oauth2/token',
  });
  assert.equal(ipcMismatch.allowed, false);

  // Task 7: IPC bindService() succeeds when signed by same vendor certificate
  const ipcOk = engine.simulateAndroidBindServiceIpc({
    super_app_cert_sha256: DEFAULT_VENDOR_CERT_SHA256,
    child_app_cert_sha256: DEFAULT_VENDOR_CERT_SHA256,
    child_package_name: 'io.mosip.gov.mparivahan',
    stored_id_token: superTokens.body.id_token,
    stored_device_secret: superTokens.body.device_secret,
    htm: 'POST',
    htu: 'https://esignet.mosip.net/oauth2/token',
  });
  assert.equal(ipcOk.allowed, true);
  assert.ok(ipcOk.dpop_proof);

  // Task 10b: Reject token_exchange if device_sso scope is included
  const txWithDeviceSso = engine.handleTokenEndpoint({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    client_id: 'mosip-mparivahan-transit',
    subject_token: ipcOk.id_token,
    subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
    actor_token: ipcOk.device_secret,
    actor_token_type: 'urn:openid:params:token-type:device-secret',
    scope: 'openid profile device_sso',
    dpop_proof: ipcOk.dpop_proof!,
  });
  assert.equal(txWithDeviceSso.status, 400);
  assert.equal(txWithDeviceSso.body.error, 'invalid_scope');

  // Task 10a: Reject token_exchange if Child App requests wider scope ("email") than Super App ("openid profile")
  const txWiderScope = engine.handleTokenEndpoint({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    client_id: 'mosip-mparivahan-transit',
    subject_token: ipcOk.id_token,
    subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
    actor_token: ipcOk.device_secret,
    actor_token_type: 'urn:openid:params:token-type:device-secret',
    scope: 'openid profile email',
    dpop_proof: ipcOk.dpop_proof!,
  });
  assert.equal(txWiderScope.status, 400);
  assert.equal(txWiderScope.body.error, 'invalid_scope');

  // Bonus Task 1: Trigger interaction_required re-consent when bonus_reconsent_mode is true
  const txBonusPrompt = engine.handleTokenEndpoint({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    client_id: 'mosip-mparivahan-transit',
    subject_token: ipcOk.id_token,
    subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
    actor_token: ipcOk.device_secret,
    actor_token_type: 'urn:openid:params:token-type:device-secret',
    scope: 'openid profile email',
    dpop_proof: ipcOk.dpop_proof!,
    bonus_reconsent_mode: true,
  });
  assert.equal(txBonusPrompt.status, 400);
  assert.equal(txBonusPrompt.body.error, 'interaction_required');
  assert.deepEqual(txBonusPrompt.body.required_scopes_diff, ['email']);

  // Task 9.a.iii.4: Reject token_exchange if DPoP proof is signed by Rogue Key X instead of Key A
  const txRogueKey = engine.handleTokenEndpoint({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    client_id: 'mosip-mparivahan-transit',
    subject_token: ipcOk.id_token,
    subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
    actor_token: ipcOk.device_secret,
    actor_token_type: 'urn:openid:params:token-type:device-secret',
    scope: 'openid profile',
    dpop_proof: createDpopProof({
      jwk: ROGUE_DEVICE_KEY_X,
      htm: 'POST',
      htu: 'https://esignet.mosip.net/oauth2/token',
    }),
  });
  assert.equal(txRogueKey.status, 400);
  assert.equal(txRogueKey.body.error, 'invalid_dpop_proof');

  // Task 8 & 9: Valid narrow/subset scope ("openid profile") succeeds silently!
  const txValid = engine.handleTokenEndpoint({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    client_id: 'mosip-mparivahan-transit',
    subject_token: ipcOk.id_token,
    subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
    actor_token: ipcOk.device_secret,
    actor_token_type: 'urn:openid:params:token-type:device-secret',
    scope: 'openid profile',
    dpop_proof: ipcOk.dpop_proof!,
  });
  assert.equal(txValid.status, 200);
  assert.ok(txValid.body.access_token);
  assert.equal(txValid.body.token_type, 'DPoP');

  // Step 7: Child App calls GET /oauth2/userinfo with DPoP proof signed by Super App's Key A
  const userInfoDpop = engine.simulateAndroidBindServiceIpc({
    super_app_cert_sha256: DEFAULT_VENDOR_CERT_SHA256,
    child_app_cert_sha256: DEFAULT_VENDOR_CERT_SHA256,
    child_package_name: 'io.mosip.gov.mparivahan',
    htm: 'GET',
    htu: 'https://esignet.mosip.net/oauth2/userinfo',
    access_token_for_ath: txValid.body.access_token!,
  });
  const userInfoRes = engine.handleUserInfo({
    access_token: txValid.body.access_token!,
    dpop_proof: userInfoDpop.dpop_proof!,
  });
  assert.equal(userInfoRes.status, 200);
  assert.equal(userInfoRes.body.name, 'Ananya Deshmukh');
  assert.equal(userInfoRes.body.email, undefined);

  // Session Revocation & Logout (POST /oauth2/revoke): revokes device_secret jti and invalidates sid
  const revokeRes = engine.handleRevokeOrLogout({
    device_secret: ipcOk.device_secret,
    id_token: ipcOk.id_token,
    client_id: 'mosip-super-wallet-android',
  });
  assert.equal(revokeRes.status, 200);
  assert.equal(revokeRes.body.revoked, true);
  assert.ok(revokeRes.body.revoked_jti);
  assert.ok(revokeRes.body.invalidated_sid);

  // Subsequent token exchange after revocation must fail with invalid_grant
  const txAfterRevoke = engine.handleTokenEndpoint({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    client_id: 'mosip-mparivahan-transit',
    subject_token: ipcOk.id_token,
    subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
    actor_token: ipcOk.device_secret,
    actor_token_type: 'urn:openid:params:token-type:device-secret',
    scope: 'openid profile',
    dpop_proof: ipcOk.dpop_proof!,
  });
  assert.equal(txAfterRevoke.status, 400);
  assert.equal(txAfterRevoke.body.error, 'invalid_grant');
});

