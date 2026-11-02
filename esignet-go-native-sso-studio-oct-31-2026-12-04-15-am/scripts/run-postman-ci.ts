import assert from 'node:assert/strict';
import {
  SUPER_APP_KEY_A,
  ROGUE_DEVICE_KEY_X,
  computeJwkThumbprint,
  computePkceChallenge,
  computeDsHash,
  createDpopProof,
  verifyAndDecodeJwt,
  type IdTokenPayload,
} from '../src/lib/nativeSsoEngine.ts';

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000/api';

async function runPostmanCollectionAssertions() {
  console.log(`[Newman/Postman CI] Running Native SSO 1.0 Collection against ${BASE_URL}...`);

  const dpopJkt = computeJwkThumbprint(SUPER_APP_KEY_A);
  const codeVerifier = 'postman-ci-pkce-verifier-fapi2-9876543210';
  const codeChallenge = computePkceChallenge(codeVerifier);

  // 1. OIDC Discovery
  const discRes = await fetch(`${BASE_URL}/.well-known/openid-configuration`);
  assert.equal(discRes.status, 200, 'Discovery endpoint must return 200');
  const discBody = (await discRes.json()) as Record<string, unknown>;
  assert.equal(discBody.native_sso_supported, true);
  console.log('✓ [1/7] GET /.well-known/openid-configuration (native_sso_supported == true)');

  // 2. Super App PAR (POST /oauth2/par)
  const parRes = await fetch(`${BASE_URL}/oauth2/par`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: 'mosip-super-wallet-android',
      scope: 'openid profile email device_sso',
      redirect_uri: 'io.mosip.inji.superwallet://oauth2redirect',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      dpop_jkt: dpopJkt,
    }),
  });
  assert.equal(parRes.status, 201, 'PAR request must return 201 Created');
  const parBody = (await parRes.json()) as { request_uri: string };
  assert.ok(parBody.request_uri.startsWith('urn:ietf:params:oauth:request_uri:'));
  console.log(`✓ [2/7] POST /oauth2/par -> 201 Created (${parBody.request_uri})`);

  // 3. Authorize + OTP + Consent
  const authRes = await fetch(
    `${BASE_URL}/oauth2/authorize?client_id=mosip-super-wallet-android&request_uri=${encodeURIComponent(
      parBody.request_uri
    )}`
  );
  assert.equal(authRes.status, 200);
  const authBody = (await authRes.json()) as { auth_id: string };

  const otpRes = await fetch(`${BASE_URL}/oauth2/authenticate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ auth_id: authBody.auth_id, uin: '8294017365', otp: '111111' }),
  });
  assert.equal(otpRes.status, 200);

  const consentRes = await fetch(`${BASE_URL}/oauth2/consent`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      auth_id: authBody.auth_id,
      accepted_scopes: ['openid', 'profile', 'email', 'device_sso'],
      accepted_claims: ['name', 'email', 'phone_number', 'birthdate'],
    }),
  });
  assert.equal(consentRes.status, 200);
  const consentBody = (await consentRes.json()) as { code: string };
  console.log(`✓ [3/7] Authorize + OTP + Consent -> Issued code (${consentBody.code})`);

  // 4. Super App Token Exchange (grant_type=authorization_code)
  const superDpop = createDpopProof({
    jwk: SUPER_APP_KEY_A,
    htm: 'POST',
    htu: 'https://esignet.mosip.net/oauth2/token',
  });
  const superTokenRes = await fetch(`${BASE_URL}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', DPoP: superDpop },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      client_id: 'mosip-super-wallet-android',
      code: consentBody.code,
      redirect_uri: 'io.mosip.inji.superwallet://oauth2redirect',
      code_verifier: codeVerifier,
    }),
  });
  assert.equal(superTokenRes.status, 200);
  const superTokens = (await superTokenRes.json()) as {
    access_token: string;
    id_token: string;
    device_secret: string;
  };
  assert.ok(superTokens.device_secret);
  const decodedId = verifyAndDecodeJwt<IdTokenPayload>(superTokens.id_token);
  assert.equal(decodedId.payload.ds_hash, computeDsHash(superTokens.device_secret));
  console.log(
    `✓ [4/7] POST /oauth2/token (authorization_code) -> Issued device_secret & verified ds_hash (${decodedId.payload.ds_hash})`
  );

  // 5. Child App Silent SSO Token Exchange (grant_type=token-exchange)
  const childDpop = createDpopProof({
    jwk: SUPER_APP_KEY_A,
    htm: 'POST',
    htu: 'https://esignet.mosip.net/oauth2/token',
  });
  const childTxRes = await fetch(`${BASE_URL}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', DPoP: childDpop },
    body: JSON.stringify({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: 'mosip-mparivahan-transit',
      subject_token: superTokens.id_token,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      actor_token: superTokens.device_secret,
      actor_token_type: 'urn:openid:params:token-type:device-secret',
      audience: 'https://esignet.mosip.net',
      scope: 'openid profile',
    }),
  });
  assert.equal(childTxRes.status, 200);
  const childTokens = (await childTxRes.json()) as { access_token: string; token_type: string };
  assert.equal(childTokens.token_type, 'DPoP');
  console.log('✓ [5/7] POST /oauth2/token (token-exchange) -> 200 OK Silent SSO bound to Key A');

  // 6. Negative Tests: device_sso in token_exchange & Rogue Key X
  const negScopeRes = await fetch(`${BASE_URL}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', DPoP: childDpop },
    body: JSON.stringify({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: 'mosip-mparivahan-transit',
      subject_token: superTokens.id_token,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      actor_token: superTokens.device_secret,
      actor_token_type: 'urn:openid:params:token-type:device-secret',
      scope: 'openid profile device_sso',
    }),
  });
  assert.equal(negScopeRes.status, 400);

  const rogueDpop = createDpopProof({
    jwk: ROGUE_DEVICE_KEY_X,
    htm: 'POST',
    htu: 'https://esignet.mosip.net/oauth2/token',
  });
  const negKeyRes = await fetch(`${BASE_URL}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', DPoP: rogueDpop },
    body: JSON.stringify({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: 'mosip-mparivahan-transit',
      subject_token: superTokens.id_token,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      actor_token: superTokens.device_secret,
      actor_token_type: 'urn:openid:params:token-type:device-secret',
      scope: 'openid profile',
    }),
  });
  assert.equal(negKeyRes.status, 400);
  console.log('✓ [6/7] Negative Security Checks (Task 10b device_sso & Task 9.a.iii.4 Rogue Key X rejected)');

  // 7. Session Revocation & Logout (POST /oauth2/revoke) -> Subsequent Token Exchange Fails
  const revokeRes = await fetch(`${BASE_URL}/oauth2/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      device_secret: superTokens.device_secret,
      client_id: 'mosip-super-wallet-android',
    }),
  });
  assert.equal(revokeRes.status, 200);
  const revokeBody = (await revokeRes.json()) as { revoked: boolean; revoked_jti: string };
  assert.equal(revokeBody.revoked, true);

  const postRevokeTxRes = await fetch(`${BASE_URL}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', DPoP: childDpop },
    body: JSON.stringify({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: 'mosip-mparivahan-transit',
      subject_token: superTokens.id_token,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      actor_token: superTokens.device_secret,
      actor_token_type: 'urn:openid:params:token-type:device-secret',
      scope: 'openid profile',
    }),
  });
  assert.equal(postRevokeTxRes.status, 400);
  const postRevokeBody = (await postRevokeTxRes.json()) as { error: string };
  assert.equal(postRevokeBody.error, 'invalid_grant');
  console.log(
    `✓ [7/7] POST /oauth2/revoke -> Blacklisted JTI (${revokeBody.revoked_jti}) & rejected post-logout exchange with invalid_grant`
  );

  console.log('\n[Newman/Postman CI] 100% of Native SSO 1.0 Assertions Passed!');
}

runPostmanCollectionAssertions().catch((err) => {
  console.error('[Newman/Postman CI] Assertion failure:', err);
  process.exit(1);
});
