# MOSIP eSignet Native SSO — Test Data & Test Cases

This document provides the complete reference of **Test Data**, **Cryptographic Assets**, and **Test Cases** (Automated CI, Android Client, and Negative Security tests) for the **MOSIP Decode 03 OpenID Connect Native SSO 1.0** implementation.

---

## 📋 Part 1: Test Data Reference

### 1. Citizen Identity Directory (MOSIP IDA Mock)

| Field | Citizen 1 (Primary / Default) | Citizen 2 (Alternative) |
|---|---|---|
| **Full Name** | Ananya Deshmukh | Rohan Vikram |
| **MOSIP UIN** | `8294017365` | `4510928374` |
| **Valid OTP** | `111111` | `111111` |
| **Invalid OTP (Negative)** | `000000` or `999999` | `000000` or `999999` |
| **Email** | `ananya.deshmukh@citizen.mosip.net` | `rohan.vikram@transit.mosip.net` |
| **Phone Number** | `+91-98204-71932` | `+91-97412-88019` |
| **Date of Birth** | `1994-08-15` | `1989-11-23` |
| **Gender** | `Female` | `Male` |
| **Address** | 1204, Sector 4, Indiranagar, Bengaluru, Karnataka, 560038 | 402, Green Glen Layout, Bellandur, Bengaluru, Karnataka, 560103 |

---

### 2. Client Application Profiles & Scopes

| Parameter | Super App (Host / Inji) | Child App (Consumer / Transit) |
|---|---|---|
| **Package Name** | `com.decode03.superapp` | `com.decode03.childapp` |
| **Client ID** | `mosip-super-wallet-android` | `mosip-mparivahan-transit` |
| **Redirect URI** | `io.mosip.inji.superwallet://oauth2redirect` | N/A (Uses Signature-Bound IPC) |
| **Allowed Scopes** | `openid profile email device_sso` | `openid profile` |
| **Forbidden Scope** | N/A | **`device_sso`** *(Mandatory Task 10b)* |
| **Grant Type** | `authorization_code` (with PKCE S256) | `urn:ietf:params:oauth:grant-type:token-exchange` |
| **Client Type** | Public Client (Hardware Key A bound) | Public Client (Delegated Key A bound) |

---

### 3. Cryptographic Assets & Key Material

| Key / Token | Algorithm | Storage / Transport | Purpose |
|---|---|---|---|
| **Hardware Key A** | EC P-256 (`secp256r1`) | AndroidKeyStore (StrongBox/TEE) | Non-exportable hardware key for DPoP proofs |
| **DPoP Thumbprint (`dpop_jkt`)** | SHA-256 Base64URL | RFC 7638 JWK Thumbprint | Bound to session & `device_secret` |
| **PKCE `code_verifier`** | High-entropy random | In-memory during login | RFC 7636 authorization code protection |
| **`device_secret`** | A256GCM (JWE) | EncryptedSharedPreferences | Device credential holding session claims |
| **`ds_hash`** | SHA-256 Base64URL | Embedded inside `id_token` | Binds `id_token` to `device_secret` |
| **Rogue Key X (Test)** | EC P-256 | Ephemeral (Attacker Simulation) | Negative test for unauthorized key replay |

---

### 4. Server Endpoints & Presets

| Environment | Base Issuer URL | Description |
|---|---|---|
| **Live Cloud Tunnel (HTTPS)** | `https://dozen-billion-low-shepherd.trycloudflare.com/api` | Public endpoint for physical devices on 5G/Wi-Fi |
| **Local Wi-Fi LAN** | `http://172.16.138.34:3000/api` | Direct local network connection |
| **Local Laptop (ADB Reverse)** | `http://127.0.0.1:3000/api` | Via `adb reverse tcp:3000 tcp:3000` |
| **Android Emulator** | `http://10.0.2.2:3000/api` | Standard Android emulator host bridge |
| **MOSIP Collab Sandbox** | `https://esignet.collab.mosip.net` | Upstream production sandbox |

---

# 🧪 Part 2: Comprehensive Test Case List

## Category A: Automated CI / Backend Engine Tests (`scripts/run-postman-ci.ts`)

| Test ID | Test Case Name | Step & Request | Expected Result | Specification | Status |
|:---:|---|---|---|---|:---:|
| **TC-CI01** | OIDC Discovery & Native SSO Metadata | `GET /.well-known/openid-configuration` | Returns HTTP 200, contains `native_sso_supported: true` and all endpoints | OpenID Connect Discovery 1.0 | ✅ PASS |
| **TC-CI02** | PAR Request with `device_sso` & DPoP | `POST /oauth2/par` with `dpop_jkt` & `code_challenge` | Returns HTTP 201 with valid `request_uri` and `expires_in: 60` | RFC 9126 PAR + RFC 9449 DPoP | ✅ PASS |
| **TC-CI03** | Citizen Authentication & Consent | `POST /oauth2/authenticate` (UIN + OTP) ➔ `POST /oauth2/consent` | Validates OTP `111111`, records user consent, issues authorization `code` | FAPI 2.0 User Journey | ✅ PASS |
| **TC-CI04** | Token Exchange for `device_secret` | `POST /oauth2/token` (`grant_type=authorization_code`) | Issues `access_token`, `device_secret`, and `id_token` with matching `ds_hash` | OpenID Connect Native SSO 1.0 | ✅ PASS |
| **TC-CI05** | Silent RFC 8693 Token Exchange | `POST /oauth2/token` (`grant_type=token-exchange`) | Validates `device_secret` + Key A DPoP, issues scoped child access token | RFC 8693 Token Exchange | ✅ PASS |
| **TC-CI06A** | Security: Child Requests `device_sso` | `POST /oauth2/token` (token-exchange with `scope=device_sso`) | Returns HTTP 400 `invalid_scope` *(Task 10b)* | Problem Statement 03 Task 10b | ✅ PASS |
| **TC-CI06B** | Security: Rogue Key X Replay | `POST /oauth2/token` (token-exchange signed with Key X) | Returns HTTP 400 `invalid_dpop_proof` *(Task 9.a.iii.4)* | RFC 9449 Security | ✅ PASS |
| **TC-CI07** | Session Revocation & JTI Blacklisting | `POST /oauth2/revoke` ➔ re-attempt token-exchange | Blacklists JTI, subsequent exchange fails with `invalid_grant` | OpenID Connect RP-Initiated Logout | ✅ PASS |

---

## Category B: Android Super App (Inji Host) Test Cases

| Test ID | Test Case Name | Preconditions & Steps | Expected Result | Status |
|:---:|---|---|---|:---:|
| **TC-SA01** | Hardware Key A Generation | Launch Super App | StrongBox/TEE EC P-256 key generated in `AndroidKeyStore`. Alias and `dpop_jkt` thumbprint render in UI | ✅ PASS |
| **TC-SA02** | Dynamic Server Switching | Select preset chip (e.g. Cloud Tunnel or Wi-Fi) ➔ Tap "Apply" | Discovery cache purges, endpoints re-resolve from new server | ✅ PASS |
| **TC-SA03** | PAR Flow Initiation | Tap "Sign in with eSignet" | Generates PKCE verifier, creates DPoP proof for PAR, receives `request_uri` | ✅ PASS |
| **TC-SA04** | Chrome Custom Tab Login | Chrome Custom Tab opens | MOSIP Identity UI loads. Enter UIN `8294017365`, OTP `111111`, approve consent | ✅ PASS |
| **TC-SA05** | Deep Link Redirect Capture | Consent approved | Deep link `io.mosip.inji.superwallet://oauth2redirect?code=...&state=...` intercepted by `AuthRedirectActivity` | ✅ PASS |
| **TC-SA06** | State Parameter CSRF Verification | Callback received | `state` in callback matches `ParAuthManager.pendingState` | ✅ PASS |
| **TC-SA07** | Secure Credential Storage | Exchange code for tokens | `device_secret`, `id_token`, and session ID saved into `EncryptedSharedPreferences` | ✅ PASS |
| **TC-SA08** | Session Purge / Logout | Tap "Log Out & Clear Session" | All credentials deleted from secure storage, UI resets to "Ready to Sign In" | ✅ PASS |

---

## Category C: Android Child App (mParivahan Consumer) Test Cases

| Test ID | Test Case Name | Preconditions & Steps | Expected Result | Status |
|:---:|---|---|---|:---:|
| **TC-CA01** | Dual-Layer Signature IPC Binding | Super App signed with release key. Child App taps "Silent SSO Login" | Binds to `com.decode03.sso.action.BIND_SSO_SIGNING_SERVICE`. `checkSignatures` returns `SIGNATURE_MATCH` | ✅ PASS |
| **TC-CA02** | Handoff Token Retrieval | IPC connection active | Receives `id_token`, `device_secret`, and fresh DPoP proof from Super App | ✅ PASS |
| **TC-CA03** | RFC 8693 Token Exchange | Child App POSTs to `/oauth2/token` | Exchanges tokens with `subject_token` and `actor_token` without prompting the user. Child access token issued | ✅ PASS |
| **TC-CA04** | UserInfo with `ath` DPoP Proof | Request Super App to sign DPoP proof with `ath` hash of access token | GET `/oauth2/userinfo` returns HTTP 200 with citizen claims | ✅ PASS |
| **TC-CA05** | Seamless Citizen Claims Display | UserInfo response parsed | Citizen Name, UIN, Email, Phone, Birthdate, Gender display in green badge with zero UI friction | ✅ PASS |
| **TC-CA06** | Main Thread Audit Logging | Steps streamed during silent SSO | All step logs update safely via `runOnUiThread` without `CalledFromWrongThreadException` | ✅ PASS |

---

## Category D: Negative & Security Edge Case Tests

| Test ID | Test Case Name | Action / Condition | Expected Behavior |
|:---:|---|---|---|
| **TC-SEC01** | **Untrusted Calling App (Rogue APK)** | App signed with a different developer key attempts to bind to `NativeSsoService` | Bound service throws `SecurityException: Calling UID does NOT share the release signing certificate` |
| **TC-SEC02** | **Child Requests `device_sso`** | Modify Child App scope to include `device_sso` | Client-side guard throws `SecurityException`. Backend also rejects with HTTP 400 `invalid_scope` |
| **TC-SEC03** | **No Active Super App Session** | Super App logged out; tap "Silent SSO Login" in Child App | IPC returns `ERR_NO_ACTIVE_SESSION`. Child App displays: *"Please sign in with eSignet on Super App first"* |
| **TC-SEC04** | **Expired / Revoked Device Secret** | Session revoked on backend or TTL expired; tap Silent SSO | Server returns HTTP 400 `invalid_grant`. Child App alerts citizen that session has timed out |
| **TC-SEC05** | **Offline / Bad Hostname Resilience** | Host unreachable or typo in server endpoint | App logs clear network error (`Unable to resolve host` or timeout) without crashing |

---

## 🚀 Running the Automated Tests

To execute the complete 7/7 automated assertion suite locally or against the live Cloudflare tunnel:

```bash
cd esignet-go-native-sso-studio-oct-31-2026-12-04-15-am

# Run against local server
PORT=3000 npx tsx scripts/run-postman-ci.ts

# Run against live cloud tunnel
BASE_URL=https://dozen-billion-low-shepherd.trycloudflare.com/api npx tsx scripts/run-postman-ci.ts
```
