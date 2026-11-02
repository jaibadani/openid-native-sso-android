# MOSIP Decode 03 — OpenID Connect Native SSO 1.0 for Android

Implementation of **OpenID Connect Native SSO 1.0** on top of **MOSIP eSignet Go & Thunder ID Engine** for mobile apps.

This project delivers two native Android applications:
1. **Super App** (`com.decode03.superapp` / Client: `mosip-super-wallet-android`): Performs the primary FAPI 2.0 PAR + DPoP citizen authentication, generates a hardware-backed non-exportable EC P-256 key pair (**Key A**), securely stores `id_token` and `device_secret`, and exposes an IPC signing service protected by Android release signature verification.
2. **Child App** (`com.decode03.childapp` / Client: `mosip-mparivahan-transit`): Binds to Super App via IPC, verifies X.509 certificate equivalence, retrieves credentials, performs silent **RFC 8693 Token Exchange** (strictly excluding `device_sso`), and fetches citizen profile claims from `/oauth2/userinfo` with Key A DPoP proofs without prompting the citizen for credentials.

---

## Architecture & Security Highlights

* **Hardware Key A in AndroidKeyStore:** Generated under alias `esignet_hardware_key_A` using `setIsStrongBoxBacked(true)` with automatic fallback to standard TEE. The private key never leaves the hardware security module.
* **RFC 9449 DPoP Everywhere:** Every sensitive token endpoint and resource endpoint call is protected by a DPoP proof signed with Key A.
* **Dual-Layer IPC Protection:**
  1. `android:protectionLevel="signature"` custom permission (`com.decode03.sso.permission.ACCESS_NATIVE_SSO`).
  2. Runtime verification: `packageManager.checkSignatures(myUid, callerUid) == PackageManager.SIGNATURE_MATCH`.
* **RFC 8693 Silent Token Exchange:** Child App redeems Super App's `id_token` and `device_secret` (`actor_token`) for a scoped child access token. Child App is strictly forbidden from requesting `device_sso`.
* **Runtime OIDC Discovery:** Resolves endpoints dynamically at runtime from `/.well-known/openid-configuration`.

---

## Project Structure

```text
mosip2/
├── .gitignore                                  # Ignores keystore.properties, *.p12, *.jks, build/
├── build.gradle.kts                            # Root build file
├── settings.gradle.kts                         # Multi-module settings (:sso-common, :superapp, :childapp)
├── gradle.properties                           # JVM args and AndroidX configuration
├── keystore.properties.example                 # Signing configuration template
├── README.md                                   # This documentation file
│
├── sso-common/                                 # Shared Library Module
│   ├── build.gradle.kts
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── aidl/com/decode03/sso/
│       │   └── ISSOSigningService.aidl         # AIDL interface (requestSsoHandoff & signDpopProof)
│       └── java/com/decode03/sso/
│           ├── Constants.kt                    # Action strings, permissions, grant types, error codes
│           ├── SsoConfig.kt                    # Centralized client_id, issuer URL, and scope settings
│           └── OidcDiscovery.kt                # Runtime OIDC discovery parser & endpoint cache
│
├── superapp/                                   # Super App (Host / Identity Provider)
│   ├── build.gradle.kts                        # Reads keystore.properties (fails release if missing)
│   └── src/main/
│       ├── AndroidManifest.xml                 # Declares signature permission & NativeSsoService
│       ├── java/com/decode03/superapp/
│       │   ├── MainActivity.kt                 # "Sign in with eSignet" button, session dashboard, logs
│       │   ├── auth/
│       │   │   ├── ParAuthManager.kt           # PAR request + Custom Tab + authorization_code exchange
│       │   │   ├── PkceUtil.kt                 # RFC 7636 PKCE S256 generator
│       │   │   └── SessionStorage.kt           # MasterKey EncryptedSharedPreferences storage
│       │   ├── callback/
│       │   │   └── AuthRedirectActivity.kt     # Custom Tab deep link redirect callback handler
│       │   ├── crypto/
│       │   │   ├── HardwareKeyManager.kt       # StrongBox/TEE EC P-256 key manager & JWK thumbprint
│       │   │   └── DpopProofGenerator.kt       # RFC 9449 DPoP proof builder (ES256)
│       │   └── service/
│       │       └── NativeSsoService.kt         # Signature-enforced bound IPC service
│       └── res/
│           ├── layout/activity_main.xml
│           ├── values/strings.xml
│           └── values/themes.xml
│
└── childapp/                                   # Child App (Consumer / Silent SSO)
    ├── build.gradle.kts                        # Same release signing configuration
    └── src/main/
        ├── AndroidManifest.xml                 # Requests signature permission & queries Super App
        ├── java/com/decode03/childapp/
        │   ├── MainActivity.kt                 # "Silent SSO Login" button & citizen claims display
        │   ├── auth/
        │   │   └── TokenExchangeManager.kt     # Coordinates RFC 8693 exchange & UserInfo call
        │   ├── ipc/
        │   │   └── SuperAppServiceConnector.kt # Binds to Super App & verifies certificate equality
        │   └── model/
        │       └── CitizenClaims.kt            # Parsed userinfo claims model
        └── res/
            ├── layout/activity_main.xml
            ├── values/strings.xml
            └── values/themes.xml
```

---

## Prerequisites

1. **Java Development Kit (JDK) 17**:
   * Configured in all modules (`JavaVersion.VERSION_17`).
   * Verify with `java -version`.
2. **Android SDK (API Level 34)**:
   * Platforms: `platforms;android-34`
   * Build-Tools: `build-tools;34.0.0`
   * Set `ANDROID_HOME` or create `local.properties` with `sdk.dir=/path/to/android/sdk`.

---

## Keystore Setup (Signing Configuration)

Both apps **MUST** be signed with the same release certificate for Android's `signature` permission and `checkSignatures()` to allow IPC communication.

### Step 1: Generate PKCS12 Keystore
Run `keytool` from a terminal (placing the keystore at `../keystore/sso-team.p12` relative to project root):
```bash
mkdir -p ../keystore
keytool -genkeypair -v -keystore ../keystore/sso-team.p12 -storetype PKCS12 \
  -alias sso-team-key -alg EC -keysize 256 -validity 10000 \
  -dname "CN=MOSIP Native SSO Team, OU=Engineering, O=MOSIP, L=Bengaluru, ST=KA, C=IN"
```

### Step 2: Create `keystore.properties`
Copy `keystore.properties.example` to `keystore.properties` in the project root:
```properties
storeFile=../keystore/sso-team.p12
storePassword=YourStorePassword
keyAlias=sso-team-key
keyPassword=YourStorePassword
```
*(Note: `keystore.properties`, `*.p12`, and `*.jks` are ignored by `.gitignore`.)*

If `keystore.properties` is missing, running `assembleRelease` will immediately halt with a clear error message.

---

## Building Release APKs

Build both applications from the project root:
```bash
# Build Super App Release APK
./gradlew :superapp:assembleRelease

# Build Child App Release APK
./gradlew :childapp:assembleRelease
```

### Output APK Locations:
* Super App: `superapp/build/outputs/apk/release/superapp-release.apk`
* Child App: `childapp/build/outputs/apk/release/childapp-release.apk`

---

## Verifying Release Certificate Match

Before installing on devices, verify that both release APKs share the exact same certificate SHA-256:

```bash
apksigner verify --print-certs superapp/build/outputs/apk/release/superapp-release.apk
apksigner verify --print-certs childapp/build/outputs/apk/release/childapp-release.apk
```

**Expected Result:** The `Signer #1 certificate SHA-256 digest` output printed by both commands must match character-for-character.

---

## Two-Device / Emulator Test Checklist

### Happy Path (End-to-End Silent SSO)
1. **Install Both APKs on Device:**
   ```bash
   adb install superapp/build/outputs/apk/release/superapp-release.apk
   adb install childapp/build/outputs/apk/release/childapp-release.apk
   ```
2. **Open Super App (`com.decode03.superapp`):**
   * Confirm Hardware Key A initialized (displays alias and `dpop_jkt`).
   * Tap **"Sign in with eSignet"**.
   * App calls PAR (`POST /oauth2/par`) with `scope="openid profile email device_sso"`.
   * Chrome Custom Tab opens with `request_uri`. Complete OTP login and consent.
   * Redirect `io.mosip.inji.superwallet://oauth2redirect` is captured.
   * Tokens exchanged; `Session Active (device_secret issued)` displays on dashboard.
3. **Open Child App (`com.decode03.childapp`):**
   * Tap **"Silent SSO Login"**.
   * App connects to Super App via IPC and verifies certificate signature match.
   * Child App obtains `id_token`, `device_secret`, and fresh DPoP proof.
   * Child App performs Token Exchange (`POST /oauth2/token`) requesting `scope="openid profile"` (no `device_sso`).
   * Child App requests DPoP proof for `/oauth2/userinfo` with `ath`.
   * **Verification:** Citizen claims (Name, Sub ID, Email, etc.) render immediately on screen with zero login prompts or re-authentication.

### Negative Security Test Scenarios
* **Test Case 1 — Signature Mismatch:**
  * Build a rogue app signed with a different debug or test keystore.
  * Attempt to bind to Super App's `com.decode03.sso.action.BIND_SSO_SIGNING_SERVICE`.
  * **Expected:** Connection is rejected with `SecurityException` (`SIGNATURE_MISMATCH`).
* **Test Case 2 — Child App Requests `device_sso` (Task 10b):**
  * Change `SsoConfig.childAppScopes` to include `device_sso`.
  * Attempt Token Exchange.
  * **Expected:** Client-side safety guard triggers immediately. If sent to backend, backend rejects with HTTP 400 (`invalid_scope`).
* **Test Case 3 — No Active Session:**
  * In Super App, tap **"Log Out & Clear Session"**.
  * Open Child App and tap **"Silent SSO Login"**.
  * **Expected:** Handoff returns `NO_ACTIVE_SESSION`. Child App displays friendly guidance asking user to sign into Super App first.
* **Test Case 4 — Expired Device Secret:**
  * Wait for `device_secret` TTL to expire (or revoke session on server).
  * Child App attempts Token Exchange.
  * **Expected:** Backend returns `invalid_grant` ("Expired or invalid device_secret"). Child App informs citizen that session has timed out.

---

## Local Mock Server & Backend Integration

The repository includes a complete eSignet Go & Thunder ID Native SSO reference server in `esignet-go-native-sso-studio-oct-31-2026-12-04-15-am/` with full FAPI 2.0, PAR, PKCE, DPoP, Token Exchange, and interactive Citizen Login/Consent screens.

### 1. Start the Server Locally
```bash
cd esignet-go-native-sso-studio-oct-31-2026-12-04-15-am
npm install --legacy-peer-deps
PORT=3000 npx tsx server.ts
```

### 2. Run Automated Postman CI Tests (100% Pass)
```bash
npx tsx scripts/run-postman-ci.ts
```
**Test Coverage (7/7 Automated Assertions):**
* ✓ `[1/7]` GET `/.well-known/openid-configuration` (`native_sso_supported == true`)
* ✓ `[2/7]` POST `/oauth2/par` (201 Created with `request_uri`)
* ✓ `[3/7]` Authorize + OTP + Consent (Issued authorization code)
* ✓ `[4/7]` POST `/oauth2/token` (`authorization_code` -> Issues `device_secret` & verifies `ds_hash`)
* ✓ `[5/7]` POST `/oauth2/token` (`token-exchange` -> 200 OK Silent SSO bound to Key A)
* ✓ `[6/7]` Negative Security Checks (Task 10b `device_sso` scope rejection & Task 9.a.iii.4 Rogue Key X rejection)
* ✓ `[7/7]` POST `/oauth2/revoke` (Blacklists JTI & rejects subsequent exchange with `invalid_grant`)

### 3. Dynamic Server Switching (No APK Rebuild Required)
Both Super App and Child App include an on-screen **eSignet Server Endpoint** configuration card with preset chips:
* **⚡ Public Tunnel:** Live cloud tunnel for real Android devices anywhere on 5G/Wi-Fi.
* **📶 Wi-Fi LAN (`http://172.16.138.34:3000/api`):** Local zero-latency Wi-Fi communication.
* **💻 Local Laptop (`http://127.0.0.1:3000/api`):** Via `adb reverse tcp:3000 tcp:3000`.
* **📱 Android Emulator (`http://10.0.2.2:3000/api`):** Standard Android emulator host gateway.
* **🌐 MOSIP Collab Sandbox (`https://esignet.collab.mosip.net`):** Upstream production testbed.

Tap any chip or enter a custom URL, then tap **"Apply & Refresh Discovery"** to immediately purge the discovery cache and switch servers at runtime.

---

## Problem Statement 03 — Compliance Matrix

| Mandatory Task | Requirement | Implementation Status | Location |
|:---:|---|:---:|---|
| **Task 1** | Support `device_sso` scope in PAR & Authorize | ✅ Implemented | `ParAuthManager.kt`, `nativeSsoEngine.ts:handleParEndpoint` |
| **Task 2** | Android Hardware Key A generation (StrongBox/TEE) | ✅ Implemented | `HardwareKeyManager.kt` (`esignet_hardware_key_A`) |
| **Task 3** | RFC 9449 DPoP proof generation & verification | ✅ Implemented | `DpopProofGenerator.kt`, `nativeSsoEngine.ts:validateDpopProof` |
| **Task 4** | Issue `device_secret` JWE & embed `ds_hash` in `id_token` | ✅ Implemented | `nativeSsoEngine.ts:issueDeviceSecret`, SHA-256 base64url hash |
| **Task 5** | Signature-protected IPC bound service | ✅ Implemented | `NativeSsoService.kt` (dual-layer signature check) |
| **Task 6** | RFC 8693 Token Exchange (`grant_type=token-exchange`) | ✅ Implemented | `TokenExchangeManager.kt`, `nativeSsoEngine.ts:handleTokenExchange` |
| **Task 7** | Fetch `/oauth2/userinfo` with DPoP proof + `ath` | ✅ Implemented | `TokenExchangeManager.kt:step 5`, `nativeSsoEngine.ts:handleUserInfo` |
| **Task 8** | Negative Security: Reject `device_sso` in Child App | ✅ Implemented | Client guard in `TokenExchangeManager.kt` + Server 400 rejection |
| **Task 9** | Negative Security: Reject rogue Key X thumbprints | ✅ Implemented | Server validates `dpop_jkt` match against session binding |
| **Task 10** | Session Revocation & Logout blacklisting | ✅ Implemented | `nativeSsoEngine.ts:handleRevokeOrLogout` (`jti` blacklist) |

---

## Assumptions & Verified Items

1. **Hardware Key StrongBox Availability:** Tested key generation with automatic fallback to standard TEE if StrongBox hardware is not present on the test device/emulator.
2. **DPoP Algorithm (ES256):** Standard ECDSA P-256 signatures in Java DER format are automatically converted to 64-byte raw IEEE P1363 (`r || s`) format for strict RFC 7515 / RFC 9449 compliance.
3. **PAR Client Authentication:** Configured by default for public clients (PKCE S256 + DPoP `dpop_jkt`), with optional support for `client_assertion` (`private_key_jwt`) via `SsoConfig.clientAssertionJwt`.
4. **Token Exchange Audience:** Defaults to the runtime discovered `issuer` (`"https://esignet.mosip.net"`), customizable via `SsoConfig.tokenExchangeAudience`.
