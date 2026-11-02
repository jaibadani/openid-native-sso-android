export interface SourceCodeArtifact {
  id: string;
  repo:
    | 'mosip/esignet (develop-go)'
    | 'thunder-id/thunderid'
    | 'android-native-sso-suite'
    | 'ios-native-sso-suite'
    | 'ci-automation';
  filePath: string;
  language: 'go' | 'kotlin' | 'swift' | 'yaml' | 'xml' | 'json';
  taskLabels: string[];
  summary: string;
  code: string;
}

export const SOURCE_CODE_ARTIFACTS: SourceCodeArtifact[] = [
  {
    id: 'thunder-device-secret-provider',
    repo: 'thunder-id/thunderid',
    filePath: 'pkg/oauth2/devicesecret/provider.go',
    language: 'go',
    taskLabels: ['Task 3: Device Secret Provider Interface [Thunder ID]'],
    summary:
      'Defines the DeviceSecretProvider interface exposed by Thunder ID Engine so eSignet Go can plug in cryptographic JWS+JWE device_secret issuance and validation.',
    code: `package devicesecret

import (
	"context"
)

// GenerateRequest contains the authenticated session and hardware DPoP binding
// parameters required to issue a Native SSO device_secret.
type GenerateRequest struct {
	Sub       string   \`json:"sub"\`
	AuthID    string   \`json:"auth_id"\`
	ClientID  string   \`json:"client_id"\`
	Scope     string   \`json:"scope"\`
	ACR       string   \`json:"acr"\`
	Claims    []string \`json:"claims"\`
	DPoPJKT   string   \`json:"dpop_jkt"\`
}

// GenerateResponse returns the signed-then-encrypted device_secret and its ds_hash
// per OpenID Connect Native SSO 1.0 Section 3.2.
type GenerateResponse struct {
	DeviceSecret string \`json:"device_secret"\`
	DSHash       string \`json:"ds_hash"\`
	JTI          string \`json:"jti"\`
	ExpiresAt    int64  \`json:"exp"\`
}

// ValidatedSecretClaims represents the verified claims extracted from a device_secret
// during OAuth 2.0 Token Exchange (RFC 8693).
type ValidatedSecretClaims struct {
	Issuer      string   \`json:"iss"\`
	Subject     string   \`json:"sub"\`
	AuthID      string   \`json:"auth_id"\`
	OrgClientID string   \`json:"client_id"\`
	Scope       string   \`json:"scope"\`
	ACR         string   \`json:"acr"\`
	Claims      []string \`json:"claims"\`
	DPoPJKT     string   \`json:"cnf_jkt"\`
	JTI         string   \`json:"jti"\`
	ExpiresAt   int64    \`json:"exp"\`
}

// DeviceSecretProvider is the Thunder ID Engine extension point implemented by eSignet Go.
type DeviceSecretProvider interface {
	// GenerateDeviceSecret issues a signed-then-encrypted JWT (JWS inside JWE)
	// and computes ds_hash = BASE64URL(LEFT_128_BITS(SHA256(device_secret))).
	GenerateDeviceSecret(ctx context.Context, req GenerateRequest) (*GenerateResponse, error)

	// ValidateDeviceSecret decrypts the JWE, verifies the inner JWS signature,
	// checks expiry and revocation, and verifies requestingClientID is permitted
	// by the originating Super App's vendor allowlist.
	ValidateDeviceSecret(ctx context.Context, requestingClientID string, deviceSecret string) (*ValidatedSecretClaims, error)
}
`,
  },
  {
    id: 'esignet-device-secret-impl',
    repo: 'mosip/esignet (develop-go)',
    filePath: 'internal/sso/device_secret_service.go',
    language: 'go',
    taskLabels: [
      'Task 4a: Generate Device Secret [eSignet]',
      'Task 4b: Validate Device Secret [eSignet]',
    ],
    summary:
      'Implements DeviceSecretProvider in eSignet Go using KeyManager for RS256/ES256 JWS signing and A256GCM JWE encryption so device_secret remains opaque to mobile clients.',
    code: `package sso

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mosip/esignet/internal/client"
	"github.com/mosip/esignet/internal/keymanager"
	"github.com/thunder-id/thunderid/pkg/oauth2/devicesecret"
)

type EsignetDeviceSecretService struct {
	issuer        string
	ttl           time.Duration
	keyMgr        keymanager.KeyManager
	clientRepo    client.Repository
	revocationSet RevocationStore
}

type DeviceSecretJWTClaims struct {
	jwt.RegisteredClaims
	AuthID   string   \`json:"auth_id"\`
	ClientID string   \`json:"client_id"\`
	Scope    string   \`json:"scope"\`
	ACR      string   \`json:"acr"\`
	Claims   []string \`json:"claims"\`
	CNF      struct {
		JKT string \`json:"jkt"\`
	} \`json:"cnf"\`
}

func (s *EsignetDeviceSecretService) GenerateDeviceSecret(
	ctx context.Context,
	req devicesecret.GenerateRequest,
) (*devicesecret.GenerateResponse, error) {
	now := time.Now().UTC()
	exp := now.Add(s.ttl)
	jti := fmt.Sprintf("ds-%s-%d", req.AuthID, now.UnixNano())

	claims := DeviceSecretJWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   req.Sub,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        jti,
		},
		AuthID:   req.AuthID,
		ClientID: req.ClientID,
		Scope:    req.Scope,
		ACR:      req.ACR,
		Claims:   req.Claims,
	}
	claims.CNF.JKT = req.DPoPJKT

	// 1. Sign inner JWT (JWS) via eSignet KeyManager
	innerJWS, err := s.keyMgr.SignJWT(ctx, "ESIGNET_SSO_SIGN", claims)
	if err != nil {
		return nil, fmt.Errorf("failed to sign device_secret JWS: %w", err)
	}

	// 2. Encrypt JWS into JWE (A256GCM) so mobile apps treat device_secret as opaque
	deviceSecretJWE, err := s.keyMgr.EncryptJWE(ctx, "ESIGNET_SSO_ENC", []byte(innerJWS))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt device_secret JWE: %w", err)
	}

	// 3. Compute ds_hash = BASE64URL(SHA256(device_secret)[0:16]) per Native SSO 1.0 Section 3.2
	sum := sha256.Sum256([]byte(deviceSecretJWE))
	dsHash := base64.RawURLEncoding.EncodeToString(sum[:16])

	return &devicesecret.GenerateResponse{
		DeviceSecret: deviceSecretJWE,
		DSHash:       dsHash,
		JTI:          jti,
		ExpiresAt:    exp.Unix(),
	}, nil
}

func (s *EsignetDeviceSecretService) ValidateDeviceSecret(
	ctx context.Context,
	requestingClientID string,
	deviceSecretJWE string,
) (*devicesecret.ValidatedSecretClaims, error) {
	// 1. Decrypt outer JWE envelope
	innerJWSBytes, err := s.keyMgr.DecryptJWE(ctx, "ESIGNET_SSO_ENC", deviceSecretJWE)
	if err != nil {
		return nil, errors.New("invalid_grant: failed to decrypt device_secret JWE")
	}

	// 2. Verify inner JWS signature & standard claims (exp, iss)
	var claims DeviceSecretJWTClaims
	if err := s.keyMgr.VerifyJWT(ctx, "ESIGNET_SSO_SIGN", string(innerJWSBytes), &claims); err != nil {
		return nil, fmt.Errorf("invalid_grant: device_secret signature or expiry invalid: %w", err)
	}

	// 3. Check JTI revocation
	if s.revocationSet.IsRevoked(ctx, claims.ID) {
		return nil, errors.New("invalid_grant: device_secret has been revoked")
	}

	// 4. Verify requesting Child App is permitted by Super App's vendor allowlist
	orgClient, err := s.clientRepo.FindByID(ctx, claims.ClientID)
	if err != nil {
		return nil, errors.New("invalid_client: originating Super App client not found")
	}
	if requestingClientID != claims.ClientID && !orgClient.AllowsSSOChildClient(requestingClientID) {
		return nil, errors.New("unauthorized_client: child client not in Super App vendor family allowlist")
	}

	return &devicesecret.ValidatedSecretClaims{
		Issuer:      claims.Issuer,
		Subject:     claims.Subject,
		AuthID:      claims.AuthID,
		OrgClientID: claims.ClientID,
		Scope:       claims.Scope,
		ACR:         claims.ACR,
		Claims:      claims.Claims,
		DPoPJKT:     claims.CNF.JKT,
		JTI:         claims.ID,
		ExpiresAt:   claims.ExpiresAt.Unix(),
	}, nil
}
`,
  },
  {
    id: 'thunder-token-endpoint',
    repo: 'thunder-id/thunderid',
    filePath: 'pkg/oauth2/token/handler.go',
    language: 'go',
    taskLabels: [
      'Task 1 & 2: Validate device_sso Scope',
      'Task 5 & 6: Invoke Provider & Return device_secret',
      'Task 9 & 10: Token Exchange & Scope Subset Enforcement',
    ],
    summary:
      'Handles both authorization_code (issuing device_secret & embedding ds_hash in id_token) and urn:ietf:params:oauth:grant-type:token-exchange (verifying ds_hash, sid, cnf.jkt == DPoP jkt, and scope subset rules).',
    code: `package token

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"slices"
	"strings"

	"github.com/thunder-id/thunderid/pkg/oauth2/devicesecret"
)

const (
	ScopeDeviceSSO       = "device_sso"
	GrantTypeAuthCode    = "authorization_code"
	GrantTypeTokenExch   = "urn:ietf:params:oauth:grant-type:token-exchange"
	ActorTokenTypeSecret = "urn:openid:params:token-type:device-secret"
	SubTokenTypeIDToken  = "urn:ietf:params:oauth:token-type:id_token"
)

func (h *TokenHandler) HandleAuthorizationCode(ctx context.Context, req *TokenRequest, dpopJKT string) (*TokenResponse, error) {
	clientCfg, err := h.clientStore.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	authCodeSession, err := h.codeStore.ConsumeCode(ctx, req.Code, req.CodeVerifier, dpopJKT)
	if err != nil {
		return nil, ErrInvalidGrant
	}

	grantedScopes := strings.Fields(authCodeSession.Scope)
	hasDeviceSSO := slices.Contains(grantedScopes, ScopeDeviceSSO)

	// Mandatory Task 2: Confirm allowed_authorization_scopes includes device_sso
	if hasDeviceSSO && !slices.Contains(clientCfg.AllowedAuthorizationScopes, ScopeDeviceSSO) {
		return nil, NewOAuthError("invalid_scope", "client is not authorized for device_sso scope")
	}

	var deviceSecret string
	var dsHash string

	// Mandatory Task 5: Invoke Device Secret Provider when device_sso is valid
	if hasDeviceSSO {
		dsResp, err := h.deviceSecretProvider.GenerateDeviceSecret(ctx, devicesecret.GenerateRequest{
			Sub:      authCodeSession.Subject,
			AuthID:   authCodeSession.SessionID,
			ClientID: req.ClientID,
			Scope:    authCodeSession.Scope,
			ACR:      authCodeSession.ACR,
			Claims:   authCodeSession.ConsentedClaims,
			DPoPJKT:  dpopJKT,
		})
		if err != nil {
			return nil, err
		}
		deviceSecret = dsResp.DeviceSecret
		dsHash = dsResp.DSHash
	}

	// Mandatory Task 4.a.ix & Task 6: Embed ds_hash into id_token and return device_secret
	idToken, err := h.tokenSigner.IssueIDToken(ctx, IDTokenParams{
		Subject:   authCodeSession.Subject,
		Audience:  req.ClientID,
		SessionID: authCodeSession.SessionID,
		ACR:       authCodeSession.ACR,
		DSHash:    dsHash,
	})
	if err != nil {
		return nil, err
	}

	accessToken, err := h.tokenSigner.IssueDPoPAccessToken(ctx, authCodeSession.Subject, req.ClientID, authCodeSession.Scope, dpopJKT)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "DPoP",
		IDToken:      idToken,
		DeviceSecret: deviceSecret,
		ExpiresIn:    3600,
		Scope:        authCodeSession.Scope,
	}, nil
}

func (h *TokenHandler) HandleTokenExchange(ctx context.Context, req *TokenRequest, dpopJKT string) (*TokenResponse, error) {
	requestedScopes := strings.Fields(req.Scope)

	// Mandatory Task 10b: Reject token_exchange if device_sso scope is included
	if slices.Contains(requestedScopes, ScopeDeviceSSO) {
		return nil, NewOAuthError("invalid_scope", "device_sso scope is not permitted on token_exchange grant")
	}

	// Mandatory Task 9.a.i: Require actor_token_type = urn:openid:params:token-type:device-secret
	if req.ActorTokenType != ActorTokenTypeSecret || req.SubjectTokenType != SubTokenTypeIDToken {
		return nil, NewOAuthError("invalid_request", "unsupported actor_token_type or subject_token_type")
	}

	// Mandatory Task 9.a.iii.3: Confirm allowed_authorization_scopes includes device_sso
	childClient, err := h.clientStore.GetClient(ctx, req.ClientID)
	if err != nil || !slices.Contains(childClient.AllowedAuthorizationScopes, ScopeDeviceSSO) {
		return nil, NewOAuthError("invalid_scope", "requesting client is not enabled for device_sso")
	}

	// Mandatory Task 9.a.ii: Validate actor_token via DeviceSecretProvider
	dsClaims, err := h.deviceSecretProvider.ValidateDeviceSecret(ctx, req.ClientID, req.ActorToken)
	if err != nil {
		return nil, NewOAuthError("invalid_grant", err.Error())
	}

	// Mandatory Task 9.a.iii.4: Confirm cnf.jkt in device_secret matches current DPoP header thumbprint
	if subtle.ConstantTimeCompare([]byte(dsClaims.DPoPJKT), []byte(dpopJKT)) != 1 {
		return nil, NewOAuthError("invalid_dpop_proof", "DPoP proof key thumbprint does not match device_secret cnf.jkt")
	}

	// Mandatory Task 9.a.iii.1 & 2: Validate id_token, ds_hash binding, and sid
	idTokenClaims, err := h.tokenSigner.VerifyIDToken(ctx, req.SubjectToken)
	if err != nil {
		return nil, NewOAuthError("invalid_grant", "invalid subject_token id_token")
	}

	sum := sha256.Sum256([]byte(req.ActorToken))
	recomputedDSHash := base64.RawURLEncoding.EncodeToString(sum[:16])
	if subtle.ConstantTimeCompare([]byte(idTokenClaims.DSHash), []byte(recomputedDSHash)) != 1 {
		return nil, NewOAuthError("invalid_grant", "ds_hash binding mismatch between id_token and device_secret")
	}

	if idTokenClaims.SID != dsClaims.AuthID || !h.sessionStore.IsActive(ctx, idTokenClaims.SID) {
		return nil, NewOAuthError("invalid_grant", "session ID (sid) is invalid or terminated")
	}

	// Mandatory Task 10a: Enforce that requested scope is a subset of Super App's granted scope
	superAppScopes := strings.Fields(dsClaims.Scope)
	for _, sc := range requestedScopes {
		if !slices.Contains(superAppScopes, sc) {
			if h.enableBonusStepUpConsent {
				return nil, NewOAuthError("interaction_required", "requested scope exceeds Super App consent")
			}
			return nil, NewOAuthError("invalid_scope", "requested scope is not a subset of Super App granted scope")
		}
	}

	// Bind new access_token to the SAME hardware key thumbprint (dsClaims.DPoPJKT)
	accessToken, err := h.tokenSigner.IssueDPoPAccessToken(ctx, dsClaims.Subject, req.ClientID, req.Scope, dsClaims.DPoPJKT)
	if err != nil {
		return nil, errors.New("server_error")
	}

	return &TokenResponse{
		AccessToken:     accessToken,
		IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		TokenType:       "DPoP",
		ExpiresIn:       3600,
		Scope:           req.Scope,
	}, nil
}
`,
  },
  {
    id: 'android-super-app-service',
    repo: 'android-native-sso-suite',
    filePath: 'superapp/src/main/java/io/mosip/inji/sso/SSOSigningService.kt',
    language: 'kotlin',
    taskLabels: [
      'Task 7: Expose Bound Service & Sign DPoP with Hardware Key A [Super App]',
    ],
    summary:
      'Android Bound Service in Super App protected by signature-level permission and PackageManager.CheckSignatures verification. Keeps StrongBox Key A inside Super App while signing DPoP proofs for Child Apps.',
    code: `package io.mosip.inji.sso

import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import java.security.KeyStore
import java.security.Signature

class SSOSigningService : Service() {

    private val binder = object : ISSOSigningService.Stub() {
        override fun requestNativeSsoBundle(httpMethod: String, targetUri: String, accessTokenHash: String?): Bundle {
            verifySameVendorSignatureOrThrow(Binder.getCallingUid())

            val session = EncryptedSsoVault.loadActiveSession(applicationContext)
                ?: throw IllegalStateException("No active eSignet SSO session in Super App")

            // Key A never leaves Android Keystore / StrongBox in Super App's process
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val entry = keyStore.getEntry("esignet_hardware_key_A", null) as KeyStore.PrivateKeyEntry

            val dpopProofJwt = DpopBuilder.signWithHardwareKey(
                privateKey = entry.privateKey,
                publicKeyJwk = session.publicKeyJwk,
                htm = httpMethod,
                htu = targetUri,
                ath = accessTokenHash
            )

            return Bundle().apply {
                putString("id_token", session.idToken)
                putString("device_secret", session.deviceSecret)
                putString("dpop_proof", dpopProofJwt)
            }
        }
    }

    private fun verifySameVendorSignatureOrThrow(callingUid: Int) {
        val pm = packageManager
        val cmp = pm.checkSignatures(applicationInfo.uid, callingUid)
        if (cmp != PackageManager.SIGNATURE_MATCH) {
            throw SecurityException("Caller UID \$callingUid is not signed by the trusted vendor certificate")
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder
}
`,
  },
  {
    id: 'android-child-app-client',
    repo: 'android-native-sso-suite',
    filePath: 'childapp/src/main/java/io/mosip/mparivahan/sso/NativeSsoClient.kt',
    language: 'kotlin',
    taskLabels: [
      'Task 7 & 8: Retrieve SSO Bundle & Execute Token Exchange [Child App]',
    ],
    summary:
      'Child App client that binds to Super App SSOSigningService, fetches id_token + device_secret + DPoP proof signed by Key A, and calls POST /oauth2/token with grant_type=token-exchange (excluding device_sso scope).',
    code: `package io.mosip.mparivahan.sso

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import kotlin.coroutines.resume

class NativeSsoClient(private val context: Context, private val httpClient: OkHttpClient) {

    suspend fun performSilentSignIn(requestedScopes: List<String>): TokenExchangeResult {
        // Mandatory Task 8 Note: Ensure device_sso is NEVER included in Child App token_exchange call
        val sanitizedScope = requestedScopes.filterNot { it == "device_sso" }.joinToString(" ")

        val ssoBundle = bindAndRequestBundle(
            httpMethod = "POST",
            targetUri = "https://esignet.mosip.net/oauth2/token"
        )

        val idToken = ssoBundle.getString("id_token")!!
        val deviceSecret = ssoBundle.getString("device_secret")!!
        val dpopProof = ssoBundle.getString("dpop_proof")!!

        val formBody = FormBody.Builder()
            .add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
            .add("client_id", "mosip-mparivahan-transit")
            .add("subject_token", idToken)
            .add("subject_token_type", "urn:ietf:params:oauth:token-type:id_token")
            .add("actor_token", deviceSecret)
            .add("actor_token_type", "urn:openid:params:token-type:device-secret")
            .add("audience", "https://esignet.mosip.net")
            .add("scope", sanitizedScope)
            .build()

        val request = Request.Builder()
            .url("https://esignet.mosip.net/oauth2/token")
            .header("DPoP", dpopProof)
            .post(formBody)
            .build()

        httpClient.newCall(request).execute().use { response ->
            return TokenExchangeResult.fromHttpResponse(response.code, response.body?.string().orEmpty())
        }
    }
}
`,
  },
  {
    id: 'ios-secure-enclave-dpop',
    repo: 'ios-native-sso-suite',
    filePath: 'deliverables/ios/SecureEnclaveDpopManager.swift',
    language: 'swift',
    taskLabels: ['iOS Hardware Key A: Secure Enclave EC P-256 + RFC 7638 JKT + ES256 DPoP'],
    summary:
      'Generates non-exportable EC P-256 keys in Apple Secure Enclave (kSecAttrTokenIDSecureEnclave) shared via kSecAttrAccessGroup, computes RFC 7638 thumbprints, and converts DER signatures to raw 64-byte JWS ES256 format.',
    code: `import Foundation
import Security
import CryptoKit

public final class SecureEnclaveDpopManager {
    public static let shared = SecureEnclaveDpopManager()
    private let keyTag = "io.mosip.esignet.sso.hardware.keyA"
    private let accessGroup = "TEAMID1234.group.io.mosip.sso"

    public func loadOrCreateHardwarePrivateKey() throws -> SecKey {
        let tagData = Data(keyTag.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnRef as String: true
        ]
        var item: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let key = item {
            return (key as! SecKey)
        }
        var error: Unmanaged<CFError>?
        let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage],
            &error
        )!
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessGroup as String: accessGroup,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tagData,
                kSecAttrAccessControl as String: access
            ]
        ]
        return SecKeyCreateRandomKey(attrs as CFDictionary, &error)!
    }

    public func computeJwkThumbprint() throws -> String {
        let jwk = try exportPublicKeyJwk()
        let canonical = #"{"crv":"\#(jwk["crv"]!)","kty":"\#(jwk["kty"]!)","x":"\#(jwk["x"]!)","y":"\#(jwk["y"]!)"}"#
        let digest = SHA256.hash(data: Data(canonical.utf8))
        return Self.base64UrlEncode(Data(digest))
    }
}
`,
  },
  {
    id: 'ios-keychain-sharing-sso',
    repo: 'ios-native-sso-suite',
    filePath: 'deliverables/ios/KeychainSharingSsoManager.swift',
    language: 'swift',
    taskLabels: ['Task 7 (iOS): Shared Keychain Access Group Credential Handoff'],
    summary:
      'Persists and retrieves Super App id_token and opaque JWE device_secret across vendor apps sharing $(TeamIdentifierPrefix)group.io.mosip.sso.',
    code: `import Foundation
import Security

public final class KeychainSharingSsoManager {
    public static let shared = KeychainSharingSsoManager()
    private let serviceIdentifier = "io.mosip.esignet.native-sso.vault"
    private let accountIdentifier = "active_citizen_sso_bundle"
    private let accessGroup = "TEAMID1234.group.io.mosip.sso"

    public func saveSuperAppSsoSession(_ data: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: accountIdentifier,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: data
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    }
}
`,
  },
  {
    id: 'ios-child-app-client',
    repo: 'ios-native-sso-suite',
    filePath: 'deliverables/ios/ChildAppSsoClient.swift',
    language: 'swift',
    taskLabels: ['Task 8 (iOS): RFC 8693 Token Exchange & DPoP UserInfo Client'],
    summary:
      'Reads shared Keychain session, signs DPoP proof via SecureEnclaveDpopManager, executes grant_type=token-exchange (excluding device_sso), and calls GET /oauth2/userinfo.',
    code: `import Foundation

public final class ChildAppSsoClient {
    public func performSilentSignIn(requestedScopes: [String]) async throws -> ChildTokenExchangeResponse {
        let sanitizedScopes = requestedScopes.filter { $0 != "device_sso" }
        let sharedSession = try KeychainSharingSsoManager.shared.loadSharedSsoSession()
        let dpopProof = try SecureEnclaveDpopManager.shared.createDpopProof(
            httpMethod: "POST",
            httpUri: "https://esignet.mosip.net/oauth2/token"
        )
        // Sends grant_type=urn:ietf:params:oauth:grant-type:token-exchange with DPoP header
        return try await executeTokenExchange(sharedSession: sharedSession, scopes: sanitizedScopes, dpop: dpopProof)
    }
}
`,
  },
  {
    id: 'go-sso-unit-tests-and-revocation',
    repo: 'mosip/esignet (develop-go)',
    filePath: 'deliverables/golang/internal/sso/sso_test.go',
    language: 'go',
    taskLabels: ['Go Test Suite: Positive, Negative & POST /oauth2/revoke Tests'],
    summary:
      'Comprehensive Go 1.22+ test suite verifying GenerateDeviceSecret, ValidateDeviceSecret, ds_hash binding, cnf.jkt DPoP match, scope subset rules, and JTI + SID revocation.',
    code: `package sso

import (
	"context"
	"testing"
	"github.com/thunder-id/thunderid/pkg/devicesecret"
)

func TestNativeSSO_RevocationAndNegativeSecurity(t *testing.T) {
	ctx := context.Background()
	dsService, validator, _ := setupTestSuite(t)

	genResp, _ := dsService.GenerateDeviceSecret(ctx, devicesecret.GenerateRequest{
		Sub:      "mosip-psut-9f8a7d6c5b4e3f2a1d0c",
		AuthID:   "sid-active-citizen-001",
		ClientID: "mosip-super-wallet-android",
		Scope:    "openid profile device_sso",
		ACR:      "mosip:idp:acr:generated-code",
		DPoPJKT:  "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U",
	})

	// Revoke device_secret JTI & invalidate SID via POST /oauth2/revoke
	revResp, revErr := validator.HandleRevokeOrLogout(ctx, RevokeOrLogoutRequest{
		DeviceSecret: genResp.DeviceSecret,
		ClientID:     "mosip-super-wallet-android",
	})
	if revErr != nil || !revResp.Revoked {
		t.Fatalf("expected revocation to succeed")
	}
}
`,
  },
  {
    id: 'github-actions-newman-ci',
    repo: 'ci-automation',
    filePath: '.github/workflows/native-sso-ci.yml',
    language: 'yaml',
    taskLabels: ['CI/CD: Automated Newman Postman Runner & Unit Test Gate'],
    summary:
      'GitHub Actions workflow that runs unit tests, starts the eSignet Go / Thunder ID server, and runs Newman + automated Postman assertions against all Native SSO endpoints.',
    code: `name: MOSIP eSignet Go & Thunder ID — Native SSO 1.0 CI
on: [push, pull_request]
jobs:
  verify-native-sso:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - run: npm ci
      - run: npm test
      - run: |
          nohup npm run dev > server.log 2>&1 &
          sleep 3
          npm run test:ci
`,
  },
];

export const POSTMAN_COLLECTION_V2_1 = {
  info: {
    _postman_id: '03-esignet-native-sso-go-thunderid',
    name: 'MOSIP eSignet Go & Thunder ID — OpenID Connect Native SSO 1.0 Collection',
    description:
      'End-to-end Postman Collection testing FAPI 2.0 PAR + DPoP Super App Login, Device Secret Issuance (ds_hash), OAuth 2.0 Token Exchange Silent SSO, and Negative Security Validations.',
    schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
  },
  variable: [
    { key: 'base_url', value: 'http://localhost:3000/api' },
    { key: 'super_client_id', value: 'mosip-super-wallet-android' },
    { key: 'child_client_id', value: 'mosip-mparivahan-transit' },
    { key: 'citizen_uin', value: '8294017365' },
  ],
  item: [
    {
      name: '1. Super App — Pushed Authorization Request (POST /oauth2/par)',
      request: {
        method: 'POST',
        header: [{ key: 'Content-Type', value: 'application/json' }],
        url: '{{base_url}}/oauth2/par',
        body: {
          mode: 'raw',
          raw: JSON.stringify(
            {
              client_id: 'mosip-super-wallet-android',
              scope: 'openid profile email device_sso',
              redirect_uri: 'io.mosip.inji.superwallet://oauth2redirect',
              code_challenge: 'E9Melhoa2OwvFrGMTJgu96e2t88U2vH_K2G1x2y3z4A',
              code_challenge_method: 'S256',
              dpop_jkt: 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
            },
            null,
            2
          ),
        },
      },
    },
    {
      name: '2. Super App — Exchange Code for Tokens + Device Secret (POST /oauth2/token)',
      request: {
        method: 'POST',
        header: [
          { key: 'Content-Type', value: 'application/json' },
          { key: 'DPoP', value: '{{super_app_dpop_proof}}' },
        ],
        url: '{{base_url}}/oauth2/token',
        body: {
          mode: 'raw',
          raw: JSON.stringify(
            {
              grant_type: 'authorization_code',
              client_id: 'mosip-super-wallet-android',
              code: '{{authorization_code}}',
              redirect_uri: 'io.mosip.inji.superwallet://oauth2redirect',
              code_verifier: '{{pkce_code_verifier}}',
            },
            null,
            2
          ),
        },
      },
    },
    {
      name: '3. Child App — Silent SSO Token Exchange (POST /oauth2/token)',
      request: {
        method: 'POST',
        header: [
          { key: 'Content-Type', value: 'application/json' },
          { key: 'DPoP', value: '{{dpop_proof_signed_by_super_app_key_A}}' },
        ],
        url: '{{base_url}}/oauth2/token',
        body: {
          mode: 'raw',
          raw: JSON.stringify(
            {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              client_id: 'mosip-mparivahan-transit',
              subject_token: '{{super_app_id_token}}',
              subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
              actor_token: '{{super_app_device_secret}}',
              actor_token_type: 'urn:openid:params:token-type:device-secret',
              audience: 'https://esignet.mosip.net',
              scope: 'openid profile',
            },
            null,
            2
          ),
        },
      },
    },
    {
      name: '4. Negative Test — Reject device_sso Scope in Token Exchange (Task 10b)',
      request: {
        method: 'POST',
        header: [
          { key: 'Content-Type', value: 'application/json' },
          { key: 'DPoP', value: '{{dpop_proof_signed_by_super_app_key_A}}' },
        ],
        url: '{{base_url}}/oauth2/token',
        body: {
          mode: 'raw',
          raw: JSON.stringify(
            {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              client_id: 'mosip-mparivahan-transit',
              subject_token: '{{super_app_id_token}}',
              subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
              actor_token: '{{super_app_device_secret}}',
              actor_token_type: 'urn:openid:params:token-type:device-secret',
              scope: 'openid profile device_sso',
            },
            null,
            2
          ),
        },
      },
    },
    {
      name: '5. Child App — Fetch Scoped Citizen Claims (GET /oauth2/userinfo)',
      request: {
        method: 'GET',
        header: [
          { key: 'Authorization', value: 'DPoP {{child_app_access_token}}' },
          { key: 'DPoP', value: '{{child_userinfo_dpop_proof}}' },
        ],
        url: '{{base_url}}/oauth2/userinfo',
      },
    },
    {
      name: '6. Session Revocation & Logout — Blacklist JTI & Invalidate SID (POST /oauth2/revoke)',
      request: {
        method: 'POST',
        header: [{ key: 'Content-Type', value: 'application/json' }],
        url: '{{base_url}}/oauth2/revoke',
        body: {
          mode: 'raw',
          raw: JSON.stringify(
            {
              device_secret: '{{super_app_device_secret}}',
              sid: '{{super_app_session_id}}',
              client_id: 'mosip-super-wallet-android',
            },
            null,
            2
          ),
        },
      },
    },
  ],
};

export interface MandatoryTaskStatusItem {
  number: string;
  repoTag: 'eSignet' | 'Thunder ID' | 'Client, Mobile App' | 'Bonus';
  title: string;
  specDetail: string;
}

export const MANDATORY_TASKS_CHECKLIST: MandatoryTaskStatusItem[] = [
  {
    number: '01',
    repoTag: 'eSignet',
    title: 'Request the device_sso scope',
    specDetail: 'Add support for device_sso in client authorize / PAR request to distinguish Native-SSO-enabled login.',
  },
  {
    number: '02',
    repoTag: 'eSignet',
    title: 'Validate device_sso at token endpoint',
    specDetail: 'Confirm allowed_authorization_scopes includes device_sso for the requesting registered client.',
  },
  {
    number: '03',
    repoTag: 'Thunder ID',
    title: 'Implement Device Secret Provider interface',
    specDetail: 'Expose DeviceSecretProvider interface in Thunder ID Engine for eSignet core integration.',
  },
  {
    number: '04',
    repoTag: 'eSignet',
    title: 'Generate & Validate Device Secret JWT/JWE',
    specDetail: 'Sign JWS with cnf.jkt, auth_id, exp, client_id, scope, acr, claims, iss; encrypt JWE; embed ds_hash in id_token.',
  },
  {
    number: '05',
    repoTag: 'eSignet',
    title: 'Invoke device secret generation on token endpoint',
    specDetail: 'Trigger GenerateDeviceSecret once device_sso scope is verified on authorization_code grant.',
  },
  {
    number: '06',
    repoTag: 'eSignet',
    title: 'Return tokens & device_secret to Super App',
    specDetail: 'Return DPoP-bound access_token, id_token (with ds_hash & sid), and signed-then-encrypted device_secret.',
  },
  {
    number: '07',
    repoTag: 'Client, Mobile App',
    title: 'Retrieve id_token, device_secret & DPoP proof via IPC',
    specDetail: 'Bind to Super App SSOSigningService, verify same vendor signing certificate, and sign DPoP proof with Key A.',
  },
  {
    number: '08',
    repoTag: 'Client, Mobile App',
    title: 'Initiate OAuth 2.0 Token Exchange call',
    specDetail: 'Call /oauth2/token with grant_type=token-exchange reusing Key A DPoP proof, omitting device_sso scope.',
  },
  {
    number: '09',
    repoTag: 'Thunder ID',
    title: 'Handle Token Exchange & Verify Cryptographic Bindings',
    specDetail: 'Validate actor_token, ds_hash binding to id_token, active sid, allowed_authorization_scopes, and cnf.jkt == DPoP jkt.',
  },
  {
    number: '10',
    repoTag: 'Thunder ID',
    title: 'Enforce scope subset & reject device_sso in exchange',
    specDetail: 'Ensure Child App scope is a subset of Super App granted scope and reject device_sso on token_exchange.',
  },
  {
    number: 'B1',
    repoTag: 'Bonus',
    title: 'Trigger step-up re-consent when Child App scopes differ',
    specDetail: 'Return interaction_required and render Child App re-consent prompt when requested scopes exceed Super App consent.',
  },
];
