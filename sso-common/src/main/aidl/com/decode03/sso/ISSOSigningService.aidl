package com.decode03.sso;

import android.os.Bundle;

/**
 * Signature-protected bound IPC service exposed by Super App.
 *
 * Implements OpenID Connect Native SSO 1.0 and FAPI 2.0 DPoP signing delegation.
 * Callers are strictly validated using PackageManager.checkSignatures(myUid, callerUid).
 */
interface ISSOSigningService {
    /**
     * Authenticates caller certificate, verifies active Super App session,
     * and signs a fresh DPoP proof for the child app's RFC 8693 token exchange.
     *
     * @param childClientId The client_id of the calling child app.
     * @param tokenEndpointUrl Full target token endpoint URL for DPoP binding (e.g. "https://esignet.mosip.net/oauth2/token").
     * @return Bundle containing:
     *         - "id_token": String
     *         - "device_secret": String
     *         - "dpop_proof": String (signed with Key A for POST tokenEndpointUrl, ath=null)
     *         - "dpop_jkt": String (RFC 7638 SHA-256 thumbprint of Key A)
     *         Or on failure:
     *         - "error_code": String
     *         - "error_message": String
     */
    Bundle requestSsoHandoff(String childClientId, String tokenEndpointUrl);

    /**
     * Signs a fresh DPoP Proof JWT using Super App's hardware-backed Key A (EC P-256)
     * for subsequent resource requests made by the child app (e.g. GET /oauth2/userinfo).
     *
     * @param htm HTTP Method ("GET" or "POST").
     * @param htu HTTP URI (e.g. "https://esignet.mosip.net/oauth2/userinfo").
     * @param accessToken Optional access token. When provided, its SHA-256 hash is embedded in the "ath" claim.
     * @return Compact ES256 DPoP JWT string.
     */
    String signDpopProof(String htm, String htu, @nullable String accessToken);
}
