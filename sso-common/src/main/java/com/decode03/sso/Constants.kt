package com.decode03.sso

object Constants {
    // IPC Bundle Keys
    const val KEY_ID_TOKEN = "id_token"
    const val KEY_DEVICE_SECRET = "device_secret"
    const val KEY_DPOP_PROOF = "dpop_proof"
    const val KEY_DPOP_JKT = "dpop_jkt"
    const val KEY_ERROR_CODE = "error_code"
    const val KEY_ERROR_MESSAGE = "error_message"

    // Error Codes
    const val ERR_NO_ACTIVE_SESSION = "NO_ACTIVE_SESSION"
    const val ERR_SIGNATURE_MISMATCH = "SIGNATURE_MISMATCH"
    const val ERR_DEVICE_SECRET_EXPIRED = "DEVICE_SECRET_EXPIRED"
    const val ERR_SCOPE_REJECTED = "SCOPE_REJECTED"
    const val ERR_HARDWARE_KEY_FAILURE = "HARDWARE_KEY_FAILURE"
    const val ERR_NETWORK_ERROR = "NETWORK_ERROR"
    const val ERR_DISCOVERY_FAILED = "DISCOVERY_FAILED"
    const val ERR_SERVER_PROTOCOL_VIOLATION = "SERVER_PROTOCOL_VIOLATION"

    // IPC Action & Signature Permission
    const val ACTION_BIND_SSO = "com.decode03.sso.action.BIND_SSO_SIGNING_SERVICE"
    const val PERMISSION_ACCESS_NATIVE_SSO = "com.decode03.sso.permission.ACCESS_NATIVE_SSO"

    // OAuth 2.0 / OpenID Connect Native SSO Grant Types & Token Types
    const val GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"
    const val GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
    const val TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
    const val TOKEN_TYPE_DEVICE_SECRET = "urn:openid:params:token-type:device-secret"

    // Scopes
    const val SCOPE_OPENID = "openid"
    const val SCOPE_PROFILE = "profile"
    const val SCOPE_EMAIL = "email"
    const val SCOPE_DEVICE_SSO = "device_sso"

    // RFC 9449 DPoP Header Types
    const val DPOP_HEADER_TYP = "dpop+jwt"
    const val DPOP_ALG_ES256 = "ES256"

    // Hardware Keystore Alias
    const val KEYSTORE_ALIAS_HARDWARE_KEY_A = "esignet_hardware_key_A"
    const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
}
