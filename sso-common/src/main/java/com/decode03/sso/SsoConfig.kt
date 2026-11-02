package com.decode03.sso

import android.content.Context

/**
 * Central configuration file for MOSIP eSignet Native SSO mobile apps.
 *
 * Defaults to the live HTTPS public tunnel with Native SSO 1.0 support:
 * https://obtaining-afford-silicon-genesis.trycloudflare.com/api
 *
 * Developers and testers can switch between Public Tunnel, Local Wi-Fi,
 * Local Laptop (via adb reverse), Local Emulator (10.0.2.2), or MOSIP Collab Sandbox
 * directly from the app UI without rebuilding the APK.
 */
object SsoConfig {
    const val PRESET_PUBLIC_TUNNEL: String = "https://obtaining-afford-silicon-genesis.trycloudflare.com/api"
    const val PRESET_LOCAL_WIFI: String = "http://172.16.138.34:3000/api"
    const val PRESET_LOCAL_ADB: String = "http://127.0.0.1:3000/api"
    const val PRESET_LOCAL_EMULATOR: String = "http://10.0.2.2:3000/api"
    const val PRESET_COLLAB_SANDBOX: String = "https://esignet.collab.mosip.net"

    private const val PREFS_NAME = "sso_config_preferences"
    private const val KEY_CUSTOM_ISSUER = "key_custom_issuer_url"

    /**
     * OpenID Connect Issuer URL.
     * Runtime endpoints (par, authorization, token, userinfo) will be discovered
     * dynamically from "$issuerUrl/.well-known/openid-configuration".
     */
    var issuerUrl: String = "https://obtaining-afford-silicon-genesis.trycloudflare.com/api"

    /**
     * Super App OAuth 2.0 Client ID (registered with device_sso scope).
     */
    var superAppClientId: String = "mosip-super-wallet-android"

    /**
     * Super App Redirect URI registered with eSignet.
     * Captured via Custom Tab / Deep Link in AuthRedirectActivity.
     */
    var superAppRedirectUri: String = "io.mosip.inji.superwallet://oauth2redirect"

    /**
     * Scopes requested by Super App during PAR login.
     * MUST include "device_sso" to request device_secret issuance.
     */
    var superAppScopes: String = "openid profile email device_sso"

    /**
     * Child App OAuth 2.0 Client ID (registered for token-exchange).
     */
    var childAppClientId: String = "mosip-mparivahan-transit"

    /**
     * Scopes requested by Child App during RFC 8693 Token Exchange.
     * MUST be a subset of Super App's scopes and MUST NOT request "device_sso".
     */
    var childAppScopes: String = "openid profile"

    /**
     * Audience parameter for RFC 8693 Token Exchange in Child App.
     * Defaults to the OIDC Issuer URL.
     */
    var tokenExchangeAudience: String? = null
        get() = field ?: issuerUrl
        set(value) {
            field = value
        }

    /**
     * Optional client assertion JWT for private_key_jwt client authentication in PAR.
     * Null defaults to standard public client with PKCE S256 + DPoP dpop_jkt.
     */
    var clientAssertionJwt: String? = null

    /**
     * Super App package name for bound IPC service resolution.
     */
    const val SUPER_APP_PACKAGE_NAME: String = "com.decode03.superapp"

    /**
     * Child App package name.
     */
    const val CHILD_APP_PACKAGE_NAME: String = "com.decode03.childapp"

    /**
     * Initializes custom configuration from SharedPreferences if previously modified by user.
     * Resets stale dead Cloud Run URLs to the live public tunnel.
     */
    fun init(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val saved = prefs.getString(KEY_CUSTOM_ISSUER, null)
        val staleUrls = listOf("ais-pre-awedmi5q3esrqnpuk72vwm", "nec-trails-dash-guns")
        if (!saved.isNullOrBlank() && staleUrls.none { saved.contains(it) }) {
            issuerUrl = saved.trim().trimEnd('/')
        } else {
            issuerUrl = PRESET_PUBLIC_TUNNEL
            prefs.edit().putString(KEY_CUSTOM_ISSUER, PRESET_PUBLIC_TUNNEL).apply()
        }
    }

    /**
     * Updates the active issuer URL, persists it to SharedPreferences,
     * and clears the OIDC discovery cache so subsequent requests use the new server.
     */
    fun updateIssuerUrl(context: Context, newUrl: String) {
        val cleaned = newUrl.trim().trimEnd('/')
        issuerUrl = cleaned
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_CUSTOM_ISSUER, cleaned)
            .apply()
        OidcDiscoveryManager.clearCache()
    }
}
