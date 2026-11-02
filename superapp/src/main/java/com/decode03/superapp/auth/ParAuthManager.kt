package com.decode03.superapp.auth

import android.content.Context
import android.net.Uri
import android.util.Base64
import android.util.Log
import androidx.browser.customtabs.CustomTabsIntent
import com.decode03.sso.Constants
import com.decode03.sso.OidcDiscoveryManager
import com.decode03.sso.OidcEndpoints
import com.decode03.sso.ProtocolException
import com.decode03.sso.SsoConfig
import com.decode03.superapp.crypto.DpopProofGenerator
import com.decode03.superapp.crypto.HardwareKeyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID

object ParAuthManager {
    private const val TAG = "ParAuthManager"

    @Volatile
    var pendingPkceVerifier: String? = null
        private set

    @Volatile
    var pendingState: String? = null
        private set

    /**
     * Step 1: Initiates PAR login flow:
     * - Fetches OIDC discovery document at runtime
     * - Generates PKCE code_verifier & code_challenge (S256)
     * - Obtains Hardware Key A's RFC 7638 thumbprint (`dpop_jkt`)
     * - Generates RFC 9449 DPoP proof for the PAR endpoint
     * - POSTs to PAR endpoint with `scope` including `device_sso`
     * - Launches Custom Tab with returned `request_uri`
     */
    suspend fun startParLogin(context: Context): Result<String> = withContext(Dispatchers.IO) {
        try {
            // 1. Runtime OIDC Discovery
            val endpointsResult = OidcDiscoveryManager.getEndpoints()
            val endpoints = endpointsResult.getOrElse { error ->
                return@withContext Result.failure(
                    ProtocolException("OIDC Discovery failed: ${error.message}")
                )
            }

            val parEndpoint = endpoints.parEndpoint ?: return@withContext Result.failure(
                ProtocolException("eSignet discovery document did not return 'pushed_authorization_request_endpoint'.")
            )

            // 2. PKCE & Hardware Key Thumbprint
            val pkce = PkceUtil.generate()
            pendingPkceVerifier = pkce.codeVerifier
            val state = UUID.randomUUID().toString()
            pendingState = state

            val dpopJkt = HardwareKeyManager.computeJwkThumbprint()
            Log.d(TAG, "Hardware Key A dpop_jkt: $dpopJkt")

            // 3. RFC 9449 DPoP Proof for PAR
            val dpopProof = DpopProofGenerator.createDpopProof(
                htm = "POST",
                htu = parEndpoint
            )

            // 4. Build PAR JSON Payload
            val requestBody = JSONObject().apply {
                put("client_id", SsoConfig.superAppClientId)
                put("scope", SsoConfig.superAppScopes)
                put("redirect_uri", SsoConfig.superAppRedirectUri)
                put("code_challenge", pkce.codeChallenge)
                put("code_challenge_method", pkce.codeChallengeMethod)
                put("dpop_jkt", dpopJkt)
                put("response_type", "code")
                put("state", state)
                put("nonce", UUID.randomUUID().toString())

                // Optional client assertion if configured
                SsoConfig.clientAssertionJwt?.let { assertion ->
                    put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                    put("client_assertion", assertion)
                }
            }

            // 5. Execute HTTP POST to PAR endpoint
            val parUrl = URL(parEndpoint)
            val connection = (parUrl.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 10000
                readTimeout = 10000
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Accept", "application/json")
                setRequestProperty("DPoP", dpopProof)
            }

            OutputStreamWriter(connection.outputStream).use { writer ->
                writer.write(requestBody.toString())
                writer.flush()
            }

            val responseCode = connection.responseCode
            val responseBody = if (responseCode in 200..299) {
                BufferedReader(InputStreamReader(connection.inputStream)).readText()
            } else {
                val err = connection.errorStream?.let { BufferedReader(InputStreamReader(it)).readText() }
                return@withContext Result.failure(
                    ProtocolException("PAR request rejected (HTTP $responseCode): $err")
                )
            }

            val responseJson = JSONObject(responseBody)
            val requestUri = responseJson.optString("request_uri")
            if (requestUri.isBlank()) {
                return@withContext Result.failure(
                    ProtocolException("PAR response missing required 'request_uri': $responseBody")
                )
            }

            Log.i(TAG, "PAR Success! request_uri: $requestUri (expires_in: ${responseJson.optInt("expires_in")}s)")

            // 6. Launch Custom Tab with authorization_endpoint and request_uri
            val authUrl = "${endpoints.authorizationEndpoint}?client_id=${Uri.encode(SsoConfig.superAppClientId)}&request_uri=${Uri.encode(requestUri)}"

            withContext(Dispatchers.Main) {
                val customTabsIntent = CustomTabsIntent.Builder()
                    .setShowTitle(true)
                    .build()
                customTabsIntent.launchUrl(context, Uri.parse(authUrl))
            }

            Result.success(requestUri)
        } catch (e: Exception) {
            Log.e(TAG, "PAR Login error: ${e.message}", e)
            Result.failure(e)
        }
    }

    /**
     * Step 2: Exchanges the authorization code received from the Custom Tab redirect
     * for tokens, including `device_secret` (issued because `device_sso` scope was requested).
     */
    suspend fun exchangeCodeForTokens(
        context: Context,
        code: String
    ): Result<SuperAppSession> = withContext(Dispatchers.IO) {
        try {
            val verifier = pendingPkceVerifier ?: return@withContext Result.failure(
                IllegalStateException("Missing pending PKCE code_verifier. Restart login flow.")
            )

            val endpointsResult = OidcDiscoveryManager.getEndpoints()
            val endpoints = endpointsResult.getOrThrow()
            val tokenEndpoint = endpoints.tokenEndpoint

            // RFC 9449 DPoP proof for POST /oauth2/token
            val dpopProof = DpopProofGenerator.createDpopProof(
                htm = "POST",
                htu = tokenEndpoint
            )

            val requestBody = JSONObject().apply {
                put("grant_type", Constants.GRANT_TYPE_AUTHORIZATION_CODE)
                put("client_id", SsoConfig.superAppClientId)
                put("code", code)
                put("redirect_uri", SsoConfig.superAppRedirectUri)
                put("code_verifier", verifier)
            }

            val tokenUrl = URL(tokenEndpoint)
            val connection = (tokenUrl.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 10000
                readTimeout = 10000
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Accept", "application/json")
                setRequestProperty("DPoP", dpopProof)
            }

            OutputStreamWriter(connection.outputStream).use { writer ->
                writer.write(requestBody.toString())
                writer.flush()
            }

            val responseCode = connection.responseCode
            val responseBody = if (responseCode in 200..299) {
                BufferedReader(InputStreamReader(connection.inputStream)).readText()
            } else {
                val err = connection.errorStream?.let { BufferedReader(InputStreamReader(it)).readText() }
                return@withContext Result.failure(
                    ProtocolException("Token exchange failed (HTTP $responseCode): $err")
                )
            }

            val tokenJson = JSONObject(responseBody)
            val accessToken = tokenJson.optString("access_token")
            val idToken = tokenJson.optString("id_token")
            val deviceSecret = tokenJson.optString("device_secret")

            if (accessToken.isBlank() || idToken.isBlank() || deviceSecret.isBlank()) {
                return@withContext Result.failure(
                    ProtocolException("Server token response missing required tokens. Expected access_token, id_token, and device_secret.")
                )
            }

            // Extract sid from id_token payload
            val sid = parseSidFromJwt(idToken)
            val dpopJkt = HardwareKeyManager.computeJwkThumbprint()

            // Securely store session in EncryptedSharedPreferences
            val storage = SessionStorage(context)
            storage.saveSession(
                idToken = idToken,
                accessToken = accessToken,
                deviceSecret = deviceSecret,
                sid = sid,
                dpopJkt = dpopJkt,
                rawClaimsJson = tokenJson.toString()
            )

            // Clear temporary PKCE state
            pendingPkceVerifier = null
            pendingState = null

            val session = storage.getSession()!!
            Log.i(TAG, "Super App successfully authenticated! Session stored (sid=$sid).")
            Result.success(session)
        } catch (e: Exception) {
            Log.e(TAG, "Token exchange error: ${e.message}", e)
            Result.failure(e)
        }
    }

    private fun parseSidFromJwt(jwt: String): String? {
        return try {
            val parts = jwt.split('.')
            if (parts.size >= 2) {
                val payloadString = String(Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_PADDING), Charsets.UTF_8)
                val json = JSONObject(payloadString)
                json.optString("sid").ifBlank { null }
            } else null
        } catch (e: Exception) {
            null
        }
    }
}
