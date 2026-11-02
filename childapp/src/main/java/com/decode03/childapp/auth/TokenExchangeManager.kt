package com.decode03.childapp.auth

import android.content.Context
import android.util.Log
import com.decode03.childapp.ipc.SuperAppServiceConnector
import com.decode03.childapp.model.CitizenClaims
import com.decode03.sso.Constants
import com.decode03.sso.OidcDiscoveryManager
import com.decode03.sso.ProtocolException
import com.decode03.sso.SsoConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * Executes the RFC 8693 Token Exchange Silent SSO flow in Child App:
 * 1. Discovers runtime endpoints (/.well-known/openid-configuration)
 * 2. Connects to Super App's signature-protected bound service
 * 3. Retrieves id_token, device_secret, and fresh DPoP proof
 * 4. Calls /oauth2/token with grant_type=urn:ietf:params:oauth:grant-type:token-exchange (NO device_sso)
 * 5. Calls /oauth2/userinfo with DPoP proof signed by Key A and displays citizen claims
 */
class TokenExchangeManager(private val context: Context) {

    private val connector = SuperAppServiceConnector(context)

    interface AuditCallback {
        fun onStep(stepName: String, details: String)
    }

    suspend fun performSilentSso(callback: AuditCallback? = null): Result<CitizenClaims> = withContext(Dispatchers.IO) {
        try {
            // 1. Runtime OIDC Discovery
            callback?.onStep("1. OIDC Discovery", "Fetching endpoints from ${SsoConfig.issuerUrl}/.well-known/openid-configuration")
            val endpointsResult = OidcDiscoveryManager.getEndpoints()
            val endpoints = endpointsResult.getOrElse { error ->
                return@withContext Result.failure(ProtocolException("OIDC Discovery failed: ${error.message}"))
            }
            callback?.onStep("1. OIDC Discovery Completed", "token_endpoint: ${endpoints.tokenEndpoint}\nuserinfo_endpoint: ${endpoints.userinfoEndpoint}")

            // 2. Bind to Super App & get handoff bundle
            callback?.onStep("2. IPC Verification", "Binding to Super App and verifying release X.509 signature match...")
            val handoffBundle = connector.getSsoHandoffBundle(endpoints.tokenEndpoint)

            val idToken = handoffBundle.getString(Constants.KEY_ID_TOKEN)
            val deviceSecret = handoffBundle.getString(Constants.KEY_DEVICE_SECRET)
            val dpopProof = handoffBundle.getString(Constants.KEY_DPOP_PROOF)

            if (idToken.isNullOrBlank() || deviceSecret.isNullOrBlank() || dpopProof.isNullOrBlank()) {
                return@withContext Result.failure(
                    ProtocolException("Super App handoff bundle missing required tokens (id_token, device_secret, or dpop_proof)")
                )
            }
            callback?.onStep("2. IPC Success", "Retrieved id_token (${idToken.take(16)}...), device_secret, and fresh DPoP proof.")

            // 3. Safety check: ensure Child App never requests device_sso
            val requestedScope = SsoConfig.childAppScopes
            if (requestedScope.contains(Constants.SCOPE_DEVICE_SSO)) {
                throw SecurityException(
                    "VIOLATION: Child App must NEVER request 'device_sso' scope during token exchange! Current scope: '$requestedScope'"
                )
            }

            // 4. RFC 8693 Token Exchange POST
            callback?.onStep("3. Token Exchange", "Calling ${endpoints.tokenEndpoint} with grant_type=urn:ietf:params:oauth:grant-type:token-exchange and DPoP header...")
            val exchangePayload = JSONObject().apply {
                put("grant_type", Constants.GRANT_TYPE_TOKEN_EXCHANGE)
                put("client_id", SsoConfig.childAppClientId)
                put("subject_token", idToken)
                put("subject_token_type", Constants.TOKEN_TYPE_ID_TOKEN)
                put("actor_token", deviceSecret)
                put("actor_token_type", Constants.TOKEN_TYPE_DEVICE_SECRET)
                put("audience", SsoConfig.tokenExchangeAudience)
                put("scope", requestedScope)
            }

            val tokenUrl = URL(endpoints.tokenEndpoint)
            val tokenConn = (tokenUrl.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 10000
                readTimeout = 10000
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Accept", "application/json")
                setRequestProperty("DPoP", dpopProof)
            }

            OutputStreamWriter(tokenConn.outputStream).use { writer ->
                writer.write(exchangePayload.toString())
                writer.flush()
            }

            val tokenStatus = tokenConn.responseCode
            val tokenResponseText = if (tokenStatus in 200..299) {
                BufferedReader(InputStreamReader(tokenConn.inputStream)).readText()
            } else {
                val err = tokenConn.errorStream?.let { BufferedReader(InputStreamReader(it)).readText() } ?: "HTTP $tokenStatus"
                val parsedError = parseServerError(err, tokenStatus)
                return@withContext Result.failure(ProtocolException("Token Exchange failed: $parsedError"))
            }

            val tokenJson = JSONObject(tokenResponseText)
            val childAccessToken = tokenJson.optString("access_token")
            val tokenType = tokenJson.optString("token_type")

            if (childAccessToken.isBlank()) {
                return@withContext Result.failure(
                    ProtocolException("Token Exchange response missing access_token: $tokenResponseText")
                )
            }
            callback?.onStep("3. Token Exchange Success", "Child Access Token issued ($tokenType): ${childAccessToken.take(20)}...")

            // 5. Fetch /oauth2/userinfo with DPoP proof containing ath
            callback?.onStep("4. UserInfo Request", "Requesting Super App to sign DPoP proof with 'ath' for GET ${endpoints.userinfoEndpoint}...")
            val userinfoDpopProof = connector.signDpopProof("GET", endpoints.userinfoEndpoint, childAccessToken)

            val userinfoUrl = URL(endpoints.userinfoEndpoint)
            val userinfoConn = (userinfoUrl.openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 10000
                readTimeout = 10000
                setRequestProperty("Accept", "application/json")
                setRequestProperty("Authorization", "DPoP $childAccessToken")
                setRequestProperty("DPoP", userinfoDpopProof)
            }

            val userinfoStatus = userinfoConn.responseCode
            val userinfoResponseText = if (userinfoStatus in 200..299) {
                BufferedReader(InputStreamReader(userinfoConn.inputStream)).readText()
            } else {
                val err = userinfoConn.errorStream?.let { BufferedReader(InputStreamReader(it)).readText() } ?: "HTTP $userinfoStatus"
                return@withContext Result.failure(
                    ProtocolException("UserInfo request rejected (HTTP $userinfoStatus): $err")
                )
            }

            val claimsJson = JSONObject(userinfoResponseText)
            val claims = CitizenClaims.fromJson(claimsJson)
            callback?.onStep("4. UserInfo Success", "Citizen claims received: ${claims.name ?: claims.sub}")

            Log.i(TAG, "Silent SSO completed end-to-end successfully for user: ${claims.sub}")
            Result.success(claims)
        } catch (e: Exception) {
            Log.e(TAG, "Silent SSO failed: ${e.message}", e)
            Result.failure(e)
        }
    }

    private fun parseServerError(rawError: String, httpStatus: Int): String {
        return try {
            val json = JSONObject(rawError)
            val error = json.optString("error")
            val description = json.optString("error_description", error)
            when (error) {
                "invalid_scope" -> "Scope rejected by server: $description"
                "invalid_grant" -> {
                    if (description.contains("expired", ignoreCase = true) || description.contains("device_secret", ignoreCase = true)) {
                        "Expired or invalid device_secret: Please re-authenticate on Super App."
                    } else {
                        "Invalid Grant: $description"
                    }
                }
                "invalid_dpop_proof" -> "DPoP proof rejected by server: $description"
                else -> "(HTTP $httpStatus) $description"
            }
        } catch (e: Exception) {
            "(HTTP $httpStatus) $rawError"
        }
    }

    fun cleanUp() {
        connector.disconnect()
    }

    companion object {
        private const val TAG = "TokenExchangeManager"
    }
}
