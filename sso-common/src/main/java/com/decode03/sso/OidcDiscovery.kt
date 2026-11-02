package com.decode03.sso

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

/**
 * Data model for OpenID Connect Discovery Metadata (RFC 8414 / OpenID Connect Discovery 1.0).
 */
data class OidcEndpoints(
    val issuer: String,
    val parEndpoint: String?,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val userinfoEndpoint: String,
    val jwksUri: String?,
    val rawJson: JSONObject
)

object OidcDiscoveryManager {
    @Volatile
    private var cachedEndpoints: OidcEndpoints? = null

    /**
     * Clears the cached discovery endpoints so the next request refreshes from the server.
     */
    fun clearCache() {
        cachedEndpoints = null
    }

    /**
     * Fetches and parses the OpenID Connect discovery document at runtime from:
     * "$baseUrl/.well-known/openid-configuration"
     */
    suspend fun getEndpoints(
        issuerBaseUrl: String = SsoConfig.issuerUrl,
        forceRefresh: Boolean = false
    ): Result<OidcEndpoints> = withContext(Dispatchers.IO) {
        if (!forceRefresh && cachedEndpoints != null && cachedEndpoints?.issuer == issuerBaseUrl) {
            return@withContext Result.success(cachedEndpoints!!)
        }

        try {
            val normalizedBase = issuerBaseUrl.trimEnd('/')
            val discoveryUrl = "$normalizedBase/.well-known/openid-configuration"
            val url = URL(discoveryUrl)
            val connection = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 10000
                readTimeout = 10000
                setRequestProperty("Accept", "application/json")
            }

            val responseCode = connection.responseCode
            if (responseCode !in 200..299) {
                val errorStream = connection.errorStream?.let {
                    BufferedReader(InputStreamReader(it)).readText()
                } ?: "HTTP $responseCode"
                return@withContext Result.failure(
                    ProtocolException(
                        "Failed to fetch OIDC discovery document from $discoveryUrl. Status: $responseCode, Response: $errorStream"
                    )
                )
            }

            val responseBody = BufferedReader(InputStreamReader(connection.inputStream)).readText()
            val json = JSONObject(responseBody)

            val issuer = json.optString("issuer")
            if (issuer.isBlank()) {
                return@withContext Result.failure(
                    ProtocolException("Invalid OIDC discovery response: 'issuer' field is required but missing.")
                )
            }

            val authorizationEndpoint = json.optString("authorization_endpoint")
            if (authorizationEndpoint.isBlank()) {
                return@withContext Result.failure(
                    ProtocolException("Invalid OIDC discovery response: 'authorization_endpoint' field is missing.")
                )
            }

            val tokenEndpoint = json.optString("token_endpoint")
            if (tokenEndpoint.isBlank()) {
                return@withContext Result.failure(
                    ProtocolException("Invalid OIDC discovery response: 'token_endpoint' field is missing.")
                )
            }

            val userinfoEndpoint = json.optString("userinfo_endpoint")
            if (userinfoEndpoint.isBlank()) {
                return@withContext Result.failure(
                    ProtocolException("Invalid OIDC discovery response: 'userinfo_endpoint' field is missing.")
                )
            }

            val parEndpoint = json.optString("pushed_authorization_request_endpoint").ifBlank { null }
            val jwksUri = json.optString("jwks_uri").ifBlank { null }

            val endpoints = OidcEndpoints(
                issuer = issuer,
                parEndpoint = parEndpoint,
                authorizationEndpoint = authorizationEndpoint,
                tokenEndpoint = tokenEndpoint,
                userinfoEndpoint = userinfoEndpoint,
                jwksUri = jwksUri,
                rawJson = json
            )

            // Update default tokenExchangeAudience if not customized
            if (SsoConfig.tokenExchangeAudience == SsoConfig.issuerUrl) {
                SsoConfig.tokenExchangeAudience = endpoints.issuer
            }

            cachedEndpoints = endpoints
            Result.success(endpoints)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

class ProtocolException(message: String) : Exception(message)
