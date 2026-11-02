package com.decode03.superapp.crypto

import android.util.Base64
import com.decode03.sso.Constants
import org.json.JSONObject
import java.security.MessageDigest
import java.util.UUID

/**
 * RFC 9449 OAuth 2.0 Demonstrating Proof of Possession (DPoP) Proof Generator.
 *
 * Produces compact JWS signed with Super App's hardware-backed Key A (ES256).
 */
object DpopProofGenerator {

    /**
     * Generates an RFC 9449 compliant DPoP proof JWT.
     *
     * @param htm The HTTP Method (e.g. "POST" or "GET").
     * @param htu The HTTP Target URI without query or fragment (e.g. "https://esignet.mosip.net/oauth2/token").
     * @param accessToken Optional access token. When provided, its SHA-256 hash is embedded in "ath".
     * @return Compact serialized JWT: "<header>.<payload>.<signature>"
     */
    fun createDpopProof(
        htm: String,
        htu: String,
        accessToken: String? = null
    ): String {
        val normalizedHtu = normalizeHtu(htu)
        val jwk = HardwareKeyManager.getPublicJwk()

        // 1. DPoP Header (typ = "dpop+jwt", alg = "ES256", jwk = public key)
        val headerJson = JSONObject().apply {
            put("typ", Constants.DPOP_HEADER_TYP)
            put("alg", Constants.DPOP_ALG_ES256)
            put("jwk", jwk)
        }

        // 2. DPoP Payload (htm, htu, iat, jti, optional ath)
        val iatSeconds = System.currentTimeMillis() / 1000
        val jti = UUID.randomUUID().toString()

        val payloadJson = JSONObject().apply {
            put("htm", htm.uppercase())
            put("htu", normalizedHtu)
            put("iat", iatSeconds)
            put("jti", jti)

            if (!accessToken.isNullOrBlank()) {
                put("ath", computeAccessTokenHash(accessToken))
            }
        }

        // 3. JWS Compact Serialization
        val encodedHeader = base64UrlEncode(headerJson.toString().toByteArray(Charsets.UTF_8))
        val encodedPayload = base64UrlEncode(payloadJson.toString().toByteArray(Charsets.UTF_8))
        val signingInput = "$encodedHeader.$encodedPayload"

        val signatureBytes = HardwareKeyManager.signEs256(signingInput.toByteArray(Charsets.US_ASCII))
        val encodedSignature = base64UrlEncode(signatureBytes)

        return "$signingInput.$encodedSignature"
    }

    /**
     * Computes RFC 9449 `ath` (Access Token Hash):
     * BASE64URL(SHA-256(ASCII(access_token)))
     */
    fun computeAccessTokenHash(accessToken: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(accessToken.toByteArray(Charsets.US_ASCII))
        return base64UrlEncode(digest)
    }

    private fun normalizeHtu(rawUrl: String): String {
        val queryIndex = rawUrl.indexOf('?')
        val cleanUrl = if (queryIndex != -1) rawUrl.substring(0, queryIndex) else rawUrl
        val hashIndex = cleanUrl.indexOf('#')
        return if (hashIndex != -1) cleanUrl.substring(0, hashIndex) else cleanUrl
    }

    private fun base64UrlEncode(bytes: ByteArray): String {
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP).trim()
    }
}
