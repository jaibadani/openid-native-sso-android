package com.decode03.superapp.auth

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom

data class PkcePair(
    val codeVerifier: String,
    val codeChallenge: String,
    val codeChallengeMethod: String = "S256"
)

object PkceUtil {
    private val secureRandom = SecureRandom()

    fun generate(): PkcePair {
        val verifierBytes = ByteArray(32)
        secureRandom.nextBytes(verifierBytes)
        val codeVerifier = Base64.encodeToString(
            verifierBytes,
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        ).trim()

        val digest = MessageDigest.getInstance("SHA-256")
            .digest(codeVerifier.toByteArray(Charsets.US_ASCII))
        val codeChallenge = Base64.encodeToString(
            digest,
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        ).trim()

        return PkcePair(
            codeVerifier = codeVerifier,
            codeChallenge = codeChallenge
        )
    }
}
