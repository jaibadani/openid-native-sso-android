package com.decode03.superapp.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import android.util.Log
import com.decode03.sso.Constants
import org.json.JSONObject
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint

/**
 * Manages the hardware-backed EC P-256 key pair (Key A) inside AndroidKeyStore.
 *
 * Implements:
 * - StrongBox Keymaster generation with fallback to TEE
 * - Non-exportable private key protection
 * - RFC 7517 JWK extraction (x, y affine coordinates)
 * - RFC 7638 JWK SHA-256 Thumbprint computation (`dpop_jkt`)
 * - ES256 signing with DER to IEEE P1363 (r || s, 64-byte) conversion for JWS compliance
 */
object HardwareKeyManager {
    private const val TAG = "HardwareKeyManager"
    private const val ALIAS = Constants.KEYSTORE_ALIAS_HARDWARE_KEY_A

    /**
     * Retrieves or generates the hardware-backed EC P-256 key pair.
     * Prefers StrongBox Keymaster; automatically falls back to TEE if StrongBox is unavailable.
     */
    @Synchronized
    fun getOrCreateKeyA(): KeyPair {
        val keyStore = KeyStore.getInstance(Constants.ANDROID_KEYSTORE_PROVIDER).apply {
            load(null)
        }

        if (keyStore.containsAlias(ALIAS)) {
            val privateKey = keyStore.getKey(ALIAS, null)
            val certificate = keyStore.getCertificate(ALIAS)
            if (privateKey != null && certificate != null) {
                return KeyPair(certificate.publicKey, privateKey as java.security.PrivateKey)
            }
        }

        return generateKeyA(useStrongBox = true)
    }

    private fun generateKeyA(useStrongBox: Boolean): KeyPair {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                Constants.ANDROID_KEYSTORE_PROVIDER
            )

            val builder = KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)

            if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    builder.setIsStrongBoxBacked(true)
                } catch (e: Exception) {
                    Log.w(TAG, "Failed setting StrongBox on builder, falling back to TEE: ${e.message}")
                }
            }

            keyPairGenerator.initialize(builder.build())
            val keyPair = keyPairGenerator.generateKeyPair()
            Log.i(TAG, "Hardware Key A generated successfully (StrongBox requested: $useStrongBox)")
            return keyPair
        } catch (e: Exception) {
            if (useStrongBox && (e is StrongBoxUnavailableException || e.message?.contains("StrongBox", ignoreCase = true) == true)) {
                Log.w(TAG, "StrongBox unavailable on this hardware. Falling back to standard TEE Keymaster...")
                return generateKeyA(useStrongBox = false)
            }
            Log.e(TAG, "Failed to generate Key A in AndroidKeyStore: ${e.message}", e)
            throw RuntimeException("Failed to generate hardware-backed key: ${e.message}", e)
        }
    }

    /**
     * Extracts RFC 7517 Public JWK representation of Key A:
     * {"kty":"EC","crv":"P-256","x":"...","y":"..."}
     */
    fun getPublicJwk(): JSONObject {
        val keyPair = getOrCreateKeyA()
        val ecPublicKey = keyPair.public as ECPublicKey
        val w: ECPoint = ecPublicKey.w

        val xBytes = getPaddedCoordinate(w.affineX.toByteArray(), 32)
        val yBytes = getPaddedCoordinate(w.affineY.toByteArray(), 32)

        val xBase64Url = Base64.encodeToString(xBytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP).trim()
        val yBase64Url = Base64.encodeToString(yBytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP).trim()

        return JSONObject().apply {
            put("kty", "EC")
            put("crv", "P-256")
            put("x", xBase64Url)
            put("y", yBase64Url)
        }
    }

    /**
     * Computes RFC 7638 SHA-256 JWK Thumbprint (`dpop_jkt`).
     * Canonical lexicographical order for EC P-256: {"crv","kty","x","y"}
     */
    fun computeJwkThumbprint(): String {
        val jwk = getPublicJwk()
        val canonicalJson = "{\"crv\":\"${jwk.getString("crv")}\",\"kty\":\"${jwk.getString("kty")}\",\"x\":\"${jwk.getString("x")}\",\"y\":\"${jwk.getString("y")}\"}"
        val digest = MessageDigest.getInstance("SHA-256").digest(canonicalJson.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP).trim()
    }

    /**
     * Signs data using Hardware Key A with SHA256withECDSA.
     * Converts ASN.1 DER signature output to IEEE P1363 (64-byte raw r || s) for JWS ES256 compliance.
     */
    fun signEs256(dataToSign: ByteArray): ByteArray {
        val keyPair = getOrCreateKeyA()
        val signatureEngine = Signature.getInstance("SHA256withECDSA")
        signatureEngine.initSign(keyPair.private)
        signatureEngine.update(dataToSign)
        val derSignature = signatureEngine.sign()
        return derToP1363(derSignature)
    }

    /**
     * Converts an ASN.1 DER encoded ECDSA signature into IEEE P1363 format (fixed 64 bytes: 32 bytes r + 32 bytes s).
     */
    private fun derToP1363(der: ByteArray): ByteArray {
        if (der.size < 8 || der[0].toInt() != 0x30) {
            throw IllegalArgumentException("Invalid DER sequence header")
        }

        var offset = 2
        if (der[1].toInt() and 0x80 != 0) {
            val lengthBytes = der[1].toInt() and 0x7F
            offset = 2 + lengthBytes
        }

        // Read r
        if (der[offset].toInt() != 0x02) throw IllegalArgumentException("Expected ASN.1 INTEGER for r")
        offset++
        val rLen = der[offset++].toInt() and 0xFF
        val rBytes = der.copyOfRange(offset, offset + rLen)
        offset += rLen

        // Read s
        if (der[offset].toInt() != 0x02) throw IllegalArgumentException("Expected ASN.1 INTEGER for s")
        offset++
        val sLen = der[offset++].toInt() and 0xFF
        val sBytes = der.copyOfRange(offset, offset + sLen)

        val p1363 = ByteArray(64)
        val normalizedR = getPaddedCoordinate(rBytes, 32)
        val normalizedS = getPaddedCoordinate(sBytes, 32)

        System.arraycopy(normalizedR, 0, p1363, 0, 32)
        System.arraycopy(normalizedS, 0, p1363, 32, 32)
        return p1363
    }

    private fun getPaddedCoordinate(bytes: ByteArray, targetLength: Int): ByteArray {
        if (bytes.size == targetLength) return bytes
        if (bytes.size > targetLength) {
            // Trim leading zero sign bytes from BigInteger
            val start = bytes.size - targetLength
            return bytes.copyOfRange(start, bytes.size)
        }
        val padded = ByteArray(targetLength)
        System.arraycopy(bytes, 0, padded, targetLength - bytes.size, bytes.size)
        return padded
    }
}
