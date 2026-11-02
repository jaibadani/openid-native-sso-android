package com.decode03.superapp.auth

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

data class SuperAppSession(
    val idToken: String,
    val accessToken: String,
    val deviceSecret: String,
    val sid: String?,
    val dpopJkt: String,
    val createdAt: Long,
    val rawClaimsJson: String?
)

class SessionStorage(context: Context) {
    private val sharedPreferences: SharedPreferences

    init {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        sharedPreferences = EncryptedSharedPreferences.create(
            context,
            PREFS_FILENAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun saveSession(
        idToken: String,
        accessToken: String,
        deviceSecret: String,
        sid: String?,
        dpopJkt: String,
        rawClaimsJson: String? = null
    ) {
        sharedPreferences.edit()
            .putString(KEY_ID_TOKEN, idToken)
            .putString(KEY_ACCESS_TOKEN, accessToken)
            .putString(KEY_DEVICE_SECRET, deviceSecret)
            .putString(KEY_SID, sid)
            .putString(KEY_DPOP_JKT, dpopJkt)
            .putLong(KEY_CREATED_AT, System.currentTimeMillis())
            .putString(KEY_CLAIMS_JSON, rawClaimsJson)
            .apply()
        Log.i(TAG, "Active SSO session securely stored in EncryptedSharedPreferences")
    }

    fun getSession(): SuperAppSession? {
        val idToken = sharedPreferences.getString(KEY_ID_TOKEN, null) ?: return null
        val accessToken = sharedPreferences.getString(KEY_ACCESS_TOKEN, null) ?: return null
        val deviceSecret = sharedPreferences.getString(KEY_DEVICE_SECRET, null) ?: return null
        val sid = sharedPreferences.getString(KEY_SID, null)
        val dpopJkt = sharedPreferences.getString(KEY_DPOP_JKT, "") ?: ""
        val createdAt = sharedPreferences.getLong(KEY_CREATED_AT, 0L)
        val claims = sharedPreferences.getString(KEY_CLAIMS_JSON, null)

        return SuperAppSession(
            idToken = idToken,
            accessToken = accessToken,
            deviceSecret = deviceSecret,
            sid = sid,
            dpopJkt = dpopJkt,
            createdAt = createdAt,
            rawClaimsJson = claims
        )
    }

    fun hasActiveSession(): Boolean {
        return getSession() != null
    }

    fun clearSession() {
        sharedPreferences.edit().clear().apply()
        Log.i(TAG, "SSO session cleared from EncryptedSharedPreferences")
    }

    companion object {
        private const val TAG = "SessionStorage"
        private const val PREFS_FILENAME = "superapp_sso_encrypted_prefs"

        private const val KEY_ID_TOKEN = "id_token"
        private const val KEY_ACCESS_TOKEN = "access_token"
        private const val KEY_DEVICE_SECRET = "device_secret"
        private const val KEY_SID = "sid"
        private const val KEY_DPOP_JKT = "dpop_jkt"
        private const val KEY_CREATED_AT = "created_at"
        private const val KEY_CLAIMS_JSON = "claims_json"
    }
}
