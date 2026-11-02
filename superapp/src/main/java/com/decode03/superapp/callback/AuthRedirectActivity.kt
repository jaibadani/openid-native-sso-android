package com.decode03.superapp.callback

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.decode03.superapp.MainActivity
import com.decode03.superapp.auth.ParAuthManager
import kotlinx.coroutines.launch

/**
 * Handles incoming deep link callback from the Custom Tab:
 * "io.mosip.inji.superwallet://oauth2redirect?code=...&state=..."
 */
class AuthRedirectActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        val uri = intent?.data
        if (uri == null) {
            finish()
            return
        }

        Log.i(TAG, "Custom Tab redirect received: $uri")

        val error = uri.getQueryParameter("error")
        if (error != null) {
            val description = uri.getQueryParameter("error_description") ?: error
            Log.e(TAG, "Authentication rejected by eSignet: $description")
            Toast.makeText(this, "Sign in failed: $description", Toast.LENGTH_LONG).show()
            returnToMain(errorMessage = description)
            return
        }

        val code = uri.getQueryParameter("code")
        val state = uri.getQueryParameter("state")

        if (code.isNullOrBlank()) {
            Log.e(TAG, "Authorization callback missing 'code' parameter")
            Toast.makeText(this, "Missing authorization code", Toast.LENGTH_LONG).show()
            returnToMain(errorMessage = "Missing authorization code in redirect")
            return
        }

        if (ParAuthManager.pendingState != null && state != ParAuthManager.pendingState) {
            Log.e(TAG, "OAuth 2.0 state mismatch! Possible CSRF attack.")
            Toast.makeText(this, "Security error: State parameter mismatch", Toast.LENGTH_LONG).show()
            returnToMain(errorMessage = "Security error: State mismatch")
            return
        }

        // Exchange authorization code for tokens and device_secret
        lifecycleScope.launch {
            val result = ParAuthManager.exchangeCodeForTokens(applicationContext, code)
            result.onSuccess { session ->
                Log.i(TAG, "Session established with sid: ${session.sid}")
                Toast.makeText(this@AuthRedirectActivity, "Signed in with eSignet successfully!", Toast.LENGTH_SHORT).show()
                returnToMain(success = true)
            }.onFailure { ex ->
                Log.e(TAG, "Token exchange failed: ${ex.message}", ex)
                Toast.makeText(this@AuthRedirectActivity, "Token exchange failed: ${ex.message}", Toast.LENGTH_LONG).show()
                returnToMain(errorMessage = ex.message)
            }
        }
    }

    private fun returnToMain(success: Boolean = false, errorMessage: String? = null) {
        val mainIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra("AUTH_SUCCESS", success)
            putExtra("AUTH_ERROR", errorMessage)
        }
        startActivity(mainIntent)
        finish()
    }

    companion object {
        private const val TAG = "AuthRedirectActivity"
    }
}
