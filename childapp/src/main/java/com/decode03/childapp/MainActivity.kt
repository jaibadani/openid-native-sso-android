package com.decode03.childapp

import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.decode03.childapp.auth.TokenExchangeManager
import com.decode03.childapp.databinding.ActivityMainBinding
import com.decode03.childapp.model.CitizenClaims
import com.decode03.sso.SsoConfig
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var tokenExchangeManager: TokenExchangeManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        SsoConfig.init(applicationContext)
        tokenExchangeManager = TokenExchangeManager(applicationContext)

        initServerUrlUi()
        setupListeners()
    }

    private fun initServerUrlUi() {
        binding.etServerUrl.setText(SsoConfig.issuerUrl)

        binding.btnApplyServerUrl.setOnClickListener {
            val url = binding.etServerUrl.text?.toString()?.trim()
            if (!url.isNullOrBlank()) {
                SsoConfig.updateIssuerUrl(applicationContext, url)
                appendAuditLog("Updated Server URL to: ${SsoConfig.issuerUrl} (Discovery cache purged)")
                Toast.makeText(this, "Server URL updated", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnPresetCloud.setOnClickListener {
            binding.etServerUrl.setText(SsoConfig.PRESET_PUBLIC_TUNNEL)
            SsoConfig.updateIssuerUrl(applicationContext, SsoConfig.PRESET_PUBLIC_TUNNEL)
            appendAuditLog("Switched to Live Public Tunnel: ${SsoConfig.PRESET_PUBLIC_TUNNEL}")
            Toast.makeText(this, "Set to Public Tunnel", Toast.LENGTH_SHORT).show()
        }

        binding.btnPresetWifi.setOnClickListener {
            binding.etServerUrl.setText(SsoConfig.PRESET_LOCAL_WIFI)
            SsoConfig.updateIssuerUrl(applicationContext, SsoConfig.PRESET_LOCAL_WIFI)
            appendAuditLog("Switched to Local Wi-Fi Server: ${SsoConfig.PRESET_LOCAL_WIFI}")
            Toast.makeText(this, "Set to Wi-Fi 172.16.138.34", Toast.LENGTH_SHORT).show()
        }

        binding.btnPresetAdb.setOnClickListener {
            binding.etServerUrl.setText(SsoConfig.PRESET_LOCAL_ADB)
            SsoConfig.updateIssuerUrl(applicationContext, SsoConfig.PRESET_LOCAL_ADB)
            appendAuditLog("Switched to Local Laptop (adb reverse): ${SsoConfig.PRESET_LOCAL_ADB}")
            Toast.makeText(this, "Set to Local 127.0.0.1", Toast.LENGTH_SHORT).show()
        }

        binding.btnPresetEmulator.setOnClickListener {
            binding.etServerUrl.setText(SsoConfig.PRESET_LOCAL_EMULATOR)
            SsoConfig.updateIssuerUrl(applicationContext, SsoConfig.PRESET_LOCAL_EMULATOR)
            appendAuditLog("Switched to Android Emulator Host: ${SsoConfig.PRESET_LOCAL_EMULATOR}")
            Toast.makeText(this, "Set to Emulator 10.0.2.2", Toast.LENGTH_SHORT).show()
        }

        binding.btnPresetCollab.setOnClickListener {
            binding.etServerUrl.setText(SsoConfig.PRESET_COLLAB_SANDBOX)
            SsoConfig.updateIssuerUrl(applicationContext, SsoConfig.PRESET_COLLAB_SANDBOX)
            appendAuditLog("Switched to MOSIP Collab Sandbox: ${SsoConfig.PRESET_COLLAB_SANDBOX}")
            Toast.makeText(this, "Set to Collab Sandbox", Toast.LENGTH_SHORT).show()
        }
    }

    private fun setupListeners() {
        binding.btnSilentSso.setOnClickListener {
            performSilentSsoLogin()
        }
    }

    private fun performSilentSsoLogin() {
        binding.progressBar.visibility = View.VISIBLE
        binding.btnSilentSso.isEnabled = false
        binding.tvClaimsBadge.text = "Authenticating via Native SSO..."
        binding.tvClaimsBadge.setTextColor(getColor(android.R.color.darker_gray))
        appendAuditLog("Triggered Silent SSO login flow...")

        lifecycleScope.launch {
            val result = tokenExchangeManager.performSilentSso(object : TokenExchangeManager.AuditCallback {
                override fun onStep(stepName: String, details: String) {
                    appendAuditLog("[$stepName] $details")
                }
            })

            binding.progressBar.visibility = View.GONE
            binding.btnSilentSso.isEnabled = true

            result.onSuccess { claims ->
                displayClaims(claims)
                appendAuditLog("SUCCESS: Citizen profile retrieved seamlessly without prompting user!")
                Toast.makeText(this@MainActivity, "Signed in silently as ${claims.name ?: claims.sub}", Toast.LENGTH_SHORT).show()
            }.onFailure { error ->
                handleFailure(error)
            }
        }
    }

    private fun displayClaims(claims: CitizenClaims) {
        binding.tvClaimsBadge.text = getString(R.string.status_child_authenticated)
        binding.tvClaimsBadge.setTextColor(getColor(android.R.color.holo_green_dark))

        val claimsText = buildString {
            append("Name: ").append(claims.name ?: "N/A").append("\n")
            append("Subject (sub): ").append(claims.sub).append("\n")
            append("Email: ").append(claims.email ?: "N/A").append("\n")
            append("Phone: ").append(claims.phoneNumber ?: "N/A").append("\n")
            append("Birthdate: ").append(claims.birthdate ?: "N/A").append("\n")
            append("Gender: ").append(claims.gender ?: "N/A").append("\n\n")
            append("Raw Scoped Claims:\n").append(claims.rawJson.toString(2))
        }
        binding.tvClaimsDetails.text = claimsText
    }

    private fun handleFailure(error: Throwable) {
        val errorMessage = error.message ?: "Authentication failed"
        binding.tvClaimsBadge.text = "SSO Authentication Failed"
        binding.tvClaimsBadge.setTextColor(getColor(android.R.color.holo_red_dark))

        val friendlyMessage = when {
            errorMessage.contains("NO_ACTIVE_SESSION", ignoreCase = true) ->
                "No active Super App session found.\nPlease open Super App and tap 'Sign in with eSignet' first."
            errorMessage.contains("SIGNATURE MISMATCH", ignoreCase = true) ->
                "Security Error: X.509 signature mismatch.\nSuper App and Child App must be signed with the exact same keystore."
            errorMessage.contains("device_sso", ignoreCase = true) ->
                "Security Policy Error: Child App is forbidden from requesting 'device_sso' scope."
            errorMessage.contains("expired", ignoreCase = true) ->
                "Session Expired: The device secret or session has expired.\nPlease re-authenticate on Super App."
            else -> errorMessage
        }

        binding.tvClaimsDetails.text = friendlyMessage
        appendAuditLog("ERROR: $friendlyMessage")
        Toast.makeText(this, friendlyMessage, Toast.LENGTH_LONG).show()
    }

    private fun appendAuditLog(message: String) {
        val current = binding.tvAuditLogs.text.toString()
        val time = android.text.format.DateFormat.format("HH:mm:ss", System.currentTimeMillis())
        binding.tvAuditLogs.text = "[$time] $message\n$current"
    }

    override fun onDestroy() {
        super.onDestroy()
        tokenExchangeManager.cleanUp()
    }
}
