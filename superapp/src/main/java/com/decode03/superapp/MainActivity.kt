package com.decode03.superapp

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.decode03.sso.Constants
import com.decode03.sso.SsoConfig
import com.decode03.superapp.auth.ParAuthManager
import com.decode03.superapp.auth.SessionStorage
import com.decode03.superapp.crypto.HardwareKeyManager
import com.decode03.superapp.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var sessionStorage: SessionStorage

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        SsoConfig.init(applicationContext)
        sessionStorage = SessionStorage(applicationContext)

        initServerUrlUi()
        initHardwareKeyInfo()
        setupListeners()
        refreshSessionUi()
        handleLaunchIntent(intent)
    }

    private fun initServerUrlUi() {
        binding.etServerUrl.setText(SsoConfig.issuerUrl)

        binding.btnApplyServerUrl.setOnClickListener {
            val url = binding.etServerUrl.text?.toString()?.trim()
            if (!url.isNullOrBlank()) {
                SsoConfig.updateIssuerUrl(applicationContext, url)
                appendLog("Updated Server URL to: ${SsoConfig.issuerUrl} (Discovery cache purged)")
                Toast.makeText(this, "Server URL updated", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnPresetCloud.setOnClickListener {
            binding.etServerUrl.setText(SsoConfig.PRESET_PUBLIC_TUNNEL)
            SsoConfig.updateIssuerUrl(applicationContext, SsoConfig.PRESET_PUBLIC_TUNNEL)
            appendLog("Switched to Live Public Tunnel: ${SsoConfig.PRESET_PUBLIC_TUNNEL}")
            Toast.makeText(this, "Set to Public Tunnel", Toast.LENGTH_SHORT).show()
        }

        binding.btnPresetWifi.setOnClickListener {
            binding.etServerUrl.setText(SsoConfig.PRESET_LOCAL_WIFI)
            SsoConfig.updateIssuerUrl(applicationContext, SsoConfig.PRESET_LOCAL_WIFI)
            appendLog("Switched to Local Wi-Fi Server: ${SsoConfig.PRESET_LOCAL_WIFI}")
            Toast.makeText(this, "Set to Wi-Fi 172.16.138.34", Toast.LENGTH_SHORT).show()
        }

        binding.btnPresetAdb.setOnClickListener {
            binding.etServerUrl.setText(SsoConfig.PRESET_LOCAL_ADB)
            SsoConfig.updateIssuerUrl(applicationContext, SsoConfig.PRESET_LOCAL_ADB)
            appendLog("Switched to Local Laptop (adb reverse): ${SsoConfig.PRESET_LOCAL_ADB}")
            Toast.makeText(this, "Set to Local 127.0.0.1", Toast.LENGTH_SHORT).show()
        }

        binding.btnPresetEmulator.setOnClickListener {
            binding.etServerUrl.setText(SsoConfig.PRESET_LOCAL_EMULATOR)
            SsoConfig.updateIssuerUrl(applicationContext, SsoConfig.PRESET_LOCAL_EMULATOR)
            appendLog("Switched to Android Emulator Host: ${SsoConfig.PRESET_LOCAL_EMULATOR}")
            Toast.makeText(this, "Set to Emulator 10.0.2.2", Toast.LENGTH_SHORT).show()
        }

        binding.btnPresetCollab.setOnClickListener {
            binding.etServerUrl.setText(SsoConfig.PRESET_COLLAB_SANDBOX)
            SsoConfig.updateIssuerUrl(applicationContext, SsoConfig.PRESET_COLLAB_SANDBOX)
            appendLog("Switched to MOSIP Collab Sandbox: ${SsoConfig.PRESET_COLLAB_SANDBOX}")
            Toast.makeText(this, "Set to Collab Sandbox", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        handleLaunchIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        refreshSessionUi()
    }

    private fun initHardwareKeyInfo() {
        try {
            val keyA = HardwareKeyManager.getOrCreateKeyA()
            val jkt = HardwareKeyManager.computeJwkThumbprint()
            val jwk = HardwareKeyManager.getPublicJwk()

            val details = buildString {
                append("Alias: ").append(Constants.KEYSTORE_ALIAS_HARDWARE_KEY_A).append("\n")
                append("Algorithm: ").append(keyA.public.algorithm).append(" (EC P-256)\n")
                append("RFC 7638 dpop_jkt: ").append(jkt).append("\n")
                append("Public JWK x: ").append(jwk.getString("x").take(16)).append("...\n")
                append("Public JWK y: ").append(jwk.getString("y").take(16)).append("...")
            }
            binding.tvHardwareKeyDetails.text = details
            appendLog("Hardware Key A loaded successfully from Keystore (jkt: $jkt)")
        } catch (e: Exception) {
            binding.tvHardwareKeyDetails.text = "Error initializing Key A: ${e.message}"
            appendLog("ERROR: Hardware Key A initialization failed: ${e.message}")
        }
    }

    private fun setupListeners() {
        binding.btnSignInEsignet.setOnClickListener {
            performParLogin()
        }

        binding.btnClearSession.setOnClickListener {
            sessionStorage.clearSession()
            appendLog("User logged out. EncryptedSharedPreferences session purged.")
            refreshSessionUi()
            Toast.makeText(this, "Session cleared", Toast.LENGTH_SHORT).show()
        }
    }

    private fun performParLogin() {
        binding.progressBar.visibility = View.VISIBLE
        binding.btnSignInEsignet.isEnabled = false
        appendLog("Initiating PAR flow to ${SsoConfig.issuerUrl}...")

        lifecycleScope.launch {
            val result = ParAuthManager.startParLogin(this@MainActivity)
            binding.progressBar.visibility = View.GONE
            binding.btnSignInEsignet.isEnabled = true

            result.onSuccess { requestUri ->
                appendLog("PAR Accepted! request_uri generated: $requestUri")
                appendLog("Opening Chrome Custom Tab for citizen authentication...")
            }.onFailure { error ->
                appendLog("PAR FAILED: ${error.message}")
                Toast.makeText(this@MainActivity, "PAR Failed: ${error.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun refreshSessionUi() {
        val session = sessionStorage.getSession()
        if (session != null) {
            binding.tvSessionBadge.text = getString(R.string.status_signed_in)
            binding.tvSessionBadge.setTextColor(getColor(android.R.color.holo_green_dark))
            binding.btnClearSession.visibility = View.VISIBLE

            val details = buildString {
                append("Status: ACTIVE\n")
                append("Session ID (sid): ").append(session.sid ?: "N/A").append("\n")
                append("Key A dpop_jkt: ").append(session.dpopJkt).append("\n")
                append("device_secret: ").append(session.deviceSecret.take(24)).append("... (Protected)\n")
                append("IPC Service: READY on ").append(Constants.ACTION_BIND_SSO).append("\n")
                append("Signature Security: Same release cert enforced")
            }
            binding.tvSessionDetails.text = details
        } else {
            binding.tvSessionBadge.text = getString(R.string.status_not_signed_in)
            binding.tvSessionBadge.setTextColor(getColor(android.R.color.holo_red_dark))
            binding.btnClearSession.visibility = View.GONE
            binding.tvSessionDetails.text = "Click 'Sign in with eSignet' to perform PAR + DPoP login."
        }
    }

    private fun handleLaunchIntent(intent: Intent?) {
        val success = intent?.getBooleanExtra("AUTH_SUCCESS", false) ?: false
        val error = intent?.getStringExtra("AUTH_ERROR")

        if (success) {
            appendLog("Authentication callback processed: Token exchange completed!")
            refreshSessionUi()
        } else if (error != null) {
            appendLog("Authentication callback error: $error")
        }
    }

    private fun appendLog(message: String) {
        val currentLogs = binding.tvConsoleLogs.text.toString()
        val timestamp = android.text.format.DateFormat.format("HH:mm:ss", System.currentTimeMillis())
        binding.tvConsoleLogs.text = "[$timestamp] $message\n$currentLogs"
    }
}
