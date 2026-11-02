package com.decode03.childapp.ipc

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import com.decode03.sso.Constants
import com.decode03.sso.ISSOSigningService
import com.decode03.sso.ProtocolException
import com.decode03.sso.SsoConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Handles binding to Super App's signature-protected NativeSsoService.
 *
 * Enforces X.509 certificate equality before establishing connection:
 * PackageManager.checkSignatures(myUid, superAppUid) == SIGNATURE_MATCH.
 */
class SuperAppServiceConnector(private val context: Context) {

    private var ssoService: ISSOSigningService? = null
    private var isBound = false

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            Log.i(TAG, "Connected to Super App ISSOSigningService")
            ssoService = ISSOSigningService.Stub.asInterface(service)
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            Log.w(TAG, "Disconnected from Super App ISSOSigningService")
            ssoService = null
            isBound = false
        }
    }

    /**
     * Binds to Super App's service, verifying that both apps are signed with the same keystore.
     */
    suspend fun connect(): Result<ISSOSigningService> = withContext(Dispatchers.IO) {
        if (ssoService != null) {
            return@withContext Result.success(ssoService!!)
        }

        try {
            // 1. Signature Check against Super App's package
            verifySuperAppSignature()

            // 2. Establish IPC binding
            suspendCancellableCoroutine { continuation ->
                val intent = Intent(Constants.ACTION_BIND_SSO).apply {
                    `package` = SsoConfig.SUPER_APP_PACKAGE_NAME
                }

                val conn = object : ServiceConnection {
                    override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                        val boundService = ISSOSigningService.Stub.asInterface(service)
                        ssoService = boundService
                        isBound = true
                        if (continuation.isActive) {
                            continuation.resume(Result.success(boundService))
                        }
                    }

                    override fun onServiceDisconnected(name: ComponentName?) {
                        ssoService = null
                        isBound = false
                    }

                    override fun onBindingDied(name: ComponentName?) {
                        ssoService = null
                        isBound = false
                        if (continuation.isActive) {
                            continuation.resumeWithException(
                                ProtocolException("Binding to Super App service died unexpectedly.")
                            )
                        }
                    }
                }

                val success = context.bindService(intent, conn, Context.BIND_AUTO_CREATE)
                if (!success) {
                    if (continuation.isActive) {
                        continuation.resume(
                            Result.failure(
                                ProtocolException(
                                    "Failed to bind to Super App service. Verify that Super App is installed and signed with the same keystore."
                                )
                            )
                        )
                    }
                }

                continuation.invokeOnCancellation {
                    if (isBound) {
                        try {
                            context.unbindService(conn)
                        } catch (e: Exception) {
                            Log.w(TAG, "Error unbinding on cancellation: ${e.message}")
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Connection to Super App failed: ${e.message}", e)
            Result.failure(e)
        }
    }

    /**
     * Verifies that Super App is installed and shares the exact same release signing certificate.
     */
    fun verifySuperAppSignature() {
        val pm = context.packageManager
        val myUid = android.os.Process.myUid()

        val superAppPackageInfo = try {
            pm.getPackageInfo(SsoConfig.SUPER_APP_PACKAGE_NAME, 0)
        } catch (e: PackageManager.NameNotFoundException) {
            throw ProtocolException("Super App (${SsoConfig.SUPER_APP_PACKAGE_NAME}) is not installed on this device.")
        }

        val targetUid = superAppPackageInfo.applicationInfo.uid
        val signatureMatch = pm.checkSignatures(myUid, targetUid)

        if (signatureMatch != PackageManager.SIGNATURE_MATCH) {
            throw SecurityException(
                "SIGNATURE MISMATCH: Super App (UID $targetUid) and Child App (UID $myUid) " +
                "are NOT signed with the same certificate! checkSignatures() returned: $signatureMatch."
            )
        }

        Log.i(TAG, "X.509 Signature check PASSED: Super App and Child App share identical signing certificates.")
    }

    /**
     * Calls requestSsoHandoff on Super App's bound service.
     */
    suspend fun getSsoHandoffBundle(tokenEndpointUrl: String): Bundle = withContext(Dispatchers.IO) {
        val service = connect().getOrThrow()
        val bundle = service.requestSsoHandoff(SsoConfig.childAppClientId, tokenEndpointUrl)

        if (bundle.containsKey(Constants.KEY_ERROR_CODE)) {
            val errorCode = bundle.getString(Constants.KEY_ERROR_CODE)
            val errorMessage = bundle.getString(Constants.KEY_ERROR_MESSAGE) ?: "Unknown error"
            throw ProtocolException("Super App SSO Handoff failed [$errorCode]: $errorMessage")
        }

        bundle
    }

    /**
     * Calls signDpopProof on Super App's bound service to sign resource requests (e.g. GET /oauth2/userinfo).
     */
    suspend fun signDpopProof(htm: String, htu: String, accessToken: String?): String = withContext(Dispatchers.IO) {
        val service = connect().getOrThrow()
        service.signDpopProof(htm, htu, accessToken)
    }

    fun disconnect() {
        if (isBound) {
            try {
                context.unbindService(connection)
            } catch (e: Exception) {
                Log.w(TAG, "Error unbinding service: ${e.message}")
            }
            isBound = false
            ssoService = null
        }
    }

    companion object {
        private const val TAG = "SuperAppConnector"
    }
}
