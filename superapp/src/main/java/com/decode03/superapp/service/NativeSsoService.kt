package com.decode03.superapp.service

import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import com.decode03.sso.Constants
import com.decode03.sso.ISSOSigningService
import com.decode03.superapp.auth.SessionStorage
import com.decode03.superapp.crypto.DpopProofGenerator
import com.decode03.superapp.crypto.HardwareKeyManager

/**
 * Signature-protected bound IPC service implementing OpenID Connect Native SSO 1.0.
 *
 * Enforces dual-layer security:
 * 1. Declared in AndroidManifest with android:protectionLevel="signature".
 * 2. Runtime verification: PackageManager.checkSignatures(myUid, callerUid) == SIGNATURE_MATCH.
 *
 * Exposes:
 * - requestSsoHandoff: Returns id_token, device_secret, and a fresh DPoP proof for POST /oauth2/token.
 * - signDpopProof: Signs subsequent resource requests (e.g. GET /oauth2/userinfo) using Hardware Key A.
 */
class NativeSsoService : Service() {

    private val binder = object : ISSOSigningService.Stub() {

        override fun requestSsoHandoff(childClientId: String, tokenEndpointUrl: String): Bundle {
            val callerUid = Binder.getCallingUid()
            enforceSignatureMatch(callerUid)

            Log.i(TAG, "SSO Handoff requested by client '$childClientId' (caller UID $callerUid)")
            val bundle = Bundle()

            try {
                val storage = SessionStorage(applicationContext)
                val session = storage.getSession()

                if (session == null) {
                    Log.w(TAG, "SSO Handoff rejected: No active Super App session found.")
                    bundle.putString(Constants.KEY_ERROR_CODE, Constants.ERR_NO_ACTIVE_SESSION)
                    bundle.putString(
                        Constants.KEY_ERROR_MESSAGE,
                        "No active Super App session found. Please sign in with eSignet on Super App first."
                    )
                    return bundle
                }

                // Sign fresh DPoP proof for Child App's POST tokenEndpoint call
                val dpopProof = DpopProofGenerator.createDpopProof(
                    htm = "POST",
                    htu = tokenEndpointUrl,
                    accessToken = null
                )

                bundle.putString(Constants.KEY_ID_TOKEN, session.idToken)
                bundle.putString(Constants.KEY_DEVICE_SECRET, session.deviceSecret)
                bundle.putString(Constants.KEY_DPOP_PROOF, dpopProof)
                bundle.putString(Constants.KEY_DPOP_JKT, session.dpopJkt)

                Log.i(TAG, "SSO Handoff credentials and DPoP proof successfully dispatched to child app.")
                return bundle
            } catch (e: Exception) {
                Log.e(TAG, "Error generating SSO handoff bundle: ${e.message}", e)
                bundle.putString(Constants.KEY_ERROR_CODE, Constants.ERR_HARDWARE_KEY_FAILURE)
                bundle.putString(Constants.KEY_ERROR_MESSAGE, "Hardware key signing failure: ${e.message}")
                return bundle
            }
        }

        override fun signDpopProof(htm: String, htu: String, accessToken: String?): String {
            val callerUid = Binder.getCallingUid()
            enforceSignatureMatch(callerUid)

            Log.d(TAG, "Resource DPoP proof requested by caller UID $callerUid for $htm $htu")
            return DpopProofGenerator.createDpopProof(
                htm = htm,
                htu = htu,
                accessToken = accessToken
            )
        }
    }

    override fun onBind(intent: Intent?): IBinder {
        Log.i(TAG, "NativeSsoService onBind called with action: ${intent?.action}")
        return binder
    }

    /**
     * Rejects any caller that does not possess the exact same X.509 signing certificate.
     */
    private fun enforceSignatureMatch(callerUid: Int) {
        val myUid = android.os.Process.myUid()
        if (callerUid == myUid) return

        val match = packageManager.checkSignatures(myUid, callerUid)
        if (match != PackageManager.SIGNATURE_MATCH) {
            val packages = packageManager.getPackagesForUid(callerUid)?.joinToString() ?: "unknown"
            val errorMsg = "SECURITY VIOLATION: Calling UID $callerUid ($packages) does NOT share the release signing certificate with Super App! Match result: $match"
            Log.e(TAG, errorMsg)
            throw SecurityException(errorMsg)
        }
    }

    companion object {
        private const val TAG = "NativeSsoService"
    }
}
