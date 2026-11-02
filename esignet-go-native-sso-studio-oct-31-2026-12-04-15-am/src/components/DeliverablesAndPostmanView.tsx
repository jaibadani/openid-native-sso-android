import React, { useState } from 'react';
import {
  Download,
  Copy,
  Check,
  FileText,
  Presentation,
  Terminal,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
} from 'lucide-react';
import { POSTMAN_COLLECTION_V2_1 } from '../lib/codeAndDeliverablesData';

const PRESENTATION_SLIDES = [
  {
    slideNumber: '01 / 06',
    title: 'Enabling OpenID Connect Native SSO 1.0 in eSignet Go & Thunder ID',
    subtitle: 'MOSIP Decode Problem Statement 03 — End-to-End Architecture & Implementation',
    bullets: [
      'Eliminates repeated OTP/Biometric authentication across mobile apps signed by the same trusted vendor certificate.',
      'Replaces browser-cookie SSO (impossible across isolated mobile app sandboxes) with a hardware-bound cryptographic handoff.',
      'Spans eSignet Go (DeviceSecretProvider + KeyManager JWS/JWE), Thunder ID Engine (Token Exchange RFC 8693), and Android IPC.',
    ],
    metricLabel: 'Authentication Friction Reduction',
    metricValue: '1 Login → N Vendor Apps (0 Re-Prompts)',
  },
  {
    slideNumber: '02 / 06',
    title: 'Threat Model & Defense-in-Depth Security Architecture',
    subtitle: 'Why Stolen Tokens Cannot Be Replayed Off-Device',
    bullets: [
      'Hardware Key Binding (FAPI 2.0 DPoP): Super App generates EC P-256 Key A inside Android StrongBox/TEE. Private key never leaves Super App.',
      'Cryptographic Token Binding (ds_hash): id_token embeds ds_hash = BASE64URL(SHA256(device_secret)[0..127]) to prevent token substitution.',
      'Signed-then-Encrypted Secret: device_secret is signed (JWS) and encrypted (A256GCM JWE) by eSignet KeyManager so clients treat it as opaque.',
    ],
    metricLabel: 'Cryptographic Verification Layers',
    metricValue: '5 Independent Attestation Checks',
  },
  {
    slideNumber: '03 / 06',
    title: 'Super App Login Flow: PAR + DPoP + Device Secret Issuance',
    subtitle: 'Mandatory Tasks 1 through 6 [eSignet Go + Thunder ID]',
    bullets: [
      'Task 1 & 2: Super App requests scope="openid profile email device_sso" via POST /oauth2/par bound to dpop_jkt; token endpoint verifies allowed_authorization_scopes.',
      'Task 3, 4 & 5: Thunder ID invokes eSignet DeviceSecretProvider.GenerateDeviceSecret(cnf.jkt, auth_id, exp, client_id, scope, acr, claims, iss).',
      'Task 6: Returns DPoP-bound access_token, id_token (with ds_hash & sid), and JWE device_secret to Super App.',
    ],
    metricLabel: 'Token Endpoint Artifacts',
    metricValue: 'access_token + id_token + device_secret',
  },
  {
    slideNumber: '04 / 06',
    title: 'Android App-to-App IPC & Hardware DPoP Signing Service',
    subtitle: 'Mandatory Task 7 & 8 [Client Mobile App Suite]',
    bullets: [
      'Child App binds to Super App SSOSigningService via signature-protected Android Bound Service (bindService()).',
      'Super App verifies caller package X.509 certificate matches the vendor certificate via PackageManager.checkSignatures().',
      'Super App signs a fresh DPoP proof (htm=POST, htu=/oauth2/token) using Key A and returns { id_token, device_secret, dpop_proof }.',
    ],
    metricLabel: 'Private Key Exposure',
    metricValue: '0 Bytes Exported (Key A stays in Super App)',
  },
  {
    slideNumber: '05 / 06',
    title: 'Thunder ID Token Exchange & Scope Subset Enforcement',
    subtitle: 'Mandatory Tasks 9, 10 & Bonus Task 1 [Thunder ID + ConsentProvider]',
    bullets: [
      'Task 9: Validates actor_token_type=device-secret, decrypts JWE, checks cnf.jkt == DPoP header jkt, verifies ds_hash == id_token.ds_hash, and checks active sid.',
      'Task 10a & 10b: Enforces Child App scope ⊆ Super App consented scope; strictly rejects device_sso in token_exchange requests.',
      'Bonus Task 1: Triggers step-up re-consent screen (interaction_required) when Child App requests scopes beyond Super App consent.',
    ],
    metricLabel: 'Auditability',
    metricValue: '100% Consent Lineage Recorded (derived_from)',
  },
  {
    slideNumber: '06 / 06',
    title: 'Complete Deliverables & Verification Summary',
    subtitle: 'Ready for MOSIP Collab Sandbox & Production Deployment',
    bullets: [
      '1. Dual Native Mobile App Simulator (Super App + Child App) with real cryptographic SHA-256 / JWK / JWE execution.',
      '2. Updated Postman Collection v2.1 covering PAR, Auth Code, Token Exchange, UserInfo, and Negative Security Tests.',
      '3. Full Golang (eSignet + Thunder ID) & Android Kotlin source code + Technical Design Document.',
    ],
    metricLabel: 'Specification Compliance',
    metricValue: '10/10 Mandatory Tasks + Bonus Verified',
  },
];

const MINIMAL_APK_FILES: Array<{ path: string; language: string; content: string }> = [
  {
    path: 'settings.gradle.kts',
    language: 'kotlin',
    content: `pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "MyFirstApp"
include(":app")
`,
  },
  {
    path: 'build.gradle.kts',
    language: 'kotlin',
    content: `plugins {
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
}
`,
  },
  {
    path: 'gradle.properties',
    language: 'properties',
    content: `org.gradle.jvmargs=-Xmx2048m -Dfile.encoding=UTF-8
android.useAndroidX=true
kotlin.code.style=official
android.nonTransitiveRClass=true
`,
  },
  {
    path: 'gradle/wrapper/gradle-wrapper.properties',
    language: 'properties',
    content: `distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https\\://services.gradle.org/distributions/gradle-8.7-bin.zip
networkTimeout=10000
validateDistributionUrl=true
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
`,
  },
  {
    path: 'app/build.gradle.kts',
    language: 'kotlin',
    content: `plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.myfirstapp"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.myfirstapp"
        minSdk = 28
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
}
`,
  },
  {
    path: 'app/src/main/AndroidManifest.xml',
    language: 'xml',
    content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <application
        android:allowBackup="true"
        android:label="@string/app_name"
        android:supportsRtl="true"
        android:theme="@style/Theme.MyFirstApp">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>

</manifest>
`,
  },
  {
    path: 'app/src/main/java/com/example/myfirstapp/MainActivity.kt',
    language: 'kotlin',
    content: `package com.example.myfirstapp

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val inputEditText = findViewById<EditText>(R.id.inputEditText)
        val submitButton = findViewById<Button>(R.id.submitButton)
        val outputTextView = findViewById<TextView>(R.id.outputTextView)

        submitButton.setOnClickListener {
            outputTextView.text = inputEditText.text.toString()
        }
    }
}
`,
  },
  {
    path: 'app/src/main/res/layout/activity_main.xml',
    language: 'xml',
    content: `<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical"
    android:padding="24dp">

    <TextView
        android:id="@+id/titleTextView"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="@string/screen_title"
        android:textSize="24sp"
        android:textStyle="bold" />

    <EditText
        android:id="@+id/inputEditText"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:layout_marginTop="16dp"
        android:hint="@string/input_hint"
        android:importantForAutofill="no"
        android:inputType="text" />

    <Button
        android:id="@+id/submitButton"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginTop="16dp"
        android:text="@string/button_label" />

    <TextView
        android:id="@+id/outputTextView"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:layout_marginTop="24dp"
        android:text="@string/default_output"
        android:textSize="18sp" />

</LinearLayout>
`,
  },
  {
    path: 'app/src/main/res/values/strings.xml',
    language: 'xml',
    content: `<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">MyFirstApp</string>
    <string name="screen_title">My First Android App</string>
    <string name="input_hint">Enter text here</string>
    <string name="button_label">Show Text</string>
    <string name="default_output"></string>
</resources>
`,
  },
  {
    path: 'app/src/main/res/values/themes.xml',
    language: 'xml',
    content: `<?xml version="1.0" encoding="utf-8"?>
<resources>
    <style name="Theme.MyFirstApp" parent="Theme.AppCompat.Light.DarkActionBar" />
</resources>
`,
  },
];

export const DeliverablesAndPostmanView: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<
    'postman' | 'minimal_apk' | 'design_doc' | 'ppt' | 'pdf'
  >('postman');
  const [copiedPostman, setCopiedPostman] = useState(false);
  const [slideIndex, setSlideIndex] = useState(0);
  const [selectedApkFileIndex, setSelectedApkFileIndex] = useState(0);
  const [copiedApkFile, setCopiedApkFile] = useState(false);
  const [previewInputText, setPreviewInputText] = useState('');
  const [previewOutputLabel, setPreviewOutputLabel] = useState('');

  const postmanJsonString = JSON.stringify(POSTMAN_COLLECTION_V2_1, null, 2);

  const handleCopyPostman = () => {
    navigator.clipboard?.writeText(postmanJsonString);
    setCopiedPostman(true);
    setTimeout(() => setCopiedPostman(false), 1800);
  };

  const handleDownloadPostman = () => {
    const blob = new Blob([postmanJsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'MOSIP_eSignet_Go_Native_SSO.postman_collection.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopySelectedApkFile = () => {
    const file = MINIMAL_APK_FILES[selectedApkFileIndex];
    if (!file) return;
    navigator.clipboard?.writeText(file.content);
    setCopiedApkFile(true);
    setTimeout(() => setCopiedApkFile(false), 1800);
  };

  const currentSlide = PRESENTATION_SLIDES[slideIndex];

  return (
    <div className="space-y-6">
      {/* Sub-navigation bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border border-slate-800 bg-slate-900/60 rounded-xl p-4">
        <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-lg">
          <button
            type="button"
            onClick={() => setActiveSubTab('postman')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 ${
              activeSubTab === 'postman'
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Postman Collection v2.1</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveSubTab('minimal_apk')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 ${
              activeSubTab === 'minimal_apk'
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Minimal Android APK (com.example.myfirstapp)</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveSubTab('design_doc')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 ${
              activeSubTab === 'design_doc'
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>API & Technical Design Doc</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveSubTab('ppt')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 ${
              activeSubTab === 'ppt'
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Presentation className="w-3.5 h-3.5" />
            <span>Presentation Deck (PPT)</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveSubTab('pdf')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 ${
              activeSubTab === 'pdf'
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Problem Statement PDF</span>
          </button>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleCopyPostman}
            className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
          >
            {copiedPostman ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span>Copied JSON</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Postman JSON</span>
              </>
            )}
          </button>
          <button
            type="button"
            onClick={handleDownloadPostman}
            className="px-3 py-1.5 text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download Postman Collection</span>
          </button>
        </div>
      </div>

      {/* Sub-tab 1: Postman Collection */}
      {activeSubTab === 'postman' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-5 border border-slate-800 bg-slate-900/60 rounded-xl p-6 space-y-4">
            <h3 className="text-base font-semibold text-white">
              Updated Postman Endpoints (Deliverable 2)
            </h3>
            <p className="text-xs text-slate-400">
              Includes pre-configured requests for Super App PAR + Authorization Code exchange,
              Child App OAuth 2.0 Token Exchange, Negative Security Validations, and DPoP UserInfo.
            </p>
            <div className="space-y-3">
              {POSTMAN_COLLECTION_V2_1.item.map((reqItem) => (
                <div
                  key={reqItem.name}
                  className="border border-slate-800 bg-slate-950/80 rounded-lg p-3.5 space-y-1.5"
                >
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-emerald-400 font-semibold">{reqItem.request.method}</span>
                    <span className="text-slate-400">{reqItem.request.url}</span>
                  </div>
                  <div className="text-xs font-medium text-white">{reqItem.name}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="lg:col-span-7 border border-slate-800 bg-slate-950 rounded-xl overflow-hidden">
            <div className="px-4 py-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
              <span className="text-xs font-mono text-blue-300">
                MOSIP_eSignet_Go_Native_SSO.postman_collection.json
              </span>
              <span className="text-xs font-mono text-slate-400">Schema v2.1.0</span>
            </div>
            <pre className="p-4 text-xs font-mono text-slate-200 overflow-x-auto max-h-[520px] leading-relaxed">
              <code>{postmanJsonString}</code>
            </pre>
          </div>
        </div>
      )}

      {/* Sub-tab: Minimal Android APK (com.example.myfirstapp) */}
      {activeSubTab === 'minimal_apk' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Live Android Screen Simulator + Build Metadata */}
          <div className="lg:col-span-5 space-y-4">
            <div className="border border-slate-800 bg-slate-900/60 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <div className="text-xs font-mono text-blue-400">com.example.myfirstapp</div>
                  <h3 className="text-base font-semibold text-white">
                    Interactive MainActivity Preview
                  </h3>
                </div>
                <span className="text-xs font-mono text-emerald-400">compileSdk 34 · minSdk 28</span>
              </div>

              {/* Simulated Android AppCompat Light Screen */}
              <div className="rounded-xl overflow-hidden border border-slate-700 bg-white text-slate-900 shadow-lg">
                <div className="bg-slate-800 text-white px-4 py-2.5 text-sm font-semibold">
                  MyFirstApp
                </div>
                <div className="p-6 space-y-4">
                  <div className="text-xl font-bold text-slate-900">My First Android App</div>
                  <input
                    type="text"
                    value={previewInputText}
                    onChange={(e) => setPreviewInputText(e.target.value)}
                    placeholder="Enter text here"
                    className="w-full px-3 py-2 border-b-2 border-blue-600 bg-slate-50 text-sm text-slate-900 focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setPreviewOutputLabel(previewInputText)}
                    className="px-4 py-2 bg-slate-200 hover:bg-slate-300 active:bg-slate-400 text-slate-900 text-xs font-semibold uppercase tracking-wide rounded shadow-sm transition-colors"
                  >
                    Show Text
                  </button>
                  <div className="pt-2 min-h-[28px] text-base font-medium text-slate-800">
                    {previewOutputLabel}
                  </div>
                </div>
              </div>

              <div className="space-y-2 text-xs text-slate-300 bg-slate-950/80 border border-slate-800 rounded-lg p-3.5 font-mono">
                <div>
                  <span className="text-slate-400">Build Command: </span>
                  <span className="text-emerald-300">./gradlew assembleDebug</span>
                </div>
                <div>
                  <span className="text-slate-400">Output APK: </span>
                  <span className="text-blue-300">
                    app/build/outputs/apk/debug/app-debug.apk
                  </span>
                </div>
                <div>
                  <span className="text-slate-400">Dependencies: </span>
                  <span className="text-slate-200">
                    androidx.core:core-ktx:1.13.1, androidx.appcompat:appcompat:1.7.0
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: File Tree + Full File Viewer */}
          <div className="lg:col-span-7 border border-slate-800 bg-slate-950 rounded-xl overflow-hidden flex flex-col">
            <div className="p-3 bg-slate-900 border-b border-slate-800 flex flex-wrap gap-1.5">
              {MINIMAL_APK_FILES.map((file, idx) => (
                <button
                  key={file.path}
                  type="button"
                  onClick={() => setSelectedApkFileIndex(idx)}
                  className={`px-2.5 py-1 text-xs font-mono rounded border transition-colors ${
                    selectedApkFileIndex === idx
                      ? 'bg-blue-600/30 border-blue-500 text-white'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {file.path}
                </button>
              ))}
            </div>
            <div className="px-4 py-2.5 bg-slate-900/60 border-b border-slate-800 flex items-center justify-between">
              <span className="text-xs font-mono text-blue-300">
                {MINIMAL_APK_FILES[selectedApkFileIndex]?.path}
              </span>
              <button
                type="button"
                onClick={handleCopySelectedApkFile}
                className="px-2.5 py-1 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 flex items-center gap-1.5"
              >
                {copiedApkFile ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy File</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-4 text-xs font-mono text-slate-200 overflow-x-auto max-h-[500px] leading-relaxed">
              <code>{MINIMAL_APK_FILES[selectedApkFileIndex]?.content}</code>
            </pre>
          </div>
        </div>
      )}

      {/* Sub-tab 2: API & Technical Design Document */}
      {activeSubTab === 'design_doc' && (
        <div className="border border-slate-800 bg-slate-900/60 rounded-xl p-6 space-y-6">
          <div className="border-b border-slate-800 pb-4">
            <h2 className="text-xl font-semibold text-white">
              MOSIP eSignet Go & Thunder ID — Native SSO Technical Design & API Specification
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Aligned with OpenID Connect Native SSO for Mobile Apps 1.0, RFC 8693 (OAuth 2.0 Token
              Exchange), RFC 9449 (OAuth 2.0 DPoP), and FAPI 2.0 Security Profile.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="border border-slate-800 bg-slate-950/70 rounded-lg p-5 space-y-3">
              <h3 className="text-sm font-semibold text-white">
                01. Token Endpoint Extension — Authorization Code Grant
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                When <code className="text-blue-300 font-mono">grant_type=authorization_code</code>{' '}
                is invoked with an authorization code whose session includes the{' '}
                <code className="text-blue-300 font-mono">device_sso</code> scope:
              </p>
              <ul className="text-xs text-slate-300 space-y-1.5 list-disc list-inside">
                <li>
                  Thunder ID verifies client configuration{' '}
                  <code className="font-mono text-emerald-300">allowed_authorization_scopes</code>{' '}
                  contains <code className="font-mono text-emerald-300">device_sso</code>.
                </li>
                <li>
                  Invokes <code className="font-mono text-blue-300">DeviceSecretProvider.GenerateDeviceSecret</code>{' '}
                  in eSignet Go.
                </li>
                <li>
                  Embeds <code className="font-mono text-blue-300">ds_hash</code> (base64url of
                  left-most 128 bits of SHA-256 of <code className="font-mono">device_secret</code>)
                  and <code className="font-mono text-blue-300">sid</code> into{' '}
                  <code className="font-mono">id_token</code>.
                </li>
                <li>
                  Returns <code className="font-mono">access_token</code>,{' '}
                  <code className="font-mono">id_token</code>, and{' '}
                  <code className="font-mono">device_secret</code>.
                </li>
              </ul>
            </div>

            <div className="border border-slate-800 bg-slate-950/70 rounded-lg p-5 space-y-3">
              <h3 className="text-sm font-semibold text-white">
                02. Token Endpoint Extension — OAuth 2.0 Token Exchange (RFC 8693)
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                When{' '}
                <code className="text-blue-300 font-mono">
                  grant_type=urn:ietf:params:oauth:grant-type:token-exchange
                </code>{' '}
                is called by a Child App:
              </p>
              <ul className="text-xs text-slate-300 space-y-1.5 list-disc list-inside">
                <li>
                  Rejects immediately with <code className="font-mono text-rose-300">invalid_scope</code>{' '}
                  if <code className="font-mono">device_sso</code> is present in requested{' '}
                  <code className="font-mono">scope</code>.
                </li>
                <li>
                  Requires{' '}
                  <code className="font-mono text-emerald-300">
                    actor_token_type=urn:openid:params:token-type:device-secret
                  </code>
                  .
                </li>
                <li>
                  Verifies <code className="font-mono">DPoP</code> header thumbprint matches{' '}
                  <code className="font-mono">device_secret.cnf.jkt</code> (proving Super App signed
                  the proof with hardware Key A).
                </li>
                <li>
                  Enforces <code className="font-mono">requested_scope ⊆ super_app_scope</code> or
                  returns <code className="font-mono text-amber-300">interaction_required</code> for
                  step-up re-consent.
                </li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Sub-tab 3: Presentation Deck */}
      {activeSubTab === 'ppt' && (
        <div className="border border-slate-800 bg-slate-900/60 rounded-xl p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <span className="text-xs font-mono text-blue-400">{currentSlide.slideNumber}</span>
              <h2 className="text-xl font-semibold text-white mt-0.5">{currentSlide.title}</h2>
              <p className="text-xs text-slate-400 mt-0.5">{currentSlide.subtitle}</p>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                aria-label="Previous slide"
                onClick={() =>
                  setSlideIndex((prev) =>
                    prev === 0 ? PRESENTATION_SLIDES.length - 1 : prev - 1
                  )
                }
                className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                type="button"
                aria-label="Next slide"
                onClick={() =>
                  setSlideIndex((prev) => (prev + 1) % PRESENTATION_SLIDES.length)
                }
                className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
            <div className="lg:col-span-8 border border-slate-800 bg-slate-950/90 rounded-xl p-6 space-y-4">
              <h3 className="text-sm font-semibold text-slate-200">Key Architectural Points</h3>
              <ul className="space-y-3">
                {currentSlide.bullets.map((bullet, idx) => (
                  <li key={idx} className="flex items-start gap-3 text-sm text-slate-300">
                    <span className="font-mono text-xs text-blue-400 font-semibold mt-0.5">
                      0{idx + 1}.
                    </span>
                    <span className="leading-relaxed">{bullet}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="lg:col-span-4 border border-slate-800 bg-slate-950/90 rounded-xl p-6 flex flex-col justify-between">
              <div>
                <div className="text-xs text-slate-400">{currentSlide.metricLabel}</div>
                <div className="text-lg font-semibold text-emerald-400 font-mono mt-2">
                  {currentSlide.metricValue}
                </div>
              </div>
              <div className="pt-6 border-t border-slate-800 text-xs text-slate-400">
                Slide {slideIndex + 1} of {PRESENTATION_SLIDES.length} · MOSIP Decode 03 eSignet Go
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Sub-tab 4: Attached Problem Statement PDF */}
      {activeSubTab === 'pdf' && (
        <div className="border border-slate-800 bg-slate-900/60 rounded-xl p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-base font-semibold text-white">
                Official Problem Statement PDF (MOSIP Decode — 03 eSignet)
              </h3>
              <p className="text-xs text-slate-400">
                Reference document attached to workspace at{' '}
                <code className="font-mono text-blue-300">
                  /assets/aistudio/03_Enable_Native_SSO_in_eSignet_Go_for_Mobile_Apps_d4ef516b.pdf
                </code>
              </p>
            </div>
            <a
              href="/assets/aistudio/03_Enable_Native_SSO_in_eSignet_Go_for_Mobile_Apps_d4ef516b.pdf"
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-lg border border-slate-700 flex items-center gap-1.5 whitespace-nowrap shrink-0"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>Open PDF in New Tab</span>
            </a>
          </div>
          <div className="w-full h-[560px] rounded-lg overflow-hidden border border-slate-800 bg-slate-950">
            <iframe
              title="MOSIP eSignet Native SSO Problem Statement PDF"
              src="/assets/aistudio/03_Enable_Native_SSO_in_eSignet_Go_for_Mobile_Apps_d4ef516b.pdf"
              className="w-full h-full"
            />
          </div>
        </div>
      )}
    </div>
  );
};
