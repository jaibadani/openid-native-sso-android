/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef } from 'react';
import {
  Shield,
  Smartphone,
  CheckCircle2,
  AlertCircle,
  Lock,
  KeyRound,
  ArrowRight,
  RotateCcw,
  Zap,
  ChevronDown,
  ChevronUp,
  UserCheck,
  FileCode2,
  Sliders,
} from 'lucide-react';
import {
  NativeSsoServerEngine,
  SUPER_APP_KEY_A,
  ROGUE_DEVICE_KEY_X,
  DEFAULT_VENDOR_CERT_SHA256,
  UNTRUSTED_VENDOR_CERT_SHA256,
  CITIZEN_DIRECTORY,
  computeJwkThumbprint,
  computePkceChallenge,
  computeDsHash,
  createDpopProof,
  type ProtocolSequenceStep,
  type ConsentAuditRecord,
  type RegisteredOidcClient,
} from './lib/nativeSsoEngine';
import { CryptographicInspectorView } from './components/CryptographicInspectorView';
import { CodeAndArchitectureView } from './components/CodeAndArchitectureView';
import { DeliverablesAndPostmanView } from './components/DeliverablesAndPostmanView';

type ActiveNavTab = 'lab' | 'inspector' | 'code' | 'deliverables';

type SuperAppScreen =
  | 'LOGIN'
  | 'BROWSER_UIN'
  | 'BROWSER_OTP'
  | 'BROWSER_CONSENT'
  | 'AUTHENTICATED_HOME';

type ChildAppScreen = 'LOGIN' | 'BONUS_RECONSENT' | 'AUTHENTICATED_HOME';

export default function App() {
  const engineRef = useRef<NativeSsoServerEngine>(new NativeSsoServerEngine());

  const [activeTab, setActiveTab] = useState<ActiveNavTab>('lab');

  // Registered OIDC clients state (mirrored from engine for live UI reactivity)
  const [registeredClients, setRegisteredClients] = useState<Record<string, RegisteredOidcClient>>(
    () => structuredClone(engineRef.current.registeredClients)
  );

  // Super App Flow State (Steps 1-9 of User Journey)
  const [superScreen, setSuperScreen] = useState<SuperAppScreen>('LOGIN');
  const [superSelectedScopes, setSuperSelectedScopes] = useState<string[]>([
    'openid',
    'profile',
    'email',
    'device_sso',
  ]);
  const [superUin, setSuperUin] = useState<string>('8294017365');
  const [superOtp, setSuperOtp] = useState<string>('111111');
  const [superSelectedClaims, setSuperSelectedClaims] = useState<string[]>([
    'name',
    'email',
    'phone_number',
    'birthdate',
  ]);
  const [activeParUri, setActiveParUri] = useState<string>('');
  const [activeAuthId, setActiveAuthId] = useState<string>('');
  const [pkceVerifier] = useState<string>('pkce-verifier-mosip-inji-super-wallet-fapi2-99887766');
  const [superError, setSuperError] = useState<string | null>(null);

  const [superTokens, setSuperTokens] = useState<{
    access_token?: string;
    id_token?: string;
    device_secret?: string;
    dpop_proof?: string;
    scope?: string;
  }>({});
  const [superUserInfo, setSuperUserInfo] = useState<Record<string, unknown> | null>(null);

  // Child App Flow State (Steps 10-11 of User Journey)
  const [childScreen, setChildScreen] = useState<ChildAppScreen>('LOGIN');
  const [childSelectedScopes, setChildSelectedScopes] = useState<string[]>(['openid', 'profile']);
  const [childTokens, setChildTokens] = useState<{
    access_token?: string;
    id_token?: string;
    dpop_proof?: string;
    scope?: string;
  }>({});
  const [childUserInfo, setChildUserInfo] = useState<Record<string, unknown> | null>(null);
  const [childError, setChildError] = useState<{ code: string; message: string } | null>(null);
  const [pendingReconsentScopes, setPendingReconsentScopes] = useState<string[]>([]);

  // Security & Attack Simulation Controls
  const [vendorCertMatch, setVendorCertMatch] = useState<boolean>(true);
  const [useHardwareKeyA, setUseHardwareKeyA] = useState<boolean>(true);
  const [bonusReconsentEnabled, setBonusReconsentEnabled] = useState<boolean>(true);

  // Protocol Sequence Logs & Consent Audit History
  const [sequenceLogs, setSequenceLogs] = useState<ProtocolSequenceStep[]>([]);
  const [consentAuditLog, setConsentAuditLog] = useState<ConsentAuditRecord[]>([]);
  const [expandedStepId, setExpandedStepId] = useState<string | null>(null);

  const syncEngineLogs = () => {
    setSequenceLogs([...engineRef.current.sequenceLogs].reverse());
    setConsentAuditLog([...engineRef.current.consentAuditLog]);
  };

  const hardwareJkt = computeJwkThumbprint(SUPER_APP_KEY_A);

  // Toggle Super App requested scope
  const toggleSuperScope = (scopeName: string) => {
    if (scopeName === 'openid') return;
    setSuperSelectedScopes((prev) =>
      prev.includes(scopeName) ? prev.filter((s) => s !== scopeName) : [...prev, scopeName]
    );
  };

  // Toggle Child App requested scope
  const toggleChildScope = (scopeName: string) => {
    if (scopeName === 'openid') return;
    setChildSelectedScopes((prev) =>
      prev.includes(scopeName) ? prev.filter((s) => s !== scopeName) : [...prev, scopeName]
    );
  };

  // Toggle SuperApp Consent claim
  const toggleConsentClaim = (claimName: string) => {
    setSuperSelectedClaims((prev) =>
      prev.includes(claimName) ? prev.filter((c) => c !== claimName) : [...prev, claimName]
    );
  };

  // Toggle device_sso in Registered Client allowed_authorization_scopes (Task 2 / Task 9.a.iii.3)
  const handleToggleClientDeviceSsoScope = (clientId: string) => {
    const client = engineRef.current.registeredClients[clientId];
    if (!client) return;
    if (client.allowed_authorization_scopes.includes('device_sso')) {
      client.allowed_authorization_scopes = client.allowed_authorization_scopes.filter(
        (s) => s !== 'device_sso'
      );
    } else {
      client.allowed_authorization_scopes = [...client.allowed_authorization_scopes, 'device_sso'];
    }
    setRegisteredClients(structuredClone(engineRef.current.registeredClients));
  };

  // User Journey Step 2 & 3: Tap "Sign in with eSignet" -> Execute PAR + Open Browser Authorize
  const handleStartSuperAppLogin = () => {
    setSuperError(null);
    const engine = engineRef.current;
    const scopeStr = superSelectedScopes.join(' ');
    const codeChallenge = computePkceChallenge(pkceVerifier);

    const parRes = engine.handleParRequest({
      client_id: 'mosip-super-wallet-android',
      scope: scopeStr,
      redirect_uri: 'io.mosip.inji.superwallet://oauth2redirect',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      dpop_jkt: hardwareJkt,
    });

    if (parRes.status !== 201 || !parRes.body.request_uri) {
      setSuperError(parRes.body.error_description || 'PAR request failed');
      syncEngineLogs();
      return;
    }

    setActiveParUri(parRes.body.request_uri);

    const authRes = engine.startAuthorizeSession({
      client_id: 'mosip-super-wallet-android',
      request_uri: parRes.body.request_uri,
    });

    if (authRes.status !== 200 || !authRes.body.auth_id) {
      setSuperError(authRes.body.error_description || 'Authorize request failed');
      syncEngineLogs();
      return;
    }

    setActiveAuthId(authRes.body.auth_id);
    setSuperScreen('BROWSER_UIN');
    syncEngineLogs();
  };

  // User Journey Step 5: Enter UIN & Tap "Send OTP"
  const handleSendOtp = (e: React.FormEvent) => {
    e.preventDefault();
    setSuperError(null);
    if (!CITIZEN_DIRECTORY[superUin.trim()]) {
      setSuperError(
        `UIN '${superUin}' not found in MOSIP Sandbox. Use 8294017365 (Ananya) or 4510928374 (Rohan).`
      );
      return;
    }
    setSuperScreen('BROWSER_OTP');
  };

  // User Journey Step 6: Enter OTP & Tap "Submit"
  const handleVerifyOtp = (e: React.FormEvent) => {
    e.preventDefault();
    setSuperError(null);
    const engine = engineRef.current;
    const otpRes = engine.authenticateWithOtp({
      auth_id: activeAuthId,
      uin: superUin,
      otp: superOtp,
    });
    syncEngineLogs();

    if (otpRes.status !== 200) {
      setSuperError(otpRes.body.error_description || 'OTP verification failed');
      return;
    }
    setSuperScreen('BROWSER_CONSENT');
  };

  // User Journey Step 8 & 9: Review Claims on Consent Screen & Tap "Allow" -> Issue Code -> Exchange Token + Device Secret -> Fetch /userinfo
  const handleAllowConsent = () => {
    setSuperError(null);
    const engine = engineRef.current;

    const consentRes = engine.submitConsent({
      auth_id: activeAuthId,
      accepted_scopes: superSelectedScopes,
      accepted_claims: superSelectedClaims,
    });

    if (consentRes.status !== 200 || !consentRes.body.code) {
      setSuperError(consentRes.body.error_description || 'Consent submission failed');
      syncEngineLogs();
      return;
    }

    // Create DPoP proof signed by Super App's hardware Key A
    const tokenDpopProof = createDpopProof({
      jwk: SUPER_APP_KEY_A,
      htm: 'POST',
      htu: 'https://esignet.mosip.net/oauth2/token',
    });

    const tokenRes = engine.handleTokenEndpoint({
      grant_type: 'authorization_code',
      client_id: 'mosip-super-wallet-android',
      code: consentRes.body.code,
      redirect_uri: 'io.mosip.inji.superwallet://oauth2redirect',
      code_verifier: pkceVerifier,
      dpop_proof: tokenDpopProof,
    });

    if (tokenRes.status !== 200 || !tokenRes.body.access_token) {
      setSuperError(
        `${tokenRes.body.error}: ${tokenRes.body.error_description || 'Token endpoint failed'}`
      );
      syncEngineLogs();
      return;
    }

    // Call GET /oauth2/userinfo with DPoP proof bound to access_token
    const userInfoDpop = createDpopProof({
      jwk: SUPER_APP_KEY_A,
      htm: 'GET',
      htu: 'https://esignet.mosip.net/oauth2/userinfo',
      accessToken: tokenRes.body.access_token,
    });

    const userInfoRes = engine.handleUserInfo({
      access_token: tokenRes.body.access_token,
      dpop_proof: userInfoDpop,
    });

    setSuperTokens({
      access_token: tokenRes.body.access_token,
      id_token: tokenRes.body.id_token,
      device_secret: tokenRes.body.device_secret,
      dpop_proof: tokenDpopProof,
      scope: tokenRes.body.scope,
    });
    setSuperUserInfo(userInfoRes.body);
    setSuperScreen('AUTHENTICATED_HOME');
    syncEngineLogs();
  };

  // User Journey Step 10 & 11: Open Second Mobile App & Tap "Sign In" -> IPC bindService() -> Token Exchange -> Silent Login
  const handleChildAppSignIn = (reconsentApproved = false) => {
    setChildError(null);
    const engine = engineRef.current;

    // Step 1: Android IPC bindService() to Super App SSOSigningService (Mandatory Task 7)
    const ipcRes = engine.simulateAndroidBindServiceIpc({
      super_app_cert_sha256: DEFAULT_VENDOR_CERT_SHA256,
      child_app_cert_sha256: vendorCertMatch
        ? DEFAULT_VENDOR_CERT_SHA256
        : UNTRUSTED_VENDOR_CERT_SHA256,
      child_package_name: vendorCertMatch
        ? 'io.mosip.gov.mparivahan'
        : 'com.untrusted.thirdparty.app',
      stored_id_token: superTokens.id_token,
      stored_device_secret: superTokens.device_secret,
      htm: 'POST',
      htu: 'https://esignet.mosip.net/oauth2/token',
      signing_key: useHardwareKeyA ? SUPER_APP_KEY_A : ROGUE_DEVICE_KEY_X,
    });

    if (!ipcRes.allowed || !ipcRes.dpop_proof) {
      setChildError({
        code: 'ipc_security_exception',
        message: ipcRes.error || 'Android bindService() IPC rejected',
      });
      syncEngineLogs();
      return;
    }

    // Step 2: POST /oauth2/token with grant_type=urn:ietf:params:oauth:grant-type:token-exchange (Mandatory Task 8, 9, 10)
    const childScopeStr = childSelectedScopes.join(' ');
    const txRes = engine.handleTokenEndpoint({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: 'mosip-mparivahan-transit',
      subject_token: ipcRes.id_token,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      actor_token: ipcRes.device_secret,
      actor_token_type: 'urn:openid:params:token-type:device-secret',
      audience: 'https://esignet.mosip.net',
      scope: childScopeStr,
      dpop_proof: ipcRes.dpop_proof,
      bonus_reconsent_mode: bonusReconsentEnabled,
      reconsent_approved: reconsentApproved,
    });

    // Bonus Task 1: Check if interaction_required was returned for step-up re-consent
    if (txRes.status === 400 && txRes.body.error === 'interaction_required') {
      setPendingReconsentScopes(txRes.body.required_scopes_diff || []);
      setChildScreen('BONUS_RECONSENT');
      syncEngineLogs();
      return;
    }

    if (txRes.status !== 200 || !txRes.body.access_token) {
      setChildError({
        code: txRes.body.error || 'token_exchange_failed',
        message: txRes.body.error_description || 'Token exchange rejected by Thunder ID Engine',
      });
      syncEngineLogs();
      return;
    }

    // Step 3: Child App requests DPoP proof for GET /oauth2/userinfo from Super App Key A
    const userInfoIpc = engine.simulateAndroidBindServiceIpc({
      super_app_cert_sha256: DEFAULT_VENDOR_CERT_SHA256,
      child_app_cert_sha256: DEFAULT_VENDOR_CERT_SHA256,
      child_package_name: 'io.mosip.gov.mparivahan',
      htm: 'GET',
      htu: 'https://esignet.mosip.net/oauth2/userinfo',
      access_token_for_ath: txRes.body.access_token,
      signing_key: SUPER_APP_KEY_A,
    });

    const userInfoRes = engine.handleUserInfo({
      access_token: txRes.body.access_token,
      dpop_proof: userInfoIpc.dpop_proof!,
    });

    setChildTokens({
      access_token: txRes.body.access_token,
      id_token: txRes.body.id_token,
      dpop_proof: ipcRes.dpop_proof,
      scope: txRes.body.scope,
    });
    setChildUserInfo(userInfoRes.body);
    setChildScreen('AUTHENTICATED_HOME');
    syncEngineLogs();
  };

  // One-click End-to-End Automated Demo (Executes Steps 1–11 across Super App & Child App)
  const handleRunFullEndToEndDemo = () => {
    setActiveTab('lab');
    setSuperError(null);
    setChildError(null);
    setVendorCertMatch(true);
    setUseHardwareKeyA(true);

    const engine = engineRef.current;
    const superScopeList = ['openid', 'profile', 'email', 'device_sso'];
    const childScopeList = ['openid', 'profile'];
    setSuperSelectedScopes(superScopeList);
    setChildSelectedScopes(childScopeList);

    // 1. PAR
    const parRes = engine.handleParRequest({
      client_id: 'mosip-super-wallet-android',
      scope: superScopeList.join(' '),
      redirect_uri: 'io.mosip.inji.superwallet://oauth2redirect',
      code_challenge: computePkceChallenge(pkceVerifier),
      code_challenge_method: 'S256',
      dpop_jkt: hardwareJkt,
    });
    const reqUri = parRes.body.request_uri!;
    setActiveParUri(reqUri);

    // 2. Authorize
    const authRes = engine.startAuthorizeSession({
      client_id: 'mosip-super-wallet-android',
      request_uri: reqUri,
    });
    const authId = authRes.body.auth_id!;
    setActiveAuthId(authId);

    // 3. OTP
    engine.authenticateWithOtp({
      auth_id: authId,
      uin: superUin,
      otp: '111111',
    });

    // 4. Consent
    const consentRes = engine.submitConsent({
      auth_id: authId,
      accepted_scopes: superScopeList,
      accepted_claims: ['name', 'email', 'phone_number', 'birthdate'],
    });

    // 5. Super App Token Exchange (authorization_code)
    const superDpop = createDpopProof({
      jwk: SUPER_APP_KEY_A,
      htm: 'POST',
      htu: 'https://esignet.mosip.net/oauth2/token',
    });
    const superTokenRes = engine.handleTokenEndpoint({
      grant_type: 'authorization_code',
      client_id: 'mosip-super-wallet-android',
      code: consentRes.body.code!,
      redirect_uri: 'io.mosip.inji.superwallet://oauth2redirect',
      code_verifier: pkceVerifier,
      dpop_proof: superDpop,
    });

    const superUiDpop = createDpopProof({
      jwk: SUPER_APP_KEY_A,
      htm: 'GET',
      htu: 'https://esignet.mosip.net/oauth2/userinfo',
      accessToken: superTokenRes.body.access_token!,
    });
    const superUiRes = engine.handleUserInfo({
      access_token: superTokenRes.body.access_token!,
      dpop_proof: superUiDpop,
    });

    setSuperTokens({
      access_token: superTokenRes.body.access_token,
      id_token: superTokenRes.body.id_token,
      device_secret: superTokenRes.body.device_secret,
      dpop_proof: superDpop,
      scope: superTokenRes.body.scope,
    });
    setSuperUserInfo(superUiRes.body);
    setSuperScreen('AUTHENTICATED_HOME');

    // 6. Child App IPC bindService() + Token Exchange Silent SSO
    const ipcRes = engine.simulateAndroidBindServiceIpc({
      super_app_cert_sha256: DEFAULT_VENDOR_CERT_SHA256,
      child_app_cert_sha256: DEFAULT_VENDOR_CERT_SHA256,
      child_package_name: 'io.mosip.gov.mparivahan',
      stored_id_token: superTokenRes.body.id_token,
      stored_device_secret: superTokenRes.body.device_secret,
      htm: 'POST',
      htu: 'https://esignet.mosip.net/oauth2/token',
      signing_key: SUPER_APP_KEY_A,
    });

    const childTxRes = engine.handleTokenEndpoint({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: 'mosip-mparivahan-transit',
      subject_token: ipcRes.id_token,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      actor_token: ipcRes.device_secret,
      actor_token_type: 'urn:openid:params:token-type:device-secret',
      audience: 'https://esignet.mosip.net',
      scope: childScopeList.join(' '),
      dpop_proof: ipcRes.dpop_proof!,
    });

    const childUiIpc = engine.simulateAndroidBindServiceIpc({
      super_app_cert_sha256: DEFAULT_VENDOR_CERT_SHA256,
      child_app_cert_sha256: DEFAULT_VENDOR_CERT_SHA256,
      child_package_name: 'io.mosip.gov.mparivahan',
      htm: 'GET',
      htu: 'https://esignet.mosip.net/oauth2/userinfo',
      access_token_for_ath: childTxRes.body.access_token!,
      signing_key: SUPER_APP_KEY_A,
    });

    const childUiRes = engine.handleUserInfo({
      access_token: childTxRes.body.access_token!,
      dpop_proof: childUiIpc.dpop_proof!,
    });

    setChildTokens({
      access_token: childTxRes.body.access_token,
      id_token: childTxRes.body.id_token,
      dpop_proof: ipcRes.dpop_proof,
      scope: childTxRes.body.scope,
    });
    setChildUserInfo(childUiRes.body);
    setChildScreen('AUTHENTICATED_HOME');
    syncEngineLogs();
  };

  // Session Revocation & Logout (POST /oauth2/revoke)
  const handleRevokeSuperAppSession = () => {
    const engine = engineRef.current;
    engine.handleRevokeOrLogout({
      device_secret: superTokens.device_secret,
      id_token: superTokens.id_token,
      sid: activeAuthId || undefined,
      client_id: 'mosip-super-wallet-android',
    });
    // Reset Child App to login screen so user can immediately test that token exchange now fails with invalid_grant
    setChildScreen('LOGIN');
    setChildTokens({});
    setChildUserInfo(null);
    setChildError({
      code: 'session_revoked_ready_to_test',
      message:
        'POST /oauth2/revoke executed: device_secret JTI blacklisted and session SID invalidated. Click Sign In below to verify Token Exchange now rejects with invalid_grant.',
    });
    syncEngineLogs();
  };

  // Reset / Sign Out of Both Apps
  const handleResetAll = () => {
    engineRef.current = new NativeSsoServerEngine();
    setRegisteredClients(structuredClone(engineRef.current.registeredClients));
    setSuperScreen('LOGIN');
    setChildScreen('LOGIN');
    setSuperTokens({});
    setChildTokens({});
    setSuperUserInfo(null);
    setChildUserInfo(null);
    setSuperError(null);
    setChildError(null);
    setSequenceLogs([]);
    setConsentAuditLog([]);
  };

  const currentDsHash = superTokens.device_secret
    ? computeDsHash(superTokens.device_secret)
    : null;

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col">
      {/* Top Bar Contract: Strictly 3 zones separated by gap-8 */}
      <header className="flex items-center justify-between gap-8 px-6 py-4 border-b border-slate-800/90 bg-slate-950/90 sticky top-0 z-30 backdrop-blur-md">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveTab('lab');
          }}
          className="text-lg font-bold tracking-tight text-white whitespace-nowrap shrink-0"
        >
          eSignet Go Native SSO
        </a>

        {/* Zone 2: 4 concise single-line text navigation links */}
        <nav
          aria-label="Primary Navigation"
          className="flex items-center gap-6 text-sm font-medium text-slate-400 overflow-x-auto"
        >
          <button
            type="button"
            onClick={() => setActiveTab('lab')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 py-1 border-b-2 ${
              activeTab === 'lab'
                ? 'text-white border-blue-500'
                : 'border-transparent text-slate-400'
            }`}
          >
            Mobile SSO Lab
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('inspector')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 py-1 border-b-2 ${
              activeTab === 'inspector'
                ? 'text-white border-blue-500'
                : 'border-transparent text-slate-400'
            }`}
          >
            Cryptographic Inspector
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('code')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 py-1 border-b-2 ${
              activeTab === 'code'
                ? 'text-white border-blue-500'
                : 'border-transparent text-slate-400'
            }`}
          >
            Go & Android Source
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('deliverables')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 py-1 border-b-2 ${
              activeTab === 'deliverables'
                ? 'text-white border-blue-500'
                : 'border-transparent text-slate-400'
            }`}
          >
            Deliverables & Postman
          </button>
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={handleRunFullEndToEndDemo}
            className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            Run Full SSO Demo
          </button>
        </div>
      </header>

      {/* Main Content Container */}
      <main className="flex-1 max-w-[1440px] w-full mx-auto px-6 py-6 space-y-8">
        {/* Workspace Context Banner & KPI Strip */}
        <section className="border border-slate-800 bg-slate-900/50 rounded-xl p-6 space-y-5">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="space-y-1.5 max-w-3xl">
              <div className="flex items-center gap-2 text-xs text-slate-400">
                <span>MOSIP Decode 03 eSignet</span>
                <span aria-hidden="true">·</span>
                <span>OpenID Connect Native SSO 1.0</span>
                <span aria-hidden="true">·</span>
                <span>FAPI 2.0 PAR + DPoP + RFC 8693 Token Exchange</span>
              </div>
              <h1
                className="text-2xl md:text-3xl font-bold text-white tracking-tight"
                style={{ textWrap: 'balance' }}
              >
                Native Single Sign-On Workbench for eSignet Go & Thunder ID Engine
              </h1>
            </div>

            <div className="flex flex-wrap items-center gap-3 shrink-0">
              <button
                type="button"
                onClick={handleResetAll}
                className="px-3.5 py-2 text-xs font-medium text-slate-300 bg-slate-800/90 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset Device State</span>
              </button>
            </div>
          </div>

          {/* 4-Column Cryptographic Telemetry Row */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-4 border-t border-slate-800/90">
            <div className="bg-slate-950/80 border border-slate-800/90 rounded-lg p-3.5">
              <div className="text-xs text-slate-400">01. Super App Session (Inji Wallet)</div>
              <div className="text-sm font-semibold font-mono tabular-nums mt-1 text-white flex items-center gap-1.5">
                {superTokens.device_secret ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span className="text-emerald-300">Authenticated (device_sso)</span>
                  </>
                ) : (
                  <span className="text-slate-400">Unauthenticated</span>
                )}
              </div>
            </div>

            <div className="bg-slate-950/80 border border-slate-800/90 rounded-lg p-3.5">
              <div className="text-xs text-slate-400">02. StrongBox Key A (cnf.jkt)</div>
              <div className="text-sm font-semibold font-mono tabular-nums mt-1 text-blue-300 truncate">
                {hardwareJkt}
              </div>
            </div>

            <div className="bg-slate-950/80 border border-slate-800/90 rounded-lg p-3.5">
              <div className="text-xs text-slate-400">03. id_token.ds_hash (128-bit SHA-256)</div>
              <div className="text-sm font-semibold font-mono tabular-nums mt-1 text-amber-300 truncate">
                {currentDsHash || 'Awaiting device_secret issuance'}
              </div>
            </div>

            <div className="bg-slate-950/80 border border-slate-800/90 rounded-lg p-3.5">
              <div className="text-xs text-slate-400">04. Child App Silent SSO (mParivahan)</div>
              <div className="text-sm font-semibold font-mono tabular-nums mt-1 text-white flex items-center gap-1.5">
                {childTokens.access_token ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span className="text-emerald-300">Signed In Silently (DPoP Key A)</span>
                  </>
                ) : (
                  <span className="text-slate-400">Awaiting Token Exchange</span>
                )}
              </div>
            </div>
          </div>
        </section>

        {/* Active View Content */}
        {activeTab === 'lab' && (
          <div className="space-y-8">
            {/* Dual Mobile Device Simulator + IPC Security Bridge */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
              {/* LEFT PHONE: First Mobile App (Super App) */}
              <section
                aria-label="First Mobile App Simulator"
                className="lg:col-span-5 border border-slate-800 bg-slate-900/70 rounded-xl p-5 flex flex-col justify-between space-y-5"
              >
                <div className="space-y-4">
                  {/* App Header */}
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3.5">
                    <div className="flex items-center gap-2.5">
                      <div className="w-9 h-9 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
                        <Smartphone className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2 text-xs text-slate-400">
                          <span>First Mobile App (Super App)</span>
                          <span aria-hidden="true">·</span>
                          <span className="font-mono text-blue-300">Steps 1–9</span>
                        </div>
                        <h2 className="text-base font-semibold text-white">
                          Inji Citizen Super Wallet
                        </h2>
                      </div>
                    </div>
                    <span className="text-xs font-mono text-slate-400">
                      io.mosip.inji.superwallet
                    </span>
                  </div>

                  {/* Error Banner if any */}
                  {superError && (
                    <div
                      role="alert"
                      className="p-3.5 rounded-lg bg-rose-950/70 border border-rose-700/80 text-xs text-rose-200 flex items-start gap-2.5"
                    >
                      <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                      <div>
                        <div className="font-semibold text-rose-100">
                          eSignet Authorization / Token Error
                        </div>
                        <div className="mt-0.5">{superError}</div>
                      </div>
                    </div>
                  )}

                  {/* Screen 1: Super App Login Screen */}
                  {superScreen === 'LOGIN' && (
                    <div className="border border-slate-800 bg-slate-950/90 rounded-xl p-5 space-y-5">
                      <div className="space-y-1.5">
                        <div className="text-xs text-blue-400 font-medium">
                          MOSIP National Digital Wallet
                        </div>
                        <h3 className="text-lg font-semibold text-white">
                          Citizen Identity & Credentials
                        </h3>
                        <p className="text-xs text-slate-400 leading-relaxed">
                          Authenticate once via eSignet FAPI 2.0 (PAR + DPoP). When{' '}
                          <code className="text-blue-300 font-mono">device_sso</code> is requested,
                          Inji receives a hardware-bound{' '}
                          <code className="text-blue-300 font-mono">device_secret</code> to enable
                          silent sign-in across trusted partner apps.
                        </p>
                      </div>

                      {/* Scope Selector for Task 1 & Task 10a testing */}
                      <div className="space-y-2 pt-2 border-t border-slate-800/80">
                        <label className="block text-xs font-medium text-slate-300">
                          Authorize Request Scopes (Mandatory Task 1):
                        </label>
                        <div className="flex flex-wrap gap-2">
                          {(['openid', 'profile', 'email', 'phone', 'device_sso'] as const).map(
                            (sc) => {
                              const active = superSelectedScopes.includes(sc);
                              return (
                                <button
                                  key={sc}
                                  type="button"
                                  onClick={() => toggleSuperScope(sc)}
                                  className={`px-2.5 py-1.5 text-xs font-mono rounded-md border transition-colors whitespace-nowrap shrink-0 ${
                                    active
                                      ? 'bg-blue-600/25 border-blue-500 text-blue-200 font-medium'
                                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                                  }`}
                                >
                                  {active ? '✓ ' : '+ '}
                                  {sc}
                                </button>
                              );
                            }
                          )}
                        </div>
                      </div>

                      <div className="pt-2">
                        <button
                          type="button"
                          onClick={handleStartSuperAppLogin}
                          className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-sm rounded-lg transition-colors flex items-center justify-center gap-2"
                        >
                          <Shield className="w-4 h-4" />
                          <span>Sign in with eSignet</span>
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Screen 2: System Browser eSignet UIN Entry (Steps 3-5) */}
                  {superScreen === 'BROWSER_UIN' && (
                    <form
                      onSubmit={handleSendOtp}
                      className="border border-blue-500/40 bg-slate-950 rounded-xl p-5 space-y-4"
                    >
                      <div className="flex items-center justify-between text-xs text-slate-400 pb-2.5 border-b border-slate-800">
                        <span className="font-mono text-blue-300">
                          https://esignet.mosip.net/authorize
                        </span>
                        <span>System Browser (oidc-ui)</span>
                      </div>

                      <div className="space-y-1">
                        <div className="text-xs text-emerald-400 font-mono truncate">
                          PAR URI: {activeParUri}
                        </div>
                        <h3 className="text-base font-semibold text-white">
                          Step 4–5: Login with OTP
                        </h3>
                        <p className="text-xs text-slate-400">
                          Enter your 10-digit MOSIP Unique Identification Number (UIN) to receive a
                          one-time password.
                        </p>
                      </div>

                      <div className="space-y-2">
                        <label
                          htmlFor="super-uin-input"
                          className="block text-xs font-medium text-slate-300"
                        >
                          MOSIP Citizen UIN
                        </label>
                        <input
                          id="super-uin-input"
                          type="text"
                          value={superUin}
                          onChange={(e) => setSuperUin(e.target.value)}
                          placeholder="Enter 10-digit UIN"
                          className="w-full px-3.5 py-2.5 text-sm font-mono bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                        />
                        <div className="flex items-center gap-2 text-xs text-slate-400">
                          <span>Sandbox UINs:</span>
                          <button
                            type="button"
                            onClick={() => setSuperUin('8294017365')}
                            className="text-blue-400 hover:underline font-mono"
                          >
                            8294017365 (Ananya)
                          </button>
                          <span>·</span>
                          <button
                            type="button"
                            onClick={() => setSuperUin('4510928374')}
                            className="text-blue-400 hover:underline font-mono"
                          >
                            4510928374 (Rohan)
                          </button>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 pt-2">
                        <button
                          type="button"
                          onClick={() => setSuperScreen('LOGIN')}
                          className="px-3.5 py-2.5 text-xs font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg"
                        >
                          Cancel
                        </button>
                        <button
                          type="submit"
                          className="flex-1 py-2.5 px-4 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs rounded-lg transition-colors"
                        >
                          Send OTP
                        </button>
                      </div>
                    </form>
                  )}

                  {/* Screen 3: System Browser eSignet OTP Verification (Step 6) */}
                  {superScreen === 'BROWSER_OTP' && (
                    <form
                      onSubmit={handleVerifyOtp}
                      className="border border-blue-500/40 bg-slate-950 rounded-xl p-5 space-y-4"
                    >
                      <div className="flex items-center justify-between text-xs text-slate-400 pb-2.5 border-b border-slate-800">
                        <span className="font-mono text-blue-300">
                          https://esignet.mosip.net/authorize#otp
                        </span>
                        <span>UIN: {superUin}</span>
                      </div>

                      <div className="space-y-1">
                        <h3 className="text-base font-semibold text-white">
                          Step 6: Verify Registered Mobile OTP
                        </h3>
                        <p className="text-xs text-slate-400">
                          OTP dispatched to citizen mobile number. Use sandbox code{' '}
                          <code className="text-emerald-300 font-mono">111111</code>.
                        </p>
                      </div>

                      <div className="space-y-2">
                        <label
                          htmlFor="super-otp-input"
                          className="block text-xs font-medium text-slate-300"
                        >
                          6-Digit One-Time Password
                        </label>
                        <input
                          id="super-otp-input"
                          type="text"
                          value={superOtp}
                          onChange={(e) => setSuperOtp(e.target.value)}
                          className="w-full px-3.5 py-2.5 text-sm font-mono tracking-widest bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                        />
                      </div>

                      <div className="flex items-center gap-2 pt-2">
                        <button
                          type="button"
                          onClick={() => setSuperScreen('BROWSER_UIN')}
                          className="px-3.5 py-2.5 text-xs font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg"
                        >
                          Back
                        </button>
                        <button
                          type="submit"
                          className="flex-1 py-2.5 px-4 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs rounded-lg transition-colors"
                        >
                          Submit OTP
                        </button>
                      </div>
                    </form>
                  )}

                  {/* Screen 4: System Browser eSignet Consent Screen (Steps 7-8) */}
                  {superScreen === 'BROWSER_CONSENT' && (
                    <div className="border border-blue-500/40 bg-slate-950 rounded-xl p-5 space-y-4">
                      <div className="flex items-center justify-between text-xs text-slate-400 pb-2.5 border-b border-slate-800">
                        <span className="font-mono text-blue-300">
                          https://esignet.mosip.net/consent
                        </span>
                        <span>Step 7–8: Relying Party Consent</span>
                      </div>

                      <div className="space-y-1">
                        <h3 className="text-base font-semibold text-white">
                          Inji Citizen Super Wallet Requests Access
                        </h3>
                        <p className="text-xs text-slate-400">
                          Review the user PII claims and authorization scopes requested by the
                          first mobile App.
                        </p>
                      </div>

                      <div className="space-y-2">
                        <div className="text-xs font-medium text-slate-300">
                          Authorization Scopes:
                        </div>
                        <div className="text-xs font-mono text-blue-300 bg-slate-900 p-2.5 rounded border border-slate-800">
                          {superSelectedScopes.join(' · ')}
                        </div>
                      </div>

                      <div className="space-y-2">
                        <div className="text-xs font-medium text-slate-300">
                          Requested Citizen PII Claims:
                        </div>
                        <div className="grid grid-cols-2 gap-2">
                          {(['name', 'email', 'phone_number', 'birthdate'] as const).map(
                            (claim) => {
                              const checked = superSelectedClaims.includes(claim);
                              return (
                                <button
                                  key={claim}
                                  type="button"
                                  onClick={() => toggleConsentClaim(claim)}
                                  className={`p-2 rounded border text-left text-xs font-mono transition-colors ${
                                    checked
                                      ? 'bg-emerald-950/50 border-emerald-600/60 text-emerald-200'
                                      : 'bg-slate-900 border-slate-800 text-slate-400'
                                  }`}
                                >
                                  {checked ? '☑ ' : '☐ '}
                                  {claim}
                                </button>
                              );
                            }
                          )}
                        </div>
                      </div>

                      <div className="flex items-center gap-2 pt-2">
                        <button
                          type="button"
                          onClick={() => setSuperScreen('LOGIN')}
                          className="px-3.5 py-2.5 text-xs font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg"
                        >
                          Deny
                        </button>
                        <button
                          type="button"
                          onClick={handleAllowConsent}
                          className="flex-1 py-2.5 px-4 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs rounded-lg transition-colors"
                        >
                          Allow
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Screen 5: Authenticated Super App Home Screen (Step 9) */}
                  {superScreen === 'AUTHENTICATED_HOME' && superUserInfo && (
                    <div className="border border-emerald-700/60 bg-slate-950/90 rounded-xl p-5 space-y-4">
                      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                        <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold">
                          <UserCheck className="w-4 h-4" />
                          <span>Step 9: Super App Authenticated Home</span>
                        </div>
                        <span className="text-xs font-mono text-slate-400">DPoP Bound</span>
                      </div>

                      <div className="grid grid-cols-2 gap-3 text-xs">
                        <div>
                          <div className="text-slate-400">Citizen Name</div>
                          <div className="font-semibold text-white mt-0.5">
                            {String(superUserInfo.name || 'Verified Citizen')}
                          </div>
                        </div>
                        <div>
                          <div className="text-slate-400">Subject (sub)</div>
                          <div className="font-mono text-slate-300 truncate mt-0.5">
                            {String(superUserInfo.sub)}
                          </div>
                        </div>
                        {Boolean(superUserInfo.email) && (
                          <div>
                            <div className="text-slate-400">Email (email scope)</div>
                            <div className="font-mono text-slate-200 truncate mt-0.5">
                              {String(superUserInfo.email)}
                            </div>
                          </div>
                        )}
                        <div>
                          <div className="text-slate-400">Granted Scopes</div>
                          <div className="font-mono text-blue-300 mt-0.5">
                            {superTokens.scope}
                          </div>
                        </div>
                      </div>

                      {/* Device Secret Vault Status */}
                      <div className="border border-slate-800 bg-slate-900/90 rounded-lg p-3.5 space-y-1.5 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                            <Lock className="w-3.5 h-3.5 text-emerald-400" />
                            Android Keystore & SSO Vault
                          </span>
                          <span className="font-mono text-emerald-400">
                            {superTokens.device_secret ? 'device_secret Stored' : 'No device_secret'}
                          </span>
                        </div>
                        <p className="text-slate-400 leading-relaxed">
                          {superTokens.device_secret
                            ? 'SSOSigningService bound service is active. Private Key A stays in StrongBox and is ready to sign DPoP proofs for same-vendor Child Apps.'
                            : 'Warning: device_sso scope was not included, so no device_secret was issued.'}
                        </p>
                      </div>

                      <div className="pt-1 flex items-center gap-2">
                        <button
                          type="button"
                          onClick={handleRevokeSuperAppSession}
                          className="w-full py-2.5 px-3 bg-rose-950/70 hover:bg-rose-900/70 border border-rose-700/70 text-rose-200 font-medium text-xs rounded-lg transition-colors whitespace-nowrap shrink-0"
                        >
                          Revoke device_secret & Logout (POST /oauth2/revoke)
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                {/* Footer Status inside Left Phone */}
                <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400 font-mono">
                  <span>Cert: DA:39:A3:EE...3F:01</span>
                  <span>Key A: Non-Exportable TEE</span>
                </div>
              </section>

              {/* CENTER BRIDGE: Android IPC & Security Policy Controls */}
              <section
                aria-label="IPC Security Policy Controls"
                className="lg:col-span-2 border border-slate-800 bg-slate-900/50 rounded-xl p-4 flex flex-col justify-between space-y-4"
              >
                <div className="space-y-4">
                  <div className="border-b border-slate-800 pb-3">
                    <div className="flex items-center gap-1.5 text-xs font-semibold text-white">
                      <Sliders className="w-3.5 h-3.5 text-blue-400" />
                      <span>IPC & Security Controls</span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1">
                      Simulate security checks between Super App, Child App, and Thunder ID.
                    </p>
                  </div>

                  {/* Control 1: Vendor Certificate Attestation (Task 7) */}
                  <div className="space-y-1.5">
                    <div className="text-xs font-medium text-slate-300">
                      1. Vendor Signing Cert (Task 7)
                    </div>
                    <button
                      type="button"
                      onClick={() => setVendorCertMatch((v) => !v)}
                      className={`w-full p-2.5 rounded-lg border text-left text-xs transition-colors ${
                        vendorCertMatch
                          ? 'bg-emerald-950/50 border-emerald-700/70 text-emerald-200'
                          : 'bg-rose-950/60 border-rose-700/70 text-rose-200'
                      }`}
                    >
                      <div className="font-semibold">
                        {vendorCertMatch ? 'Same Vendor Cert' : 'Untrusted Cert (Mismatch)'}
                      </div>
                      <div className="text-[11px] opacity-80 font-mono mt-0.5 truncate">
                        {vendorCertMatch ? 'SHA256: DA:39:A3...3F:01' : 'SHA256: FF:00:99...32:10'}
                      </div>
                    </button>
                  </div>

                  {/* Control 2: DPoP Hardware Key Binding (Task 9.a.iii.4) */}
                  <div className="space-y-1.5">
                    <div className="text-xs font-medium text-slate-300">
                      2. DPoP Proof Key (Task 9)
                    </div>
                    <button
                      type="button"
                      onClick={() => setUseHardwareKeyA((v) => !v)}
                      className={`w-full p-2.5 rounded-lg border text-left text-xs transition-colors ${
                        useHardwareKeyA
                          ? 'bg-blue-950/50 border-blue-700/70 text-blue-200'
                          : 'bg-rose-950/60 border-rose-700/70 text-rose-200'
                      }`}
                    >
                      <div className="font-semibold">
                        {useHardwareKeyA ? 'Super App Key A (Valid)' : 'Rogue Key X (Invalid jkt)'}
                      </div>
                      <div className="text-[11px] opacity-80 font-mono mt-0.5">
                        {useHardwareKeyA ? 'cnf.jkt == dpop.jkt' : 'cnf.jkt != dpop.jkt'}
                      </div>
                    </button>
                  </div>

                  {/* Control 3: Bonus Task 1 Step-Up Re-Consent Mode */}
                  <div className="space-y-1.5">
                    <div className="text-xs font-medium text-slate-300">
                      3. Out-of-Subset Scope Policy
                    </div>
                    <button
                      type="button"
                      onClick={() => setBonusReconsentEnabled((v) => !v)}
                      className={`w-full p-2.5 rounded-lg border text-left text-xs transition-colors ${
                        bonusReconsentEnabled
                          ? 'bg-amber-950/50 border-amber-700/70 text-amber-200'
                          : 'bg-slate-950 border-slate-800 text-slate-300'
                      }`}
                    >
                      <div className="font-semibold">
                        {bonusReconsentEnabled
                          ? 'Bonus: Trigger Re-Consent'
                          : 'Strict: Reject invalid_scope'}
                      </div>
                      <div className="text-[11px] opacity-80 mt-0.5">
                        {bonusReconsentEnabled
                          ? 'Prompts user when scope differs'
                          : 'Task 10a strict rejection'}
                      </div>
                    </button>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-800 text-center">
                  <div className="text-[11px] font-mono text-slate-400">
                    bindService() IPC Bridge
                  </div>
                </div>
              </section>

              {/* RIGHT PHONE: Second Mobile App (Child App) */}
              <section
                aria-label="Second Mobile App Simulator"
                className="lg:col-span-5 border border-slate-800 bg-slate-900/70 rounded-xl p-5 flex flex-col justify-between space-y-5"
              >
                <div className="space-y-4">
                  {/* App Header */}
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3.5">
                    <div className="flex items-center gap-2.5">
                      <div className="w-9 h-9 rounded-lg bg-emerald-600/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
                        <Zap className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2 text-xs text-slate-400">
                          <span>Second Mobile App (Child App)</span>
                          <span aria-hidden="true">·</span>
                          <span className="font-mono text-emerald-300">Steps 10–11</span>
                        </div>
                        <h2 className="text-base font-semibold text-white">
                          mParivahan Citizen Transit
                        </h2>
                      </div>
                    </div>
                    <span className="text-xs font-mono text-slate-400">
                      io.mosip.gov.mparivahan
                    </span>
                  </div>

                  {/* Error Banner for Negative Tests (Task 7, 9, 10a, 10b) */}
                  {childError && (
                    <div
                      role="alert"
                      className="p-3.5 rounded-lg bg-rose-950/70 border border-rose-700/80 text-xs text-rose-200 space-y-1"
                    >
                      <div className="font-mono font-semibold text-rose-300 flex items-center gap-1.5">
                        <AlertCircle className="w-4 h-4 shrink-0" />
                        <span>Error: {childError.code}</span>
                      </div>
                      <p className="text-rose-100/90 leading-relaxed">{childError.message}</p>
                    </div>
                  )}

                  {/* Screen 1: Child App Login & Scope Selector */}
                  {childScreen === 'LOGIN' && (
                    <div className="border border-slate-800 bg-slate-950/90 rounded-xl p-5 space-y-5">
                      <div className="space-y-1.5">
                        <div className="text-xs text-emerald-400 font-medium">
                          Ministry of Road Transport · Same Vendor Family
                        </div>
                        <h3 className="text-lg font-semibold text-white">
                          Seamless Native Single Sign-On
                        </h3>
                        <p className="text-xs text-slate-400 leading-relaxed">
                          Tapping <strong>Sign In</strong> binds to the Super App’s{' '}
                          <code className="text-emerald-300 font-mono">SSOSigningService</code>,
                          retrieves <code className="font-mono text-slate-200">id_token</code> +{' '}
                          <code className="font-mono text-slate-200">device_secret</code> + DPoP
                          proof signed by Key A, and exchanges them at{' '}
                          <code className="font-mono text-slate-200">POST /oauth2/token</code>{' '}
                          without prompting for OTP or consent.
                        </p>
                      </div>

                      {/* Scope Selector for Task 10a & Task 10b */}
                      <div className="space-y-2 pt-2 border-t border-slate-800/80">
                        <label className="block text-xs font-medium text-slate-300">
                          Token Exchange Requested Scopes (Task 8 & Task 10):
                        </label>
                        <div className="flex flex-wrap gap-2">
                          {(['openid', 'profile', 'email', 'phone', 'device_sso'] as const).map(
                            (sc) => {
                              const active = childSelectedScopes.includes(sc);
                              const isForbiddenDeviceSso = sc === 'device_sso';
                              return (
                                <button
                                  key={sc}
                                  type="button"
                                  onClick={() => toggleChildScope(sc)}
                                  className={`px-2.5 py-1.5 text-xs font-mono rounded-md border transition-colors whitespace-nowrap shrink-0 ${
                                    active
                                      ? isForbiddenDeviceSso
                                        ? 'bg-rose-950/80 border-rose-500 text-rose-200 font-medium'
                                        : 'bg-emerald-600/25 border-emerald-500 text-emerald-200 font-medium'
                                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                                  }`}
                                >
                                  {active ? '✓ ' : '+ '}
                                  {sc}
                                  {isForbiddenDeviceSso ? ' (Task 10b Test)' : ''}
                                </button>
                              );
                            }
                          )}
                        </div>
                        <p className="text-[11px] text-slate-400">
                          Tip: Select a subset of Super App scopes (e.g.{' '}
                          <code className="font-mono text-slate-300">openid profile</code>) for
                          silent login, or select{' '}
                          <code className="font-mono text-slate-300">phone</code> /{' '}
                          <code className="font-mono text-rose-300">device_sso</code> to test Task
                          10 rules.
                        </p>
                      </div>

                      <div className="pt-2">
                        <button
                          type="button"
                          onClick={() => handleChildAppSignIn(false)}
                          className="w-full py-3 px-4 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-sm rounded-lg transition-colors flex items-center justify-center gap-2"
                        >
                          <span>Sign In</span>
                          <ArrowRight className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Screen 2: Bonus Task 1 Step-Up Re-Consent Screen when Child App scopes exceed Super App consent */}
                  {childScreen === 'BONUS_RECONSENT' && (
                    <div className="border border-amber-500/60 bg-slate-950 rounded-xl p-5 space-y-4">
                      <div className="flex items-center justify-between text-xs text-amber-300 pb-2.5 border-b border-slate-800">
                        <span className="font-semibold">Bonus Task 1: Step-Up Re-Consent</span>
                        <span className="font-mono">interaction_required</span>
                      </div>

                      <div className="space-y-1.5">
                        <h3 className="text-base font-semibold text-white">
                          Additional Scope Authorization Required
                        </h3>
                        <p className="text-xs text-slate-300 leading-relaxed">
                          <strong>mParivahan Citizen Transit</strong> requested scopes that were
                          not part of the original consent granted to the Super App:
                        </p>
                      </div>

                      <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-700/60 text-xs font-mono text-amber-200">
                        New Scope(s) Requested: {pendingReconsentScopes.join(', ')}
                      </div>

                      <div className="flex items-center gap-2 pt-2">
                        <button
                          type="button"
                          onClick={() => setChildScreen('LOGIN')}
                          className="px-3.5 py-2.5 text-xs font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg"
                        >
                          Cancel
                        </button>
                        <button
                          type="button"
                          onClick={() => handleChildAppSignIn(true)}
                          className="flex-1 py-2.5 px-4 bg-amber-600 hover:bg-amber-500 text-white font-semibold text-xs rounded-lg transition-colors"
                        >
                          Approve Additional Scope & Sign In
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Screen 3: Child App Authenticated Home (Step 11) */}
                  {childScreen === 'AUTHENTICATED_HOME' && childUserInfo && (
                    <div className="border border-emerald-600/60 bg-slate-950/90 rounded-xl p-5 space-y-4">
                      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                        <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold">
                          <CheckCircle2 className="w-4 h-4" />
                          <span>Step 11: Silently Signed In (Zero Re-Auth!)</span>
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            setChildScreen('LOGIN');
                            setChildTokens({});
                            setChildUserInfo(null);
                          }}
                          className="text-xs text-slate-400 hover:text-white underline"
                        >
                          Test Another Exchange
                        </button>
                      </div>

                      <div className="grid grid-cols-2 gap-3 text-xs">
                        <div>
                          <div className="text-slate-400">Citizen Holder</div>
                          <div className="font-semibold text-white mt-0.5">
                            {String(childUserInfo.name || 'Scoped Subject Only')}
                          </div>
                        </div>
                        <div>
                          <div className="text-slate-400">Scoped Claims Returned</div>
                          <div className="font-mono text-emerald-300 mt-0.5">
                            {Object.keys(childUserInfo).join(', ')}
                          </div>
                        </div>
                        <div>
                          <div className="text-slate-400">Exchanged Scope</div>
                          <div className="font-mono text-blue-300 mt-0.5">
                            {childTokens.scope}
                          </div>
                        </div>
                        <div>
                          <div className="text-slate-400">DPoP Key Binding</div>
                          <div className="font-mono text-emerald-300 mt-0.5 truncate">
                            Same Key A ({hardwareJkt.slice(0, 10)}...)
                          </div>
                        </div>
                      </div>

                      <div className="border border-slate-800 bg-slate-900/90 rounded-lg p-3.5 text-xs space-y-1">
                        <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                          <KeyRound className="w-3.5 h-3.5 text-blue-400" />
                          Cryptographic Handoff Verified
                        </div>
                        <p className="text-slate-400 leading-relaxed">
                          Thunder ID verified <code className="font-mono">ds_hash</code>,{' '}
                          <code className="font-mono">sid</code>, and{' '}
                          <code className="font-mono">cnf.jkt == DPoP.jkt</code>, issuing a scoped
                          access token bound to Super App’s Key A.
                        </p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Footer Status inside Right Phone */}
                <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400 font-mono">
                  <span>
                    Cert: {vendorCertMatch ? 'DA:39:A3:EE...3F:01' : 'FF:00:99:11...32:10'}
                  </span>
                  <span>Grant: token-exchange</span>
                </div>
              </section>
            </div>

            {/* Live Protocol Sequence Trace & Consent Audit Lineage */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Protocol Sequence Trace */}
              <section className="lg:col-span-8 border border-slate-800 bg-slate-900/60 rounded-xl p-6 space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3.5">
                  <div>
                    <h3 className="text-base font-semibold text-white">
                      Live Protocol Sequence Trace (PAR, DPoP, IPC & Token Exchange)
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Click any protocol event to inspect the raw request and response payloads.
                    </p>
                  </div>
                  <span className="text-xs font-mono text-slate-400 tabular-nums">
                    {sequenceLogs.length} Events Recorded
                  </span>
                </div>

                {sequenceLogs.length === 0 ? (
                  <div className="border border-slate-800/80 bg-slate-950/60 rounded-lg p-8 text-center space-y-3">
                    <FileCode2 className="w-7 h-7 text-slate-500 mx-auto" />
                    <div className="text-sm font-medium text-slate-200">
                      No Protocol Requests Executed Yet
                    </div>
                    <p className="text-xs text-slate-400 max-w-md mx-auto">
                      Click <strong>Sign in with eSignet</strong> on the Super App or click{' '}
                      <strong>Run Full SSO Demo</strong> in the top bar to trace the complete
                      cryptographic handshake.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-2.5 max-h-[460px] overflow-y-auto pr-1">
                    {sequenceLogs.map((step) => {
                      const isExpanded = expandedStepId === step.id;
                      return (
                        <div
                          key={step.id}
                          className="border border-slate-800 bg-slate-950/90 rounded-lg overflow-hidden"
                        >
                          <button
                            type="button"
                            onClick={() =>
                              setExpandedStepId(isExpanded ? null : step.id)
                            }
                            className="w-full px-4 py-3 text-left flex items-center justify-between gap-3 hover:bg-slate-900/70 transition-colors"
                          >
                            <div className="space-y-1 min-w-0">
                              <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                                <span
                                  className={
                                    step.status === 'success'
                                      ? 'text-emerald-400 font-semibold'
                                      : step.status === 'warning'
                                      ? 'text-amber-400 font-semibold'
                                      : 'text-rose-400 font-semibold'
                                  }
                                >
                                  HTTP {step.statusCode}
                                </span>
                                <span className="text-slate-500">·</span>
                                <span className="text-blue-300">
                                  {step.actorFrom} → {step.actorTo}
                                </span>
                                {step.rfcTaskRef && (
                                  <>
                                    <span className="text-slate-500">·</span>
                                    <span className="text-slate-400">{step.rfcTaskRef}</span>
                                  </>
                                )}
                              </div>
                              <div className="text-xs font-semibold text-white truncate">
                                {step.title}
                              </div>
                            </div>
                            {isExpanded ? (
                              <ChevronUp className="w-4 h-4 text-slate-400 shrink-0" />
                            ) : (
                              <ChevronDown className="w-4 h-4 text-slate-400 shrink-0" />
                            )}
                          </button>

                          {isExpanded && (
                            <div className="px-4 pb-4 pt-2 border-t border-slate-800/90 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                              <div>
                                <div className="text-slate-400 mb-1">Request Payload:</div>
                                <pre className="p-2.5 rounded bg-slate-900 border border-slate-800 text-slate-200 overflow-x-auto">
                                  {JSON.stringify(step.requestPayload, null, 2)}
                                </pre>
                              </div>
                              <div>
                                <div className="text-slate-400 mb-1">Response Payload:</div>
                                <pre className="p-2.5 rounded bg-slate-900 border border-slate-800 text-emerald-200 overflow-x-auto">
                                  {JSON.stringify(step.responsePayload, null, 2)}
                                </pre>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>

              {/* ConsentProvider Audit History (Sequence Diagram 2: derived_from=org_client_id) */}
              <section className="lg:col-span-4 border border-slate-800 bg-slate-900/60 rounded-xl p-6 space-y-4">
                <div className="border-b border-slate-800 pb-3.5">
                  <h3 className="text-base font-semibold text-white">
                    ConsentProvider Audit Trail
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Records explicit Super App consent and silent Child App{' '}
                    <code className="font-mono text-emerald-300">NOCAPTURE</code> lineage.
                  </p>
                </div>

                {consentAuditLog.length === 0 ? (
                  <div className="border border-slate-800/80 bg-slate-950/60 rounded-lg p-6 text-center text-xs text-slate-400">
                    Consent history rows appear here once Super App or Child App completes
                    authorization.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {consentAuditLog.map((row) => (
                      <div
                        key={row.id}
                        className="border border-slate-800 bg-slate-950/90 rounded-lg p-3.5 space-y-1.5 text-xs"
                      >
                        <div className="flex items-center justify-between font-mono">
                          <span className="text-emerald-400 font-semibold">{row.mode}</span>
                          <span className="text-slate-500 tabular-nums">
                            {row.timestamp.slice(11, 19)}
                          </span>
                        </div>
                        <div className="font-medium text-white">Client: {row.client_id}</div>
                        {row.derived_from_client_id && (
                          <div className="text-slate-400 font-mono">
                            derived_from: {row.derived_from_client_id}
                          </div>
                        )}
                        <div className="text-blue-300 font-mono">
                          Scopes: {row.granted_scopes.join(' · ')}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </section>
            </div>
          </div>
        )}

        {activeTab === 'inspector' && (
          <CryptographicInspectorView
            superAppTokens={superTokens}
            childAppTokens={childTokens}
            registeredClients={registeredClients}
            onToggleClientDeviceSsoScope={handleToggleClientDeviceSsoScope}
          />
        )}

        {activeTab === 'code' && <CodeAndArchitectureView />}

        {activeTab === 'deliverables' && <DeliverablesAndPostmanView />}
      </main>

      {/* Quiet Footer */}
      <footer className="border-t border-slate-800/80 px-6 py-4 text-xs text-slate-500">
        <div className="max-w-[1440px] mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            MOSIP Decode · 03 eSignet — Enable Native SSO in eSignet Go for Mobile Apps
          </div>
          <div className="flex items-center gap-3 font-mono">
            <span>OpenID Connect Native SSO 1.0</span>
            <span aria-hidden="true">·</span>
            <span>RFC 8693</span>
            <span aria-hidden="true">·</span>
            <span>RFC 9449 DPoP</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
