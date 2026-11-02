import express from 'express';
import path from 'path';
import { NativeSsoServerEngine, CITIZEN_DIRECTORY } from './src/lib/nativeSsoEngine.ts';

function getBaseUrl(req: express.Request): string {
  if (process.env.BASE_URL) {
    return process.env.BASE_URL.replace(/\/+$/, '');
  }
  const forwardedProto = req.headers['x-forwarded-proto'];
  const proto =
    typeof forwardedProto === 'string'
      ? forwardedProto.split(',')[0].trim()
      : req.protocol || 'http';
  const forwardedHost = req.headers['x-forwarded-host'];
  const host =
    typeof forwardedHost === 'string'
      ? forwardedHost.split(',')[0].trim()
      : req.get('host') || 'localhost:3000';
  return `${proto}://${host}/api`;
}

function renderAuthorizeHtml(params: {
  auth_id: string;
  client_id: string;
  client_name: string;
  requested_scopes: string[];
  redirect_uri: string;
  state?: string;
  dpop_jkt?: string;
  baseUrl: string;
}): string {
  const citizens = Object.values(CITIZEN_DIRECTORY);
  const defaultCitizen = citizens[0] || {
    uin: '8294017365',
    name: 'Ananya Deshmukh',
    email: 'ananya.deshmukh@citizen.mosip.net',
    phone_number: '+91-98204-71932',
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
  <title>MOSIP eSignet - Citizen Authentication</title>
  <style>
    :root {
      --primary: #0D47A1;
      --primary-dark: #0A3880;
      --primary-light: #E3F2FD;
      --accent: #00796B;
      --text-main: #1E293B;
      --text-muted: #64748B;
      --bg: #F1F5F9;
      --surface: #FFFFFF;
      --border: #CBD5E1;
      --success: #059669;
      --success-light: #D1FAE5;
      --error: #DC2626;
      --error-light: #FEE2E2;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; -webkit-tap-highlight-color: transparent; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text-main);
      padding: 16px;
      line-height: 1.5;
    }
    .container {
      max-width: 480px;
      margin: 0 auto;
      background: var(--surface);
      border-radius: 16px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
      border: 1px solid var(--border);
      overflow: hidden;
    }
    .header {
      background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
      color: #FFFFFF;
      padding: 24px 20px;
      text-align: center;
      position: relative;
    }
    .header .flag-strip {
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
      background: linear-gradient(90deg, #FF9933 33.3%, #FFFFFF 33.3%, #FFFFFF 66.6%, #138808 66.6%);
    }
    .logo-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(255, 255, 255, 0.15);
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.5px;
      margin-bottom: 8px;
    }
    .header h1 {
      font-size: 20px;
      font-weight: 700;
      margin-bottom: 4px;
    }
    .header p {
      font-size: 13px;
      opacity: 0.9;
    }
    .content {
      padding: 20px;
    }
    .client-card {
      background: var(--primary-light);
      border: 1px solid #BBDEFB;
      border-radius: 12px;
      padding: 12px 16px;
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .client-icon {
      width: 40px;
      height: 40px;
      background: var(--primary);
      color: #fff;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 20px;
      flex-shrink: 0;
    }
    .client-info h3 {
      font-size: 14px;
      font-weight: 700;
      color: var(--primary-dark);
    }
    .client-info p {
      font-size: 11px;
      color: #1565C0;
      font-family: monospace;
    }
    .section-title {
      font-size: 13px;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 8px;
    }
    .chips-row {
      display: flex;
      gap: 8px;
      overflow-x: auto;
      margin-bottom: 16px;
      padding-bottom: 4px;
    }
    .chip {
      background: #F1F5F9;
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-main);
      cursor: pointer;
      white-space: nowrap;
      transition: all 0.15s ease;
    }
    .chip.active {
      background: #E0F2FE;
      border-color: #0284C7;
      color: #0369A1;
    }
    .form-group {
      margin-bottom: 16px;
    }
    .form-group label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 6px;
      color: var(--text-main);
    }
    .form-input {
      width: 100%;
      padding: 12px 14px;
      border: 1.5px solid var(--border);
      border-radius: 10px;
      font-size: 15px;
      font-family: monospace;
      color: var(--text-main);
      background: #FFFFFF;
      transition: border-color 0.15s;
    }
    .form-input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(13, 71, 161, 0.15);
    }
    .input-hint {
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 4px;
    }
    .consent-card {
      background: #F8FAFC;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
      margin-bottom: 20px;
    }
    .consent-item {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      padding: 8px 0;
      border-bottom: 1px solid #E2E8F0;
    }
    .consent-item:last-child {
      border-bottom: none;
      padding-bottom: 0;
    }
    .consent-item input[type="checkbox"] {
      margin-top: 3px;
      width: 18px;
      height: 18px;
      accent-color: var(--primary);
    }
    .consent-item .label-box h4 {
      font-size: 13px;
      font-weight: 700;
      color: var(--text-main);
    }
    .consent-item .label-box p {
      font-size: 11px;
      color: var(--text-muted);
    }
    .badge-sso {
      display: inline-block;
      background: #FEF3C7;
      color: #92400E;
      font-size: 10px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
      margin-left: 6px;
    }
    .btn-submit {
      width: 100%;
      background: var(--primary);
      color: #FFFFFF;
      border: none;
      border-radius: 12px;
      padding: 15px;
      font-size: 16px;
      font-weight: 700;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(13, 71, 161, 0.25);
      transition: background 0.15s, transform 0.05s;
    }
    .btn-submit:hover {
      background: var(--primary-dark);
    }
    .btn-submit:active {
      transform: scale(0.99);
    }
    .btn-submit:disabled {
      background: #94A3B8;
      cursor: not-allowed;
      box-shadow: none;
    }
    .alert-box {
      border-radius: 10px;
      padding: 12px 14px;
      font-size: 13px;
      margin-top: 16px;
      display: none;
    }
    .alert-box.error {
      background: var(--error-light);
      color: var(--error);
      border: 1px solid #FCA5A5;
      display: block;
    }
    .alert-box.success {
      background: var(--success-light);
      color: var(--success);
      border: 1px solid #6EE7B7;
      display: block;
    }
    .fallback-box {
      margin-top: 16px;
      padding: 16px;
      background: #FEF9C3;
      border: 1px solid #FDE047;
      border-radius: 12px;
      text-align: center;
      display: none;
    }
    .fallback-box p {
      font-size: 13px;
      color: #854D0E;
      margin-bottom: 10px;
      font-weight: 600;
    }
    .btn-fallback {
      display: inline-block;
      background: #CA8A04;
      color: #FFFFFF;
      text-decoration: none;
      font-weight: 700;
      font-size: 14px;
      padding: 10px 20px;
      border-radius: 8px;
    }
    .footer {
      text-align: center;
      margin-top: 16px;
      font-size: 11px;
      color: var(--text-muted);
    }
    .spinner {
      border: 3px solid rgba(255,255,255,0.3);
      border-top-color: #fff;
      border-radius: 50%;
      width: 18px;
      height: 18px;
      animation: spin 0.8s linear infinite;
      display: none;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="flag-strip"></div>
      <div class="logo-badge">🛡️ MOSIP eSignet 1.0</div>
      <h1>Citizen Identity Verification</h1>
      <p>National Identity Authentication (MOSIP IDA / FAPI 2.0)</p>
    </div>

    <div class="content">
      <!-- Requesting Super App Card -->
      <div class="client-card">
        <div class="client-icon">📱</div>
        <div class="client-info">
          <h3>${params.client_name}</h3>
          <p>${params.client_id} &bull; io.mosip.inji.superwallet</p>
        </div>
      </div>

      <!-- Quick Demo Citizen Selector -->
      <div class="section-title">Select Demo Citizen Profile</div>
      <div class="chips-row">
        <button type="button" class="chip active" onclick="selectCitizen('8294017365', '111111', this)">
          👤 Ananya Deshmukh (8294017365)
        </button>
        <button type="button" class="chip" onclick="selectCitizen('4510928374', '111111', this)">
          👤 Rohan Vikram (4510928374)
        </button>
      </div>

      <!-- Login Form -->
      <form id="authForm" onsubmit="event.preventDefault(); submitAuthFlow();">
        <div class="form-group">
          <label for="uinInput">MOSIP National ID (UIN)</label>
          <input
            type="text"
            id="uinInput"
            name="uin"
            class="form-input"
            value="${defaultCitizen.uin}"
            required
            autocomplete="off"
            placeholder="10-digit MOSIP UIN"
          />
          <div class="input-hint">Default Citizen UIN in MOSIP Collab Sandbox directory</div>
        </div>

        <div class="form-group">
          <label for="otpInput">One-Time Password (OTP)</label>
          <input
            type="text"
            id="otpInput"
            name="otp"
            class="form-input"
            value="111111"
            maxlength="6"
            required
            autocomplete="off"
            placeholder="6-digit OTP code"
          />
          <div class="input-hint">Collab Sandbox / Mock IDA OTP is <strong>111111</strong></div>
        </div>

        <!-- Consent Card -->
        <div class="section-title">Citizen Consent &amp; Permissions</div>
        <div class="consent-card">
          <div class="consent-item">
            <input type="checkbox" id="scope_device_sso" checked disabled />
            <div class="label-box">
              <h4>Native Device SSO <span class="badge-sso">Required</span></h4>
              <p>Issue Hardware-bound Device Secret for silent single sign-on across companion public sector apps (e.g. mParivahan Transit, Ayushman Health).</p>
            </div>
          </div>
          <div class="consent-item">
            <input type="checkbox" id="scope_profile" checked disabled />
            <div class="label-box">
              <h4>Citizen Profile</h4>
              <p>Full Name, Date of Birth, Gender, and Registered Address.</p>
            </div>
          </div>
          <div class="consent-item">
            <input type="checkbox" id="scope_email_phone" checked disabled />
            <div class="label-box">
              <h4>Contact Information</h4>
              <p>Verified email address and registered mobile number.</p>
            </div>
          </div>
        </div>

        <button type="submit" id="btnSubmit" class="btn-submit">
          <div id="btnSpinner" class="spinner"></div>
          <span id="btnText">Verify OTP &amp; Authorize Super App</span>
        </button>
      </form>

      <div id="alertBox" class="alert-box"></div>

      <div id="fallbackBox" class="fallback-box">
        <p>✅ Authentication Approved! Tap below to return to Inji Super Wallet:</p>
        <a id="btnDeepLink" class="btn-fallback" href="#">Open Inji Super Wallet</a>
      </div>

      <div class="footer">
        Hardware Key Binding: ${params.dpop_jkt ? params.dpop_jkt.slice(0, 16) + '...' : 'StrongBox P-256'}<br />
        Encrypted JWE device_secret &bull; RFC 9449 DPoP
      </div>
    </div>
  </div>

  <script>
    const AUTH_ID = ${JSON.stringify(params.auth_id)};
    const REDIRECT_URI = ${JSON.stringify(params.redirect_uri)};
    const STATE = ${JSON.stringify(params.state || '')};
    const BASE_URL = ${JSON.stringify(params.baseUrl)};

    function selectCitizen(uin, otp, chipEl) {
      document.getElementById('uinInput').value = uin;
      document.getElementById('otpInput').value = otp;
      document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
      chipEl.classList.add('active');
    }

    function showAlert(message, type) {
      const alertBox = document.getElementById('alertBox');
      alertBox.textContent = message;
      alertBox.className = 'alert-box ' + type;
    }

    async function submitAuthFlow() {
      const uin = document.getElementById('uinInput').value.trim();
      const otp = document.getElementById('otpInput').value.trim();
      const btnSubmit = document.getElementById('btnSubmit');
      const btnSpinner = document.getElementById('btnSpinner');
      const btnText = document.getElementById('btnText');
      const alertBox = document.getElementById('alertBox');

      if (!uin || !otp) {
        showAlert('Please enter both MOSIP UIN and OTP.', 'error');
        return;
      }

      btnSubmit.disabled = true;
      btnSpinner.style.display = 'inline-block';
      btnText.textContent = 'Verifying OTP with MOSIP IDA...';
      alertBox.style.display = 'none';

      try {
        // Step 1: POST /oauth2/authenticate
        const authRes = await fetch(BASE_URL + '/oauth2/authenticate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ auth_id: AUTH_ID, uin: uin, otp: otp })
        });
        const authData = await authRes.json();

        if (!authRes.ok || !authData.verified) {
          showAlert(authData.error_description || authData.error || 'OTP authentication failed.', 'error');
          btnSubmit.disabled = false;
          btnSpinner.style.display = 'none';
          btnText.textContent = 'Verify OTP & Authorize Super App';
          return;
        }

        // Step 2: POST /oauth2/consent
        btnText.textContent = 'Granting Consent & Issuing Code...';
        const consentRes = await fetch(BASE_URL + '/oauth2/consent', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            auth_id: AUTH_ID,
            accepted_scopes: ['openid', 'profile', 'email', 'phone', 'device_sso'],
            accepted_claims: ['name', 'email', 'phone_number', 'birthdate', 'gender', 'address']
          })
        });
        const consentData = await consentRes.json();

        if (!consentRes.ok || !consentData.code) {
          showAlert(consentData.error_description || 'Consent recording failed.', 'error');
          btnSubmit.disabled = false;
          btnSpinner.style.display = 'none';
          btnText.textContent = 'Verify OTP & Authorize Super App';
          return;
        }

        // Step 3: Trigger deep link back to Android Super App
        btnText.textContent = 'Success! Redirecting to Super App...';
        showAlert('Identity verified! Returning to Inji Citizen Super App...', 'success');

        const targetRedirect = consentData.redirect_uri || REDIRECT_URI;
        const stateParam = STATE ? '&state=' + encodeURIComponent(STATE) : '';
        const deepLink = targetRedirect + '?code=' + encodeURIComponent(consentData.code) + stateParam;

        console.log('Redirecting to deep link:', deepLink);

        // Immediate redirection
        window.location.href = deepLink;

        // Show fallback card if browser/custom tab blocks immediate redirect
        setTimeout(function() {
          const fallbackBox = document.getElementById('fallbackBox');
          const btnDeepLink = document.getElementById('btnDeepLink');
          btnDeepLink.href = deepLink;
          fallbackBox.style.display = 'block';
        }, 1200);

      } catch (err) {
        showAlert('Network or server error: ' + err.message, 'error');
        btnSubmit.disabled = false;
        btnSpinner.style.display = 'none';
        btnText.textContent = 'Verify OTP & Authorize Super App';
      }
    }
  </script>
</body>
</html>`;
}

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  const ssoEngine = new NativeSsoServerEngine();

  // 1. OIDC Discovery Endpoint (GET /api/.well-known/openid-configuration & GET /.well-known/openid-configuration)
  const discoveryHandler = (req: express.Request, res: express.Response) => {
    const baseUrl = getBaseUrl(req);
    ssoEngine.setIssuer(baseUrl);

    res.json({
      issuer: baseUrl,
      pushed_authorization_request_endpoint: `${baseUrl}/oauth2/par`,
      authorization_endpoint: `${baseUrl}/oauth2/authorize`,
      token_endpoint: `${baseUrl}/oauth2/token`,
      userinfo_endpoint: `${baseUrl}/oauth2/userinfo`,
      scopes_supported: ['openid', 'profile', 'email', 'phone', 'verified_claims', 'device_sso'],
      grant_types_supported: [
        'authorization_code',
        'urn:ietf:params:oauth:grant-type:token-exchange',
        'token_exchange',
      ],
      dpop_signing_alg_values_supported: ['ES256'],
      native_sso_supported: true,
    });
  };

  app.get('/api/.well-known/openid-configuration', discoveryHandler);
  app.get('/.well-known/openid-configuration', discoveryHandler);

  // 2. Pushed Authorization Request (POST /api/oauth2/par & POST /oauth2/par)
  const parHandler = (req: express.Request, res: express.Response) => {
    const baseUrl = getBaseUrl(req);
    ssoEngine.setIssuer(baseUrl);

    const result = ssoEngine.handleParRequest({
      client_id: String(req.body.client_id || 'mosip-super-wallet-android'),
      scope: String(req.body.scope || 'openid profile email device_sso'),
      redirect_uri: String(req.body.redirect_uri || 'io.mosip.inji.superwallet://oauth2redirect'),
      code_challenge: String(req.body.code_challenge || ''),
      code_challenge_method: 'S256',
      dpop_jkt: String(req.body.dpop_jkt || ''),
      nonce: req.body.nonce ? String(req.body.nonce) : undefined,
      state: req.body.state ? String(req.body.state) : undefined,
    });
    res.status(result.status).json(result.body);
  };

  app.post('/api/oauth2/par', parHandler);
  app.post('/oauth2/par', parHandler);

  // 3. Authorize Session & Interactive Screen (GET /api/oauth2/authorize & GET /oauth2/authorize)
  const authorizeHandler = (req: express.Request, res: express.Response) => {
    const clientId = String(req.query.client_id || '');
    const requestUri = String(req.query.request_uri || '');
    const baseUrl = getBaseUrl(req);
    ssoEngine.setIssuer(baseUrl);

    const result = ssoEngine.startAuthorizeSession({
      client_id: clientId,
      request_uri: requestUri,
    });

    if (result.status !== 200) {
      if (req.headers.accept?.includes('text/html')) {
        return res.status(result.status).send(`
          <!DOCTYPE html>
          <html>
          <head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>MOSIP eSignet - Error</title>
          <style>body{font-family:sans-serif;padding:24px;background:#FEF2F2;color:#991B1B;line-height:1.5;} .card{background:#fff;padding:20px;border-radius:12px;border:1px solid #FCA5A5;box-shadow:0 2px 4px rgba(0,0,0,0.05);max-width:480px;margin:40px auto;}</style>
          </head>
          <body>
            <div class="card">
              <h2 style="margin-top:0;">Authentication Error</h2>
              <p>${result.body.error_description || result.body.error || 'Invalid authorization request'}</p>
              <p style="font-size:12px;color:#6B7280;margin-top:12px;">Please return to the Inji Citizen Super App and tap "Sign in with eSignet" to start a new session.</p>
            </div>
          </body>
          </html>
        `);
      }
      return res.status(result.status).json(result.body);
    }

    // If client requested HTML (e.g. Browser or Chrome Custom Tab), serve interactive screen
    const wantsHtml =
      Boolean(req.headers.accept && req.headers.accept.includes('text/html')) ||
      req.query.ui === 'true' ||
      req.query.format === 'html';

    if (!wantsHtml) {
      return res.status(200).json(result.body);
    }

    const session = ssoEngine.authSessions.get(result.body.auth_id || '');
    const html = renderAuthorizeHtml({
      auth_id: result.body.auth_id || '',
      client_id: clientId,
      client_name: result.body.client_name || 'Inji Citizen Super App',
      requested_scopes: result.body.requested_scopes || [
        'openid',
        'profile',
        'email',
        'device_sso',
      ],
      redirect_uri: session?.redirect_uri || 'io.mosip.inji.superwallet://oauth2redirect',
      state: session?.state,
      dpop_jkt: session?.dpop_jkt,
      baseUrl,
    });

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(html);
  };

  app.get('/api/oauth2/authorize', authorizeHandler);
  app.get('/oauth2/authorize', authorizeHandler);

  // Authorize Submit Endpoint (Form & Direct Submission)
  const authorizeSubmitHandler = (req: express.Request, res: express.Response) => {
    const authId = String(req.body.auth_id || '');
    const uin = String(req.body.uin || '8294017365');
    const otp = String(req.body.otp || '111111');
    const baseUrl = getBaseUrl(req);
    ssoEngine.setIssuer(baseUrl);

    const authResult = ssoEngine.authenticateWithOtp({
      auth_id: authId,
      uin,
      otp,
    });

    if (authResult.status !== 200) {
      if (req.headers.accept?.includes('text/html')) {
        return res.status(authResult.status).send(`
          <!DOCTYPE html><html><body style="font-family:sans-serif;padding:30px;background:#FEF2F2;color:#991B1B;">
          <h3>OTP Verification Failed</h3>
          <p>${authResult.body.error_description || 'Invalid UIN or OTP code'}</p>
          <a href="javascript:history.back()">Go back and try again</a>
          </body></html>
        `);
      }
      return res.status(authResult.status).json(authResult.body);
    }

    const consentResult = ssoEngine.submitConsent({
      auth_id: authId,
      accepted_scopes: ['openid', 'profile', 'email', 'phone', 'device_sso'],
      accepted_claims: ['name', 'email', 'phone_number', 'birthdate', 'gender', 'address'],
    });

    if (consentResult.status !== 200 || !consentResult.body.code) {
      return res.status(consentResult.status).json(consentResult.body);
    }

    const session = ssoEngine.authSessions.get(authId);
    const redirectBase =
      consentResult.body.redirect_uri ||
      session?.redirect_uri ||
      'io.mosip.inji.superwallet://oauth2redirect';
    const stateParam = session?.state ? `&state=${encodeURIComponent(session.state)}` : '';
    const deepLink = `${redirectBase}?code=${encodeURIComponent(consentResult.body.code)}${stateParam}`;

    if (req.headers.accept?.includes('application/json')) {
      return res.status(200).json({
        ...consentResult.body,
        deep_link: deepLink,
      });
    }

    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="refresh" content="0;url=${deepLink}">
        <title>Redirecting to Super App...</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #F8FAFC; padding: 24px; text-align: center; }
          .card { max-width: 440px; margin: 40px auto; background: #fff; padding: 32px 24px; border-radius: 16px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); border: 1px solid #E2E8F0; }
          .btn { display: inline-block; background: #0D47A1; color: #fff; text-decoration: none; padding: 14px 28px; border-radius: 10px; font-weight: bold; margin-top: 20px; font-size: 16px; }
        </style>
      </head>
      <body>
        <div class="card">
          <div style="font-size: 48px; margin-bottom: 12px;">✅</div>
          <h2>Authentication Approved</h2>
          <p style="color: #4B5563;">Returning to Inji Citizen Super App...</p>
          <a class="btn" href="${deepLink}">Open Super App</a>
        </div>
        <script>
          window.location.replace(${JSON.stringify(deepLink)});
        </script>
      </body>
      </html>
    `);
  };

  app.post('/api/oauth2/authorize-submit', authorizeSubmitHandler);
  app.post('/oauth2/authorize-submit', authorizeSubmitHandler);

  // 4. OTP Authentication Endpoint (POST /api/oauth2/authenticate & POST /oauth2/authenticate)
  const authHandler = (req: express.Request, res: express.Response) => {
    const baseUrl = getBaseUrl(req);
    ssoEngine.setIssuer(baseUrl);

    const result = ssoEngine.authenticateWithOtp({
      auth_id: String(req.body.auth_id || ''),
      uin: String(req.body.uin || ''),
      otp: String(req.body.otp || ''),
    });
    res.status(result.status).json(result.body);
  };

  app.post('/api/oauth2/authenticate', authHandler);
  app.post('/oauth2/authenticate', authHandler);

  // 5. Consent Approval Endpoint (POST /api/oauth2/consent & POST /oauth2/consent)
  const consentHandler = (req: express.Request, res: express.Response) => {
    const baseUrl = getBaseUrl(req);
    ssoEngine.setIssuer(baseUrl);

    const result = ssoEngine.submitConsent({
      auth_id: String(req.body.auth_id || ''),
      accepted_scopes: Array.isArray(req.body.accepted_scopes)
        ? req.body.accepted_scopes
        : ['openid', 'profile', 'email', 'device_sso'],
      accepted_claims: Array.isArray(req.body.accepted_claims)
        ? req.body.accepted_claims
        : ['name', 'email', 'phone_number', 'birthdate'],
    });
    res.status(result.status).json(result.body);
  };

  app.post('/api/oauth2/consent', consentHandler);
  app.post('/oauth2/consent', consentHandler);

  // 6. Token Endpoint (POST /api/oauth2/token & POST /oauth2/token)
  const tokenHandler = (req: express.Request, res: express.Response) => {
    const baseUrl = getBaseUrl(req);
    ssoEngine.setIssuer(baseUrl);

    const dpopHeader = String(req.headers['dpop'] || req.body.dpop_proof || '');
    const result = ssoEngine.handleTokenEndpoint({
      grant_type: String(req.body.grant_type || ''),
      client_id: String(req.body.client_id || ''),
      dpop_proof: dpopHeader,
      code: req.body.code ? String(req.body.code) : undefined,
      redirect_uri: req.body.redirect_uri ? String(req.body.redirect_uri) : undefined,
      code_verifier: req.body.code_verifier ? String(req.body.code_verifier) : undefined,
      subject_token: req.body.subject_token ? String(req.body.subject_token) : undefined,
      subject_token_type: req.body.subject_token_type
        ? String(req.body.subject_token_type)
        : undefined,
      actor_token: req.body.actor_token ? String(req.body.actor_token) : undefined,
      actor_token_type: req.body.actor_token_type ? String(req.body.actor_token_type) : undefined,
      audience: req.body.audience ? String(req.body.audience) : undefined,
      scope: req.body.scope ? String(req.body.scope) : undefined,
      bonus_reconsent_mode: Boolean(req.body.bonus_reconsent_mode),
      reconsent_approved: Boolean(req.body.reconsent_approved),
    });
    res.status(result.status).json(result.body);
  };

  app.post('/api/oauth2/token', tokenHandler);
  app.post('/oauth2/token', tokenHandler);

  // 7. UserInfo Endpoint (GET /api/oauth2/userinfo & GET /oauth2/userinfo)
  const userinfoHandler = (req: express.Request, res: express.Response) => {
    const baseUrl = getBaseUrl(req);
    ssoEngine.setIssuer(baseUrl);

    const authHeader = String(req.headers['authorization'] || '');
    const token = authHeader.replace(/^DPoP\s+/i, '').trim();
    const dpopHeader = String(req.headers['dpop'] || '');
    const result = ssoEngine.handleUserInfo({
      access_token: token,
      dpop_proof: dpopHeader,
    });
    res.status(result.status).json(result.body);
  };

  app.get('/api/oauth2/userinfo', userinfoHandler);
  app.get('/oauth2/userinfo', userinfoHandler);

  // 8. Session Revocation & Logout Endpoints
  const revokeHandler = (req: express.Request, res: express.Response) => {
    const baseUrl = getBaseUrl(req);
    ssoEngine.setIssuer(baseUrl);

    const result = ssoEngine.handleRevokeOrLogout({
      device_secret: req.body.device_secret ? String(req.body.device_secret) : undefined,
      id_token: req.body.id_token ? String(req.body.id_token) : undefined,
      sid: req.body.sid ? String(req.body.sid) : undefined,
      client_id: req.body.client_id ? String(req.body.client_id) : undefined,
    });
    res.status(result.status).json(result.body);
  };

  app.post('/api/oauth2/revoke', revokeHandler);
  app.post('/oauth2/revoke', revokeHandler);
  app.post('/api/oauth2/logout', revokeHandler);
  app.post('/oauth2/logout', revokeHandler);

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`eSignet Go & Thunder ID Native SSO Server running on port ${PORT}`);
  });
}

startServer();
