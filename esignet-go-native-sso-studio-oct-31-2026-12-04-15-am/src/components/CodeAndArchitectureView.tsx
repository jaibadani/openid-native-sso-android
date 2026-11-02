import React, { useState } from 'react';
import { Code2, Copy, Check, GitBranch, Layers, ArrowRight } from 'lucide-react';
import {
  SOURCE_CODE_ARTIFACTS,
  MANDATORY_TASKS_CHECKLIST,
  type SourceCodeArtifact,
} from '../lib/codeAndDeliverablesData';

export const CodeAndArchitectureView: React.FC = () => {
  const [selectedFileId, setSelectedFileId] = useState<string>(SOURCE_CODE_ARTIFACTS[0].id);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [activeDiagram, setActiveDiagram] = useState<'super_app' | 'child_app'>('super_app');

  const selectedFile: SourceCodeArtifact =
    SOURCE_CODE_ARTIFACTS.find((f) => f.id === selectedFileId) || SOURCE_CODE_ARTIFACTS[0];

  const handleCopyCode = (file: SourceCodeArtifact) => {
    navigator.clipboard?.writeText(file.code);
    setCopiedId(file.id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  return (
    <div className="space-y-8">
      {/* Repository Source Code Explorer */}
      <section className="border border-slate-800 bg-slate-900/60 rounded-xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-800">
          <div>
            <h2 className="text-xl font-semibold text-white">
              eSignet Go, Thunder ID Engine, Android Kotlin, iOS Swift & CI Source Suite
            </h2>
            <p className="text-sm text-slate-400 mt-1">
              Production Golang, Android Kotlin, iOS Swift (Secure Enclave + Keychain Access Group),
              and GitHub Actions CI implementations spanning{' '}
              <code className="text-blue-300 font-mono">mosip/esignet (develop-go)</code> and{' '}
              <code className="text-blue-300 font-mono">thunder-id/thunderid</code>.
            </p>
          </div>
          <div className="text-xs text-slate-400 font-mono">
            <span>{SOURCE_CODE_ARTIFACTS.length} Core Modules</span>
            <span aria-hidden="true"> · </span>
            <span>10 Mandatory Tasks + Bonus + Revocation</span>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 pt-5">
          {/* File Sidebar */}
          <div className="lg:col-span-4 space-y-2.5">
            {SOURCE_CODE_ARTIFACTS.map((item) => {
              const isSelected = item.id === selectedFile.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setSelectedFileId(item.id)}
                  className={`w-full text-left p-3.5 rounded-lg border transition-colors ${
                    isSelected
                      ? 'bg-slate-800/90 border-blue-500/70 text-white'
                      : 'bg-slate-950/60 border-slate-800/90 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span className="font-mono flex items-center gap-1.5 text-blue-300">
                      <GitBranch className="w-3.5 h-3.5" />
                      {item.repo}
                    </span>
                    <span className="font-mono uppercase">{item.language}</span>
                  </div>
                  <div className="text-xs font-mono font-semibold text-slate-100 truncate">
                    {item.filePath}
                  </div>
                  <div className="text-xs text-slate-400 mt-1.5 line-clamp-2">{item.summary}</div>
                </button>
              );
            })}
          </div>

          {/* Code Viewer */}
          <div className="lg:col-span-8 border border-slate-800 bg-slate-950 rounded-xl overflow-hidden flex flex-col">
            <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 bg-slate-900 border-b border-slate-800">
              <div>
                <div className="text-xs font-mono text-blue-300">{selectedFile.filePath}</div>
                <div className="text-xs text-slate-400 mt-0.5">
                  {selectedFile.taskLabels.join(' · ')}
                </div>
              </div>
              <button
                type="button"
                onClick={() => handleCopyCode(selectedFile)}
                className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-md border border-slate-700 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                {copiedId === selectedFile.id ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Copied File</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy Source Code</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-4 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed max-h-[540px]">
              <code>{selectedFile.code}</code>
            </pre>
          </div>
        </div>
      </section>

      {/* Sequence Diagrams from Pages 3 & 4 of Problem Statement */}
      <section className="border border-slate-800 bg-slate-900/60 rounded-xl p-6 space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <h3 className="text-lg font-semibold text-white">
              Architectural Sequence Flows (Pages 3 & 4 Reference)
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              End-to-end cryptographic handoffs across Super App, Child App, Thunder ID Engine,
              DeviceSecretProvider, and ConsentProvider.
            </p>
          </div>

          <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-lg">
            <button
              type="button"
              onClick={() => setActiveDiagram('super_app')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                activeDiagram === 'super_app'
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              1. Super App PAR + DPoP Login
            </button>
            <button
              type="button"
              onClick={() => setActiveDiagram('child_app')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                activeDiagram === 'child_app'
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              2. Child App Silent SSO Token Exchange
            </button>
          </div>
        </div>

        {activeDiagram === 'super_app' ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[
              {
                step: '01. Hardware Key Generation & PAR',
                actors: 'Super App → Thunder ID Engine',
                detail:
                  'Generates TEE StrongBox EC P-256 Key A (never exported). Sends POST /oauth2/par with scope="openid profile email device_sso", code_challenge (S256), and dpop_jkt=<thumbprint(Key A)>. Receives 201 { request_uri }.',
              },
              {
                step: '02. Browser Authorize & OTP Factor',
                actors: 'System Browser (oidc-ui) → MOSIP IDA',
                detail:
                  'Opens GET /oauth2/authorize?request_uri=... User selects Login with OTP, enters Citizen UIN, verifies 6-digit OTP against MOSIP Identity Backend.',
              },
              {
                step: '03. Consent & Code Issuance',
                actors: 'System Browser → Thunder ID Engine',
                detail:
                  'User reviews requested PII claims and device_sso scope, taps Allow. Thunder ID issues authorization_code bound to dpop_jkt and redirects 302 to Super App.',
              },
              {
                step: '04. Token Request & Scope Check',
                actors: 'Super App → Thunder ID Engine',
                detail:
                  'Super App sends POST /oauth2/token with code, code_verifier, and DPoP proof signed by Key A. Thunder ID confirms allowed_authorization_scopes includes device_sso (Task 2).',
              },
              {
                step: '05. DeviceSecretProvider Issuance',
                actors: 'Thunder ID → DeviceSecretProvider → KeyManager',
                detail:
                  'Calls generate_device_secret(sub, auth_id, client_id, scope, acr, cnf={jkt: dpop_jkt}). Signs JWS then encrypts JWE (A256GCM). Computes ds_hash = BASE64URL(SHA256(device_secret)[0:16]).',
              },
              {
                step: '06. Token Storage & /userinfo',
                actors: 'Super App ↔ Thunder ID Engine',
                detail:
                  'Embeds ds_hash + sid into id_token. Returns { access_token, id_token, device_secret }. Super App persists id_token + device_secret in private vault and fetches /oauth2/userinfo with DPoP proof.',
              },
            ].map((card) => (
              <div
                key={card.step}
                className="border border-slate-800 bg-slate-950/80 rounded-lg p-4 space-y-2"
              >
                <div className="text-xs font-mono text-blue-400">{card.actors}</div>
                <h4 className="text-sm font-semibold text-white">{card.step}</h4>
                <p className="text-xs text-slate-400 leading-relaxed">{card.detail}</p>
              </div>
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[
              {
                step: '01. Android bindService() & Vendor Cert Check',
                actors: 'Child App → Super App (SSO Signing Service)',
                detail:
                  'Child App binds to Super App signature-protected Bound Service. Super App verifies caller package X.509 certificate matches the exact vendor certificate.',
              },
              {
                step: '02. Hardware Key A DPoP Signing',
                actors: 'Super App (Key A) → Child App',
                detail:
                  'Super App constructs a fresh DPoP proof (htm=POST, htu=/oauth2/token, fresh iat/jti) signed by Key A inside Super App process, and returns { id_token, device_secret, dpop_proof }.',
              },
              {
                step: '03. OAuth 2.0 Token Exchange Call',
                actors: 'Child App → Thunder ID Engine',
                detail:
                  'POST /oauth2/token with grant_type=token-exchange, subject_token=id_token, actor_token=device_secret, actor_token_type=device-secret, scope (without device_sso), and DPoP header.',
              },
              {
                step: '04. ValidateDeviceSecret & Cryptographic Checks',
                actors: 'Thunder ID → DeviceSecretProvider (eSignet)',
                detail:
                  'Decrypts JWE, verifies JWS, checks Child App is in org_client_id allowlist. Verifies DPoP jkt == device_secret.cnf.jkt, recomputes ds_hash == id_token.ds_hash, and verifies sid == auth_id.',
              },
              {
                step: '05. ResolveConsent & Scope Subset Rule',
                actors: 'Thunder ID → ConsentProvider',
                detail:
                  'Rejects if device_sso is requested. Checks requested_scope is a subset of Super App consented scope. Appends silent audit trail row (NOCAPTURE) or triggers Bonus Re-Consent if scopes differ.',
              },
              {
                step: '06. Issue DPoP Token & Fetch /userinfo',
                actors: 'Child App ↔ Super App ↔ Thunder ID',
                detail:
                  'Binds Child App access_token to the SAME cnf.jkt (Key A). Child App requests a GET /userinfo DPoP proof (with ath) from Super App and fetches scoped citizen claims.',
              },
            ].map((card) => (
              <div
                key={card.step}
                className="border border-slate-800 bg-slate-950/80 rounded-lg p-4 space-y-2"
              >
                <div className="text-xs font-mono text-emerald-400">{card.actors}</div>
                <h4 className="text-sm font-semibold text-white">{card.step}</h4>
                <p className="text-xs text-slate-400 leading-relaxed">{card.detail}</p>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Complete 10 + 1 Mandatory Tasks Traceability Table */}
      <section className="border border-slate-800 bg-slate-900/60 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-white mb-4">
          Specification Compliance Matrix (Mandatory Tasks 1–10 & Bonus Task)
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-xs text-slate-400">
                <th className="py-2.5 pr-4 font-medium">Task</th>
                <th className="py-2.5 px-4 font-medium">Repository Target</th>
                <th className="py-2.5 px-4 font-medium">Requirement</th>
                <th className="py-2.5 pl-4 font-medium">Implementation Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 text-xs">
              {MANDATORY_TASKS_CHECKLIST.map((item) => (
                <tr key={item.number} className="hover:bg-slate-800/30">
                  <td className="py-3 pr-4 font-mono font-semibold text-blue-400 tabular-nums">
                    {item.number}
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-300 whitespace-nowrap">
                    {item.repoTag}
                  </td>
                  <td className="py-3 px-4 font-medium text-white">{item.title}</td>
                  <td className="py-3 pl-4 text-slate-400">{item.specDetail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
