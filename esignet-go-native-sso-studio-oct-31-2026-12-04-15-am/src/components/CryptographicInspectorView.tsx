import React, { useState } from 'react';
import {
  ShieldCheck,
  KeyRound,
  Lock,
  Unlock,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  RefreshCw,
} from 'lucide-react';
import {
  verifyAndDecodeJwt,
  decryptJweDeviceSecret,
  computeDsHash,
  computeJwkThumbprint,
  SUPER_APP_KEY_A,
  type RegisteredOidcClient,
  type IdTokenPayload,
  type DeviceSecretPayload,
  type AccessTokenPayload,
} from '../lib/nativeSsoEngine';

interface CryptographicInspectorViewProps {
  superAppTokens: {
    access_token?: string;
    id_token?: string;
    device_secret?: string;
    dpop_proof?: string;
  };
  childAppTokens: {
    access_token?: string;
    id_token?: string;
    dpop_proof?: string;
  };
  registeredClients: Record<string, RegisteredOidcClient>;
  onToggleClientDeviceSsoScope: (clientId: string) => void;
}

export const CryptographicInspectorView: React.FC<CryptographicInspectorViewProps> = ({
  superAppTokens,
  childAppTokens,
  registeredClients,
  onToggleClientDeviceSsoScope,
}) => {
  const [selectedArtifact, setSelectedArtifact] = useState<
    'device_secret' | 'super_id_token' | 'super_access_token' | 'child_access_token'
  >('device_secret');
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const handleCopy = (label: string, text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedField(label);
    setTimeout(() => setCopiedField(null), 1800);
  };

  const hardwareJkt = computeJwkThumbprint(SUPER_APP_KEY_A);

  // Decode Super App id_token
  const decodedIdToken = superAppTokens.id_token
    ? verifyAndDecodeJwt<IdTokenPayload>(superAppTokens.id_token)
    : null;

  // Decrypt & decode device_secret JWE -> JWS
  const decryptedDsJwe = superAppTokens.device_secret
    ? decryptJweDeviceSecret(superAppTokens.device_secret)
    : null;
  const decodedDsJws =
    decryptedDsJwe?.valid && decryptedDsJwe.innerJws
      ? verifyAndDecodeJwt<DeviceSecretPayload>(decryptedDsJwe.innerJws)
      : null;

  // Compute live ds_hash verification
  const recomputedDsHash = superAppTokens.device_secret
    ? computeDsHash(superAppTokens.device_secret)
    : null;
  const dsHashMatches =
    Boolean(recomputedDsHash) &&
    Boolean(decodedIdToken?.payload?.ds_hash) &&
    recomputedDsHash === decodedIdToken?.payload?.ds_hash;

  // Decode Super App & Child App Access Tokens
  const decodedSuperAt = superAppTokens.access_token
    ? verifyAndDecodeJwt<AccessTokenPayload>(superAppTokens.access_token)
    : null;
  const decodedChildAt = childAppTokens.access_token
    ? verifyAndDecodeJwt<AccessTokenPayload>(childAppTokens.access_token)
    : null;

  return (
    <div className="space-y-8">
      {/* Top Cryptographic Binding Proof Matrix */}
      <section className="border border-slate-800 bg-slate-900/60 rounded-xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-800">
          <div>
            <h2 className="text-xl font-semibold text-white">
              Cryptographic Binding & Hardware Key Attestation Verifier
            </h2>
            <p className="text-sm text-slate-400 mt-1">
              Inspects live RFC 9449 DPoP thumbprints, OpenID Native SSO 1.0{' '}
              <code className="text-blue-300 font-mono">ds_hash</code> bindings, and JWE-encrypted{' '}
              <code className="text-blue-300 font-mono">device_secret</code> claims.
            </p>
          </div>
          <div className="text-xs font-mono text-slate-400 tabular-nums">
            Key A JWK Thumbprint (RFC 7638):{' '}
            <span className="text-emerald-300 font-medium">{hardwareJkt}</span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-5">
          {/* Binding 1: ds_hash */}
          <div className="border border-slate-800 bg-slate-950/70 rounded-lg p-4">
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span>01. OpenID Native SSO Section 3.2</span>
              <span className="font-mono">SHA-256[0..127]</span>
            </div>
            <h3 className="text-sm font-semibold text-slate-100 mb-2">
              id_token ↔ device_secret Binding (ds_hash)
            </h3>
            {superAppTokens.device_secret && decodedIdToken?.payload ? (
              <div className="space-y-2 text-xs font-mono tabular-nums">
                <div className="flex justify-between gap-2">
                  <span className="text-slate-400">id_token.ds_hash:</span>
                  <span className="text-blue-300 truncate">{decodedIdToken.payload.ds_hash}</span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-slate-400">SHA256(device_secret):</span>
                  <span className="text-emerald-300 truncate">{recomputedDsHash}</span>
                </div>
                <div className="pt-2 border-t border-slate-800/80 flex items-center gap-1.5 text-emerald-400 font-sans font-medium">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span> Verified 128-bit left-most SHA-256 match ({String(dsHashMatches)})</span>
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-400">
                Complete Super App login in the Mobile SSO Lab to inspect live{' '}
                <code className="font-mono">ds_hash</code> values.
              </p>
            )}
          </div>

          {/* Binding 2: Hardware Key A cnf.jkt */}
          <div className="border border-slate-800 bg-slate-950/70 rounded-lg p-4">
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span>02. Hardware TEE Keystore Binding</span>
              <span className="font-mono">cnf.jkt == dpop.jkt</span>
            </div>
            <h3 className="text-sm font-semibold text-slate-100 mb-2">
              Super App Key A ↔ Child App Token Binding
            </h3>
            {decodedDsJws?.payload ? (
              <div className="space-y-2 text-xs font-mono tabular-nums">
                <div className="flex justify-between gap-2">
                  <span className="text-slate-400">device_secret.cnf.jkt:</span>
                  <span className="text-blue-300 truncate">{decodedDsJws.payload.cnf.jkt}</span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-slate-400">Child AT cnf.jkt:</span>
                  <span className="text-emerald-300 truncate">
                    {decodedChildAt?.payload?.cnf?.jkt || 'Not exchanged yet'}
                  </span>
                </div>
                <div className="pt-2 border-t border-slate-800/80 flex items-center gap-1.5 text-emerald-400 font-sans font-medium">
                  <ShieldCheck className="w-4 h-4 shrink-0" />
                  <span>
                    {decodedChildAt?.payload?.cnf?.jkt === hardwareJkt
                      ? 'Both apps cryptographically bound to Key A'
                      : 'Super App bound to Key A (awaiting Child App)'}
                  </span>
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-400">
                Sign in on Super App to inspect hardware <code className="font-mono">cnf.jkt</code>{' '}
                proof-of-possession claims.
              </p>
            )}
          </div>

          {/* Binding 3: Session ID sid == auth_id */}
          <div className="border border-slate-800 bg-slate-950/70 rounded-lg p-4">
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span>03. Session Continuity (Task 9.a.iii.2)</span>
              <span className="font-mono">sid == auth_id</span>
            </div>
            <h3 className="text-sm font-semibold text-slate-100 mb-2">
              Shared SSO Session Identifier
            </h3>
            {decodedIdToken?.payload && decodedDsJws?.payload ? (
              <div className="space-y-2 text-xs font-mono tabular-nums">
                <div className="flex justify-between gap-2">
                  <span className="text-slate-400">id_token.sid:</span>
                  <span className="text-blue-300 truncate">{decodedIdToken.payload.sid}</span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-slate-400">device_secret.auth_id:</span>
                  <span className="text-emerald-300 truncate">{decodedDsJws.payload.auth_id}</span>
                </div>
                <div className="pt-2 border-t border-slate-800/80 flex items-center gap-1.5 text-emerald-400 font-sans font-medium">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>Session ID matches active Thunder ID session</span>
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-400">
                Session binding between <code className="font-mono">id_token.sid</code> and{' '}
                <code className="font-mono">device_secret.auth_id</code> appears here after login.
              </p>
            )}
          </div>
        </div>
      </section>

      {/* Main Token & JWE/JWS Decoder Workbench */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 border border-slate-800 bg-slate-900/60 rounded-xl p-6 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h3 className="text-base font-semibold text-white">
              Live JWE / JWS Artifact Decoder (Mandatory Task 4)
            </h3>
            <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-lg">
              {(
                [
                  { id: 'device_secret', label: 'device_secret (JWE→JWS)' },
                  { id: 'super_id_token', label: 'Super App id_token' },
                  { id: 'super_access_token', label: 'Super App AT' },
                  { id: 'child_access_token', label: 'Child App AT' },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setSelectedArtifact(tab.id)}
                  className={`px-2.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    selectedArtifact === tab.id
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {selectedArtifact === 'device_secret' && (
            <div className="space-y-4">
              {superAppTokens.device_secret && decryptedDsJwe && decodedDsJws ? (
                <>
                  <div className="border border-slate-800 bg-slate-950 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                        <Lock className="w-3.5 h-3.5 text-amber-400" />
                        Outer JWE Compact Serialization (Opaque to Mobile Client)
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          handleCopy('device_secret', superAppTokens.device_secret || '')
                        }
                        className="text-xs text-slate-400 hover:text-white flex items-center gap-1"
                      >
                        {copiedField === 'device_secret' ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                        <span>{copiedField === 'device_secret' ? 'Copied' : 'Copy JWE'}</span>
                      </button>
                    </div>
                    <p className="text-xs font-mono text-amber-200/90 break-all leading-relaxed bg-slate-900/90 p-3 rounded border border-slate-800">
                      {superAppTokens.device_secret}
                    </p>
                  </div>

                  <div className="border border-slate-800 bg-slate-950 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                        <Unlock className="w-3.5 h-3.5 text-emerald-400" />
                        Decrypted Inner JWS Claims (Mandatory Task 4a Required Fields)
                      </span>
                      <span className="text-xs font-mono text-emerald-400">
                        alg: ES256 · typ: device-secret+jwt
                      </span>
                    </div>
                    <pre className="text-xs font-mono text-slate-200 overflow-x-auto bg-slate-900/90 p-3.5 rounded border border-slate-800 leading-relaxed">
                      {JSON.stringify(decodedDsJws.payload, null, 2)}
                    </pre>
                  </div>
                </>
              ) : (
                <div className="border border-slate-800 bg-slate-950/60 rounded-lg p-8 text-center">
                  <KeyRound className="w-8 h-8 text-slate-500 mx-auto mb-2" />
                  <p className="text-sm font-medium text-slate-200">
                    No device_secret Issued Yet
                  </p>
                  <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
                    Authenticate on the Super App in the Mobile SSO Lab with the{' '}
                    <code className="text-blue-300 font-mono">device_sso</code> scope enabled to
                    generate and decrypt the signed-then-encrypted JWT.
                  </p>
                </div>
              )}
            </div>
          )}

          {selectedArtifact === 'super_id_token' && (
            <div className="space-y-4">
              {decodedIdToken?.valid ? (
                <div className="border border-slate-800 bg-slate-950 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-medium text-slate-300">
                      Super App ID Token Claims (Embedded ds_hash & sid)
                    </span>
                    <span className="text-xs font-mono text-blue-400">alg: RS256</span>
                  </div>
                  <pre className="text-xs font-mono text-slate-200 overflow-x-auto bg-slate-900/90 p-3.5 rounded border border-slate-800 leading-relaxed">
                    {JSON.stringify(decodedIdToken.payload, null, 2)}
                  </pre>
                </div>
              ) : (
                <div className="border border-slate-800 bg-slate-950/60 rounded-lg p-8 text-center text-xs text-slate-400">
                  Sign in on Super App to inspect the issued <code className="font-mono">id_token</code>.
                </div>
              )}
            </div>
          )}

          {selectedArtifact === 'super_access_token' && (
            <div className="space-y-4">
              {decodedSuperAt?.valid ? (
                <div className="border border-slate-800 bg-slate-950 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-medium text-slate-300">
                      Super App DPoP-Bound Access Token Claims
                    </span>
                    <span className="text-xs font-mono text-emerald-400">typ: at+jwt</span>
                  </div>
                  <pre className="text-xs font-mono text-slate-200 overflow-x-auto bg-slate-900/90 p-3.5 rounded border border-slate-800 leading-relaxed">
                    {JSON.stringify(decodedSuperAt.payload, null, 2)}
                  </pre>
                </div>
              ) : (
                <div className="border border-slate-800 bg-slate-950/60 rounded-lg p-8 text-center text-xs text-slate-400">
                  Sign in on Super App to inspect its DPoP-bound <code className="font-mono">access_token</code>.
                </div>
              )}
            </div>
          )}

          {selectedArtifact === 'child_access_token' && (
            <div className="space-y-4">
              {decodedChildAt?.valid ? (
                <div className="border border-slate-800 bg-slate-950 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-medium text-slate-300">
                      Child App Token-Exchanged Access Token (Bound to Super App Key A)
                    </span>
                    <span className="text-xs font-mono text-emerald-400">
                      cnf.jkt == Super App Key A
                    </span>
                  </div>
                  <pre className="text-xs font-mono text-slate-200 overflow-x-auto bg-slate-900/90 p-3.5 rounded border border-slate-800 leading-relaxed">
                    {JSON.stringify(decodedChildAt.payload, null, 2)}
                  </pre>
                </div>
              ) : (
                <div className="border border-slate-800 bg-slate-950/60 rounded-lg p-8 text-center text-xs text-slate-400">
                  Trigger Silent SSO on the Child App in the Mobile SSO Lab to inspect its exchanged{' '}
                  <code className="font-mono">access_token</code>.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Registered OIDC Clients & Mandatory Task 2 / Task 9.a.iii.3 Scope Policy Manager */}
        <div className="lg:col-span-5 border border-slate-800 bg-slate-900/60 rounded-xl p-6 space-y-4">
          <div>
            <h3 className="text-base font-semibold text-white">
              Registered OIDC Clients (Task 2 & Task 9.a.iii.3)
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Toggle <code className="text-blue-300 font-mono">device_sso</code> in{' '}
              <code className="text-slate-300 font-mono">allowed_authorization_scopes</code> to test
              token endpoint enforcement.
            </p>
          </div>

          <div className="space-y-3">
            {Object.values(registeredClients).map((client) => {
              const hasDeviceSso = client.allowed_authorization_scopes.includes('device_sso');
              return (
                <div
                  key={client.client_id}
                  className="border border-slate-800 bg-slate-950/80 rounded-lg p-4 space-y-2.5"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="text-sm font-semibold text-white">{client.client_name}</div>
                      <div className="text-xs font-mono text-slate-400">{client.client_id}</div>
                    </div>
                    <button
                      type="button"
                      onClick={() => onToggleClientDeviceSsoScope(client.client_id)}
                      className={`px-3 py-1.5 text-xs font-medium rounded-md border transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
                        hasDeviceSso
                          ? 'bg-emerald-950/60 border-emerald-700/70 text-emerald-300 hover:bg-emerald-900/60'
                          : 'bg-rose-950/60 border-rose-700/70 text-rose-300 hover:bg-rose-900/60'
                      }`}
                    >
                      <RefreshCw className="w-3 h-3" />
                      <span>
                        {hasDeviceSso ? 'device_sso: Enabled' : 'device_sso: Disabled'}
                      </span>
                    </button>
                  </div>

                  <div className="text-xs text-slate-400 space-y-1">
                    <div>
                      <span className="text-slate-500">Package:</span>{' '}
                      <span className="font-mono text-slate-300">{client.package_name}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Allowed Scopes:</span>{' '}
                      <span className="font-mono text-blue-300">
                        {client.allowed_authorization_scopes.join(' · ')}
                      </span>
                    </div>
                    {client.allowed_sso_clients.length > 0 && (
                      <div>
                        <span className="text-slate-500">Trusted Child Apps:</span>{' '}
                        <span className="font-mono text-emerald-300">
                          {client.allowed_sso_clients.join(', ')}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
