import { useEffect, useState } from 'react';
import { useAccount, useSignMessage } from 'wagmi';
import { Principal } from '@dfinity/principal';
import { anonymousBackendActor, backendActor } from '../lib/auth';
import { buildAdminMessage } from '../lib/message';
import {
  unwrap,
  type AdminHolderBundle,
  type AdminInfo,
  type BackendService,
} from '../lib/backend';
import { formatMultibtc, formatTsNs, shortAddress } from '../lib/format';
import { ConnectWalletButton } from '../components/ConnectWalletDialog';
import { AuthGate } from '../components/AuthGate';
import { PrincipalChip } from '../components/PrincipalChip';
import type { ActorSubclass } from '@dfinity/agent';

export function Admin() {
  return (
    <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6 space-y-6">
      <header className="space-y-1">
        <h1 className="text-2xl font-bold text-ink-900">Admin</h1>
        <p className="text-sm text-ink-600">
          Sign in with Internet Identity, then sign with the admin EVM wallet. Both must match
          the values configured by a canister controller.
        </p>
      </header>
      <AdminConfigPanel />
      <AuthGate>{({ principal }) => <AdminControls callerPrincipal={principal} />}</AuthGate>
    </div>
  );
}

function AdminConfigPanel() {
  const [info, setInfo] = useState<AdminInfo | null>(null);
  const [amController, setAmController] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [ethInput, setEthInput] = useState('');
  const [principalInput, setPrincipalInput] = useState('');

  async function load() {
    try {
      setError(null);
      const anon = await anonymousBackendActor();
      const i = await anon.get_admin_info();
      setInfo(i);
      setEthInput(i.eth_address);
      setPrincipalInput(i.principal[0]?.toText() ?? '');
      try {
        const actor = await backendActor();
        const cc = await actor.am_i_controller();
        setAmController(cc);
      } catch {
        setAmController(false);
      }
    } catch (e: any) {
      setError(e?.message ?? String(e));
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function saveEth() {
    setBusy(true);
    setError(null);
    try {
      const actor = await backendActor();
      unwrap(await actor.set_admin_eth_address(ethInput.trim()));
      await load();
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }
  async function savePrincipal() {
    setBusy(true);
    setError(null);
    try {
      const actor = await backendActor();
      const arg: [] | [Principal] =
        principalInput.trim() === '' ? [] : [Principal.fromText(principalInput.trim())];
      unwrap(await actor.set_admin_principal(arg));
      await load();
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <div className="card-header flex items-center justify-between">
        <div className="text-sm font-semibold text-ink-900">Admin configuration</div>
        {amController !== null && (
          <span
            className={`text-xs ${amController ? 'text-emerald-700' : 'text-ink-500'}`}
          >
            {amController ? 'You are a canister controller.' : 'Read-only (not a controller).'}
          </span>
        )}
      </div>
      <div className="card-body space-y-4">
        {info && (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 text-sm">
            <div>
              <div className="text-xs text-ink-500">Configured admin EVM wallet</div>
              <code className="font-mono break-all">{info.eth_address}</code>
            </div>
            <div>
              <div className="text-xs text-ink-500">Linked Internet Identity principal</div>
              <code className="font-mono break-all">
                {info.principal[0]?.toText() ?? '(none — admin auth disabled)'}
              </code>
            </div>
            <div>
              <div className="text-xs text-ink-500">Edit cap per principal</div>
              <span>{info.max_edits} edits</span>
            </div>
            <div>
              <div className="text-xs text-ink-500">Wallets cap per principal</div>
              <span>{info.max_wallets_per_principal.toString()} wallets</span>
            </div>
          </div>
        )}

        {amController && (
          <div className="rounded-md border border-ink-200 p-3 space-y-3 bg-ink-50">
            <p className="text-xs text-ink-600">
              As a canister controller you can change either value. The admin can call admin
              endpoints only when both match (signature recovers to the EVM wallet AND caller
              principal equals the linked principal).
            </p>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="block">
                <span className="field-label">Admin EVM wallet (0x…)</span>
                <div className="flex gap-2">
                  <input
                    className="field-input flex-1 font-mono"
                    value={ethInput}
                    onChange={(e) => setEthInput(e.target.value)}
                  />
                  <button
                    type="button"
                    className="btn-primary"
                    onClick={saveEth}
                    disabled={busy}
                  >
                    Save
                  </button>
                </div>
              </label>
              <label className="block">
                <span className="field-label">
                  Admin II principal (paste — leave empty to clear)
                </span>
                <div className="flex gap-2">
                  <input
                    className="field-input flex-1 font-mono"
                    placeholder="aaaaa-…"
                    value={principalInput}
                    onChange={(e) => setPrincipalInput(e.target.value)}
                  />
                  <button
                    type="button"
                    className="btn-primary"
                    onClick={savePrincipal}
                    disabled={busy}
                  >
                    Save
                  </button>
                </div>
              </label>
            </div>
          </div>
        )}
        {error && <div className="text-sm text-red-600">{error}</div>}
      </div>
    </div>
  );
}

function AdminControls({ callerPrincipal }: { callerPrincipal: Principal }) {
  const { address, isConnected } = useAccount();
  const { signMessageAsync } = useSignMessage();
  const [info, setInfo] = useState<AdminInfo | null>(null);
  const [bundles, setBundles] = useState<AdminHolderBundle[] | null>(null);
  const [csv, setCsv] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void (async () => {
      try {
        const anon = await anonymousBackendActor();
        setInfo(await anon.get_admin_info());
      } catch (e: any) {
        setError(e?.message ?? String(e));
      }
    })();
  }, []);

  const principalMatches = info?.principal[0]?.toText() === callerPrincipal.toText();
  const walletMatches =
    isConnected && info && address && address.toLowerCase() === info.eth_address.toLowerCase();

  async function adminFetch() {
    setError(null);
    setBusy(true);
    try {
      if (!walletMatches) throw new Error('Connect the configured admin EVM wallet first.');
      if (!principalMatches) throw new Error('Signed in with the wrong II principal for admin.');
      const actor = await backendActor();
      const auth = await produceAuth(actor);
      const list = unwrap(await actor.admin_list_holders_full(auth));
      setBundles(list);
      const auth2 = await produceAuth(actor);
      const csvText = unwrap(await actor.admin_export_csv(auth2));
      setCsv(csvText);
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  async function produceAuth(actor: ActorSubclass<BackendService>) {
    const nonce = unwrap(await actor.get_admin_nonce());
    const signed_at_iso = new Date().toISOString();
    const message = buildAdminMessage(signed_at_iso, nonce);
    const signature = await signMessageAsync({ message });
    return { signature, nonce, signed_at_iso };
  }

  function downloadCsv() {
    if (!csv) return;
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `multibtc-holders-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6">
      <div className="card">
        <div className="card-body space-y-3">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 text-xs">
            <div className="space-y-1">
              <PrincipalChip principal={callerPrincipal} />
              {info && (
                <div
                  className={`ml-1 ${
                    principalMatches ? 'text-emerald-700' : 'text-red-600'
                  }`}
                >
                  {principalMatches ? '✓ matches admin' : '✗ does not match admin'}
                </div>
              )}
            </div>
            <div>
              <span className="text-ink-500">Connected EVM wallet: </span>
              <code className="font-mono">{address ? shortAddress(address) : '(none)'}</code>
              {info && address && (
                <span
                  className={`ml-2 ${
                    walletMatches ? 'text-emerald-700' : 'text-red-600'
                  }`}
                >
                  {walletMatches ? '✓ matches admin' : '✗ does not match admin'}
                </span>
              )}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <ConnectWalletButton />
            <button
              type="button"
              className="btn-primary"
              onClick={adminFetch}
              disabled={!walletMatches || !principalMatches || busy}
            >
              {busy ? 'Working…' : 'Fetch + export'}
            </button>
            {csv && (
              <button type="button" className="btn-secondary" onClick={downloadCsv}>
                Download CSV
              </button>
            )}
          </div>
          {error && <div className="text-sm text-red-600">{error}</div>}
        </div>
      </div>

      {bundles && (
        <div className="card overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="bg-ink-50 text-ink-700">
              <tr>
                <th className="px-3 py-2 text-left">Principal</th>
                <th className="px-3 py-2 text-left">Legal name</th>
                <th className="px-3 py-2 text-left">Email</th>
                <th className="px-3 py-2 text-left">Country</th>
                <th className="px-3 py-2 text-left">Wallets</th>
                <th className="px-3 py-2 text-left">Total declared</th>
                <th className="px-3 py-2 text-left">Last revision</th>
              </tr>
            </thead>
            <tbody>
              {bundles.map((b, i) => {
                const total = b.wallets.reduce((acc, w) => {
                  const c =
                    w.approximate_total_claim[0] ??
                    w.detected_eth + w.detected_bsc + w.detected_polygon + w.detected_canto;
                  return acc + c;
                }, 0n);
                return (
                  <tr key={i} className="border-t border-ink-200">
                    <td className="px-3 py-2 font-mono text-xs">
                      {b.profile.principal.toText().slice(0, 12)}…
                    </td>
                    <td className="px-3 py-2">{b.profile.legal_name}</td>
                    <td className="px-3 py-2">{b.profile.email}</td>
                    <td className="px-3 py-2">{b.profile.country_of_residence}</td>
                    <td className="px-3 py-2">{b.wallets.length}</td>
                    <td className="px-3 py-2">{formatMultibtc(total)}</td>
                    <td className="px-3 py-2 text-xs">
                      {formatTsNs(b.profile.submitted_at_ns)}
                    </td>
                  </tr>
                );
              })}
              {bundles.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-3 py-6 text-center text-ink-500">
                    No holders verified yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
