import { useCallback, useEffect, useState } from 'react';
import { AuthGate } from '../components/AuthGate';
import { HolderForm } from '../components/HolderForm';
import { WalletsPanel } from '../components/WalletsPanel';
import { PrincipalChip } from '../components/PrincipalChip';
import { backendActor } from '../lib/auth';
import type { HolderProfile, WalletAttestation } from '../lib/backend';
import type { Principal } from '@dfinity/principal';

export function Verify() {
  return (
    <div className="mx-auto max-w-3xl px-4 py-10 sm:px-6 space-y-6">
      <header className="space-y-1">
        <h1 className="text-2xl font-bold text-ink-900">Verify your wallet &amp; authorize</h1>
        <p className="text-sm text-ink-600">
          Sign in with Internet Identity, save your holder profile, then link and sign for each
          wallet you control.
        </p>
      </header>
      <AuthGate>
        {({ principal, logout }) => (
          <VerifyContent principal={principal} onLogout={logout} />
        )}
      </AuthGate>
    </div>
  );
}

function VerifyContent({
  principal,
  onLogout,
}: {
  principal: Principal;
  onLogout: () => Promise<void>;
}) {
  const [holder, setHolder] = useState<HolderProfile | null>(null);
  const [wallets, setWallets] = useState<WalletAttestation[]>([]);
  const [linkedAddrs, setLinkedAddrs] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setError(null);
      const actor = await backendActor();
      const [h, ws, addrs] = await Promise.all([
        actor.get_my_holder(),
        actor.get_my_wallets(),
        actor.get_wallets_for_principal(),
      ]);
      setHolder(h[0] ?? null);
      setWallets(ws);
      setLinkedAddrs(addrs);
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  if (loading) return <div className="text-sm text-ink-500">Loading your record…</div>;

  return (
    <div className="space-y-6">
      <div className="card">
        <div className="card-body flex items-center justify-between flex-wrap gap-3">
          <PrincipalChip principal={principal} label="Signed in as" />
          <button type="button" className="btn-secondary" onClick={onLogout}>
            Sign out
          </button>
        </div>
      </div>

      {error && <div className="card"><div className="card-body text-sm text-red-600">{error}</div></div>}

      <HolderForm initial={holder} onSaved={(h) => setHolder(h)} />

      {holder ? (
        <WalletsPanel
          principal={principal}
          wallets={wallets}
          linkedAddresses={linkedAddrs}
          reload={reload}
        />
      ) : (
        <div className="card">
          <div className="card-body text-sm text-ink-600">
            Save your holder profile first — then you can link wallets and submit per-wallet
            attestations.
          </div>
        </div>
      )}
    </div>
  );
}
