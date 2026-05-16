# multiBTC Holders — Verification & Authorization Portal

A coordinated‑claim portal for **multiBTC** holders pursuing asset‑specific recovery in the **Multichain Foundation Ltd.** liquidation.

- **Live:** https://7wy2p-aqaaa-aaaah-quska-cai.icp0.io/
- **Court records:**
  - Singapore High Court — **HC/CWU 134/2025** (KPMG liquidator, May 2025)
  - U.S. Bankruptcy Court SDNY — **Case 25‑12340‑DSJ**

Every wallet attestation is cryptographically signed by the holder's EVM key, bound to a continuous **Internet Identity** session, stored with full revision history on the **Internet Computer**, and rendered as an admissible evidentiary record for KPMG and the courts.

---

## What the portal does

The portal collects evidence sufficient for three independent downstream consumers:

| Layer | Purpose | Captured fields |
|---|---|---|
| **1 — Identity** | Solicitor retainer | legal name, DOB, nationality, country of residence, email, Telegram, preferred comm channel |
| **2 — Wallets & holdings** | Claim quantification | EVM addresses (up to 5 per holder), per‑wallet ECDSA signatures, detected balances on Ethereum / BSC / Polygon / Canto, position type (raw / LP / vault / other) + protocol, bridge‑redemption tx hashes, pre‑/post‑incident timing, post‑incident acquisition history, supporting tx hashes (up to 10) |
| **3 — KPMG PoD status** | Liquidator coordination | filed yes/no, date, reference number, needs‑help flag |
| **4 — Authorization** | Group representation mandate | explicit consent to be represented, fee‑structure ack, group‑coordination ack, penalty‑of‑perjury truthfulness attestation — committed by the per‑wallet signature |
| **5 — Funding** | Funding model | upfront cost‑share / proportional to claim / litigation funding / undecided + preferred payment method |
| **6 — Optional** | Strength of record | naming preference, other Multichain token claims, supporting documentation notes |

Each per‑wallet attestation is signed via **EIP‑191 `personal_sign`** against a canonical message that includes the wallet address, the linked II principal, the revision number, a **SHA‑256 commitment** to every form field, an ISO‑8601 timestamp, and a server‑issued UUID nonce. The backend re‑computes the commitment, re‑builds the canonical message, recovers the signer via `k256`, and only persists the record when the recovered address matches the claimed wallet. Edits never overwrite — each `update_*` call appends a new revision to a stable log so the full audit trail is retrievable per holder and per wallet.

---

## Architecture

```
                  ┌──────────────────────────────────────┐
                  │  id.ai (Internet Identity)           │
                  └──────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│  Frontend asset canister (React + Vite + Tailwind + wagmi v2)    │
│  • II login → Principal                                          │
│  • EVM wallets via injected/EIP-6963 + WalletConnect + Coinbase  │
│  • balanceOf() on 4 chains via viem fallback() racing many RPCs  │
│  • Canonical message → personal_sign → submit                    │
│  • Multi-wallet add, edit with full revision history             │
└──────────────────────────────────────────────────────────────────┘
                                  │ candid (agent-js, II-authenticated)
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│  Backend canister (Rust + ic-cdk + ic-stable-structures + k256)  │
│  • link_wallet (1 principal ↔ N≤5 wallets)                       │
│  • submit_holder / update_holder (revisioned, capped at 20)      │
│  • submit_wallet_attestation / update_wallet_attestation         │
│    (revisioned, capped at 20, EIP-191 signature verified)        │
│  • get_my_*, get_*_revisions, get_public_stats                   │
│  • Controller-configurable dual-factor admin                     │
│    (caller principal == admin AND signature recovers to admin EVM)│
└──────────────────────────────────────────────────────────────────┘
```

### Mainnet deployment

| Canister | ID | Subnet |
|---|---|---|
| backend | `7d7lc-byaaa-aaaah-qusjq-cai` | `pjljw-kztyl-46ud4-ofrj6-nzkhm-3n4nt-wi3jt-ypmav-ijqkt-gjf66-uae` |
| frontend | `7wy2p-aqaaa-aaaah-quska-cai` | same |
| Internet Identity | `rdmx6-jaaaa-aaaaa-aaadq-cai` (id.ai) | — |

Both project canisters intentionally share a subnet (created with `--no-wallet --next-to`) so inter‑canister calls stay local.

### multiBTC contracts indexed

| Chain | Address | Chain ID |
|---|---|---|
| Ethereum | `0x66eFF5221ca926636224650Fd3B9c497FF828F7D` | 1 |
| BSC | `0xD9907fcDa91aC644F70477B8fC1607ad15b2D7A8` | 56 |
| Polygon | `0xf5b9b4A0534cf508ab9953c64c5310DFa0B303A1` | 137 |
| Canto | `0x80A16016cC4A2E6a2CACA8a4a498b1699fF0f844` | 7700 |

All ERC‑20 with 8 decimals (same as BTC).

---

## Repository layout

```
multichain/
├── dfx.json                       # canister declarations (backend / frontend / II)
├── canister_ids.json              # mainnet canister IDs (pinned)
├── Cargo.toml                     # Rust workspace
├── src/
│   ├── backend/                   # Rust canister
│   │   ├── Cargo.toml
│   │   ├── backend.did            # candid interface
│   │   └── src/
│   │       ├── lib.rs             # endpoints + caller checks
│   │       ├── types.rs           # HolderProfile, WalletAttestation, payloads
│   │       ├── message.rs         # link / attest / admin canonical messages
│   │       ├── commitment.rs      # canonical-form-data serialiser + sha256
│   │       ├── verify.rs          # EIP-191 personal_sign recovery (k256)
│   │       └── nonce.rs           # raw_rand UUID v4
│   └── frontend/                  # React asset canister
│       ├── package.json
│       ├── vite.config.ts
│       ├── tailwind.config.js
│       └── src/
│           ├── App.tsx
│           ├── main.tsx
│           ├── pages/             # Landing, Verify, Dashboard, Admin
│           ├── components/        # AuthGate, ConnectWalletDialog, HolderForm,
│           │                      # WalletsPanel, WalletAttestationForm,
│           │                      # editors, PrincipalChip, etc.
│           └── lib/               # auth, wagmi (4-chain fallback pools),
│                                  # contracts, backend (IDL + actor),
│                                  # message, dataCommitment, format
└── README.md
```

---

## Build & run

### Prerequisites
- `dfx` ≥ 0.30
- Rust stable with `wasm32-unknown-unknown` target
- Node ≥ 20

### Local development

```bash
# Start a clean local replica
dfx start --background --clean

# Install frontend dependencies (once)
cd src/frontend && npm install && cd ../..

# Deploy backend + frontend + a local Internet Identity canister
dfx deploy

# Build the frontend bundle with the local .env (canister IDs etc.)
cd src/frontend && npm run build && cd ../..

# Re-deploy just the frontend canister with the fresh bundle
dfx deploy frontend
```

The deploy log prints local URLs for each canister. The local II is pinned to a known monolithic dev build via [`dfx.json`](dfx.json) so the certified path serves correctly.

### Tests

```bash
# Backend — unit tests for message construction, canonical commitment,
# EIP-191 signature recovery against an ethers.js golden fixture.
cargo test -p backend

# Frontend — Vitest cross-language parity tests assert byte-equality
# between the TS canonical-message + commit serialisers and the Rust ones.
cd src/frontend && npm test
```

### Mainnet deployment

```bash
# (Once) convert ICP -> cycles in the cycles ledger
dfx --identity launch cycles convert --amount 1.0 --network ic

# (Once) create canisters with --no-wallet, on the same subnet
dfx --identity launch canister create backend  --network ic --no-wallet --with-cycles 1500000000000
dfx --identity launch canister create frontend --network ic --no-wallet --with-cycles 1000000000000 --next-to <backend-id>

# Deploy
dfx --identity launch deploy --network ic --no-wallet
```

Production builds embed `DFX_NETWORK=ic` so the frontend talks to `id.ai` and `icp0.io` rather than the local replica.

---

## Security model

### Per-wallet attestation
1. User authenticates via Internet Identity → gets a Principal P.
2. User connects an EOA, calls `get_link_nonce(addr)`; backend stores a single‑use nonce for `addr`.
3. Frontend builds the **linking message** binding `addr ↔ P`, the user signs it, frontend calls `link_wallet`.
4. Backend recovers the signer via `k256::ecdsa::VerifyingKey::recover_from_prehash` and atomically writes both directions of the `addr ↔ P` map — rejecting if the wallet is already bound to a different principal, or recovery doesn't match.
5. For each wallet, the user fills the attestation form and clicks Sign. The frontend computes a **deterministic canonical serialisation** of the form data (sorted line‑oriented, hex‑encoded string values) and SHA‑256s it. That commit hex goes into the **attestation message** along with `(wallet, principal, revision, ISO timestamp, server nonce)`.
6. Wallet signs via `personal_sign`. Frontend submits the signature, the payload, and the commit.
7. Backend re‑computes the commit from the payload, compares — rejects on mismatch. Re‑builds the attestation message, recovers the signer, compares to the claimed wallet — rejects on mismatch. Consumes the nonce, writes revision N.

Smart‑contract wallets (Coinbase Smart Wallet, Safe, Argent, ERC‑4337) are **not** supported because their signatures recover to the owner EOA, not the smart account. The UI explicitly warns; the connector list is EOA‑only.

### Admin
Dual‑factor:
1. Caller's II principal must equal the configured `admin_principal`.
2. ECDSA signature over the admin message must recover to the configured `admin_eth_address`.

`set_admin_eth_address` and `set_admin_principal` are gated by `ic_cdk::api::is_controller(&caller)`, so only canister controllers can rotate either value. Live admin config is readable via `get_admin_info` (public).

### Caps
- `MAX_EDITS = 20` revisions per holder profile and per wallet attestation.
- `MAX_WALLETS_PER_PRINCIPAL = 5`.
- 10 supporting tx hashes max per wallet.
- 15‑minute TTL on every nonce, single‑use.

---

## Disclaimer

This portal is operated by a coordinated group of multiBTC holders. **It is not affiliated with KPMG, the Multichain Foundation, or any court.** A formal engagement letter / retainer from the appointed Singapore solicitor follows off‑platform once that solicitor is retained. The data collected here is used solely for that legal coordination.
