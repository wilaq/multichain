mod commitment;
mod message;
mod nonce;
mod types;
mod verify;

use candid::Principal;
use ic_cdk::api::{caller, is_controller, time};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use std::cell::RefCell;

use crate::types::*;

type Mem = VirtualMemory<DefaultMemoryImpl>;

// Memory ids for stable structures. Append-only — never reuse a freed id.
const MEM_WALLET_TO_PRINCIPAL: MemoryId = MemoryId::new(0);
const MEM_PRINCIPAL_WALLETS: MemoryId = MemoryId::new(1);
const MEM_HOLDER_LATEST: MemoryId = MemoryId::new(2);
const MEM_HOLDER_REVISIONS: MemoryId = MemoryId::new(3);
const MEM_WALLET_LATEST: MemoryId = MemoryId::new(4);
const MEM_WALLET_REVISIONS: MemoryId = MemoryId::new(5);
const MEM_LINK_NONCES: MemoryId = MemoryId::new(6);
const MEM_ATTEST_NONCES: MemoryId = MemoryId::new(7);
const MEM_ADMIN_NONCES: MemoryId = MemoryId::new(8);
const MEM_ADMIN_ETH: MemoryId = MemoryId::new(9);
const MEM_ADMIN_PRINCIPAL: MemoryId = MemoryId::new(10);

// Singleton key for the admin-config single-row maps.
const ADMIN_KEY: u8 = 0;

thread_local! {
    static MM: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static WALLET_TO_PRINCIPAL: RefCell<StableBTreeMap<EthAddress, PrincipalVal, Mem>> =
        RefCell::new(StableBTreeMap::init(MM.with(|m| m.borrow().get(MEM_WALLET_TO_PRINCIPAL))));

    static PRINCIPAL_WALLETS: RefCell<StableBTreeMap<PrincipalAddrKey, (), Mem>> =
        RefCell::new(StableBTreeMap::init(MM.with(|m| m.borrow().get(MEM_PRINCIPAL_WALLETS))));

    static HOLDER_LATEST: RefCell<StableBTreeMap<PrincipalVal, u32, Mem>> =
        RefCell::new(StableBTreeMap::init(MM.with(|m| m.borrow().get(MEM_HOLDER_LATEST))));

    static HOLDER_REVISIONS: RefCell<StableBTreeMap<PrincipalRevKey, HolderProfile, Mem>> =
        RefCell::new(StableBTreeMap::init(MM.with(|m| m.borrow().get(MEM_HOLDER_REVISIONS))));

    static WALLET_LATEST: RefCell<StableBTreeMap<EthAddress, u32, Mem>> =
        RefCell::new(StableBTreeMap::init(MM.with(|m| m.borrow().get(MEM_WALLET_LATEST))));

    static WALLET_REVISIONS: RefCell<StableBTreeMap<AddrRevKey, WalletAttestation, Mem>> =
        RefCell::new(StableBTreeMap::init(MM.with(|m| m.borrow().get(MEM_WALLET_REVISIONS))));

    static LINK_NONCES: RefCell<StableBTreeMap<EthAddress, NonceEntry, Mem>> =
        RefCell::new(StableBTreeMap::init(MM.with(|m| m.borrow().get(MEM_LINK_NONCES))));

    static ATTEST_NONCES: RefCell<StableBTreeMap<EthAddress, NonceEntry, Mem>> =
        RefCell::new(StableBTreeMap::init(MM.with(|m| m.borrow().get(MEM_ATTEST_NONCES))));

    static ADMIN_NONCES: RefCell<StableBTreeMap<EthAddress, NonceEntry, Mem>> =
        RefCell::new(StableBTreeMap::init(MM.with(|m| m.borrow().get(MEM_ADMIN_NONCES))));

    static ADMIN_ETH: RefCell<StableBTreeMap<u8, EthAddress, Mem>> =
        RefCell::new(StableBTreeMap::init(MM.with(|m| m.borrow().get(MEM_ADMIN_ETH))));

    static ADMIN_PRINCIPAL: RefCell<StableBTreeMap<u8, PrincipalVal, Mem>> =
        RefCell::new(StableBTreeMap::init(MM.with(|m| m.borrow().get(MEM_ADMIN_PRINCIPAL))));
}

// `k256` and friends pull in `getrandom` but we never actually invoke its
// randomness path (ECDSA recovery is deterministic). Register a no-op shim so
// the linker resolves the symbol on wasm32.
getrandom::register_custom_getrandom!(always_fail_getrandom);
fn always_fail_getrandom(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

// ============================================================================
// Lifecycle
// ============================================================================

#[init]
fn init() {}

#[pre_upgrade]
fn pre_upgrade() {}

#[post_upgrade]
fn post_upgrade() {}

// ============================================================================
// Helpers
// ============================================================================

fn caller_or_err() -> Result<Principal, String> {
    let c = caller();
    if c == Principal::anonymous() {
        return Err("authentication required: please sign in with Internet Identity".into());
    }
    Ok(c)
}

fn parse_addr(s: &str) -> Result<EthAddress, String> {
    EthAddress::from_hex(s)
}

fn default_admin_eth() -> EthAddress {
    let mut a = [0u8; 20];
    hex::decode_to_slice(DEFAULT_ADMIN_ETH_ADDRESS_HEX, &mut a).expect("admin addr");
    EthAddress(a)
}

fn current_admin_eth() -> EthAddress {
    ADMIN_ETH
        .with(|m| m.borrow().get(&ADMIN_KEY))
        .unwrap_or_else(default_admin_eth)
}

fn current_admin_principal() -> Option<Principal> {
    ADMIN_PRINCIPAL.with(|m| m.borrow().get(&ADMIN_KEY).map(|p| p.0))
}

fn require_controller() -> Result<(), String> {
    if !is_controller(&caller()) {
        return Err("only a canister controller may call this".into());
    }
    Ok(())
}

fn now_ns() -> u64 {
    time()
}

fn nonce_expired(entry: &NonceEntry, ttl_ns: u64) -> bool {
    now_ns().saturating_sub(entry.issued_at_ns) > ttl_ns
}

fn nonexpired_nonce(
    map_key: &EthAddress,
    nonce: &str,
    ttl_ns: u64,
    map: &mut StableBTreeMap<EthAddress, NonceEntry, Mem>,
) -> Result<(), String> {
    let entry = map.get(map_key).ok_or("no outstanding nonce; request one first")?;
    if entry.nonce != nonce {
        return Err("nonce mismatch".into());
    }
    if nonce_expired(&entry, ttl_ns) {
        return Err("nonce expired".into());
    }
    map.remove(map_key);
    Ok(())
}

// ============================================================================
// --- Identity binding ---
// ============================================================================

#[update]
async fn get_link_nonce(eth_address: String) -> Result<String, String> {
    let _ = caller_or_err()?;
    let addr = parse_addr(&eth_address)?;
    let nonce = nonce::fresh_uuid_v4().await?;
    let entry = NonceEntry { nonce: nonce.clone(), issued_at_ns: now_ns() };
    LINK_NONCES.with(|m| m.borrow_mut().insert(addr, entry));
    Ok(nonce)
}

#[update]
fn link_wallet(payload: LinkPayload) -> Result<(), String> {
    let caller = caller_or_err()?;
    let addr = parse_addr(&payload.wallet_address)?;
    let addr_lower = addr.to_lower_hex();

    // Verify wallet not already bound to a different principal.
    if let Some(existing) = WALLET_TO_PRINCIPAL.with(|m| m.borrow().get(&addr)) {
        if existing.0 != caller {
            return Err("wallet already linked to a different Internet Identity".into());
        } else {
            return Ok(()); // already linked to caller — idempotent.
        }
    }

    // Enforce the per-principal wallet cap.
    let existing_count: u64 = PRINCIPAL_WALLETS.with(|m| {
        m.borrow()
            .iter()
            .filter(|(k, _)| k.0 == caller)
            .count() as u64
    });
    if existing_count >= MAX_WALLETS_PER_PRINCIPAL {
        return Err(format!(
            "wallet cap reached: at most {MAX_WALLETS_PER_PRINCIPAL} wallets per Internet \
             Identity"
        ));
    }

    // Consume nonce.
    LINK_NONCES.with(|m| {
        nonexpired_nonce(&addr, &payload.nonce, NONCE_TTL_NS, &mut m.borrow_mut())
    })?;

    // Rebuild canonical link message; recover address from signature.
    let msg = message::build_link_message(
        &addr_lower,
        &caller.to_text(),
        &payload.signed_at_iso,
        &payload.nonce,
    );
    let recovered = verify::recover_eth_address(&msg, &payload.signature)?;
    if recovered != addr.0 {
        return Err(format!(
            "signature recovered to 0x{recovered_hex} but the linked wallet is 0x{claimed_hex}. \
             If you're using a smart-contract wallet (Coinbase Smart Wallet, Safe, Argent, any \
             ERC-4337 account, etc.) the signature recovers to the owner EOA, not the smart \
             account — please reconnect using the EOA wallet that holds your multiBTC, or use \
             MetaMask / Rabby / Trust / Brave / Frame on the same address that holds multiBTC.",
            recovered_hex = hex::encode(recovered),
            claimed_hex = hex::encode(addr.0)
        ));
    }

    // Write both directions atomically.
    WALLET_TO_PRINCIPAL.with(|m| m.borrow_mut().insert(addr, PrincipalVal(caller)));
    PRINCIPAL_WALLETS.with(|m| m.borrow_mut().insert(PrincipalAddrKey(caller, addr), ()));
    Ok(())
}

#[query]
fn get_principal_for_wallet(eth_address: String) -> Option<Principal> {
    let addr = EthAddress::from_hex(&eth_address).ok()?;
    WALLET_TO_PRINCIPAL.with(|m| m.borrow().get(&addr).map(|v| v.0))
}

#[query]
fn get_wallets_for_principal() -> Vec<String> {
    let caller = match caller_or_err() {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    PRINCIPAL_WALLETS.with(|m| {
        m.borrow()
            .iter()
            .filter_map(|(k, _)| if k.0 == caller { Some(k.1.to_lower_hex()) } else { None })
            .collect()
    })
}

// ============================================================================
// --- Holder layer ---
// ============================================================================

fn validate_holder(p: &HolderPayload) -> Result<(), String> {
    if p.legal_name.trim().is_empty() {
        return Err("legal_name is required".into());
    }
    if p.date_of_birth_iso.len() != 10 {
        return Err("date_of_birth_iso must be YYYY-MM-DD".into());
    }
    if p.nationality.trim().is_empty() {
        return Err("nationality is required".into());
    }
    if p.country_of_residence.trim().is_empty() {
        return Err("country_of_residence is required".into());
    }
    if !p.email.contains('@') || !p.email.contains('.') {
        return Err("email format invalid".into());
    }
    if !(p.consent_group_representation
        && p.consent_data_use_for_legal
        && p.ack_engagement_letter_to_follow
        && p.ack_fee_structure
        && p.ack_group_strategy_coordinated
        && p.ack_site_not_affiliated
        && p.truthfully_attested)
    {
        return Err("all acknowledgments and the truthfulness attestation are required".into());
    }
    Ok(())
}

fn payload_to_holder(payload: HolderPayload, principal: Principal, revision: u32) -> HolderProfile {
    HolderProfile {
        revision,
        principal,
        legal_name: payload.legal_name,
        date_of_birth_iso: payload.date_of_birth_iso,
        nationality: payload.nationality,
        country_of_residence: payload.country_of_residence,
        email: payload.email,
        telegram_handle: payload.telegram_handle,
        preferred_comm_channel: payload.preferred_comm_channel,
        has_filed_pod: payload.has_filed_pod,
        pod_filed_date_iso: payload.pod_filed_date_iso,
        pod_reference: payload.pod_reference,
        needs_help_filing_pod: payload.needs_help_filing_pod,
        consent_group_representation: payload.consent_group_representation,
        consent_data_use_for_legal: payload.consent_data_use_for_legal,
        ack_engagement_letter_to_follow: payload.ack_engagement_letter_to_follow,
        ack_fee_structure: payload.ack_fee_structure,
        ack_group_strategy_coordinated: payload.ack_group_strategy_coordinated,
        ack_site_not_affiliated: payload.ack_site_not_affiliated,
        truthfully_attested: payload.truthfully_attested,
        fee_preference: payload.fee_preference,
        preferred_payment_method: payload.preferred_payment_method,
        naming_preference: payload.naming_preference,
        other_multichain_claims: payload.other_multichain_claims,
        additional_documentation_notes: payload.additional_documentation_notes,
        submitted_at_ns: now_ns(),
    }
}

#[update]
fn submit_holder(payload: HolderPayload) -> Result<HolderProfile, String> {
    let caller = caller_or_err()?;
    validate_holder(&payload)?;
    if HOLDER_LATEST.with(|m| m.borrow().contains_key(&PrincipalVal(caller))) {
        return Err("holder profile already exists; use update_holder".into());
    }
    let h = payload_to_holder(payload, caller, 0);
    HOLDER_REVISIONS.with(|m| m.borrow_mut().insert(PrincipalRevKey(caller, 0), h.clone()));
    HOLDER_LATEST.with(|m| m.borrow_mut().insert(PrincipalVal(caller), 0));
    Ok(h)
}

#[update]
fn update_holder(payload: HolderPayload) -> Result<HolderProfile, String> {
    let caller = caller_or_err()?;
    validate_holder(&payload)?;
    let prev = HOLDER_LATEST
        .with(|m| m.borrow().get(&PrincipalVal(caller)))
        .ok_or("no holder profile yet; call submit_holder")?;
    if prev >= MAX_EDITS {
        return Err(format!(
            "edit cap reached: you have already saved {MAX_EDITS} revisions for your holder \
             profile"
        ));
    }
    let next = prev + 1;
    let h = payload_to_holder(payload, caller, next);
    HOLDER_REVISIONS.with(|m| m.borrow_mut().insert(PrincipalRevKey(caller, next), h.clone()));
    HOLDER_LATEST.with(|m| m.borrow_mut().insert(PrincipalVal(caller), next));
    Ok(h)
}

#[query]
fn get_my_holder() -> Option<HolderProfile> {
    let caller = caller_or_err().ok()?;
    let latest = HOLDER_LATEST.with(|m| m.borrow().get(&PrincipalVal(caller)))?;
    HOLDER_REVISIONS.with(|m| m.borrow().get(&PrincipalRevKey(caller, latest)))
}

#[query]
fn get_holder_revisions() -> Vec<HolderProfile> {
    let caller = match caller_or_err() {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    HOLDER_REVISIONS.with(|m| {
        m.borrow()
            .iter()
            .filter_map(|(k, v)| if k.0 == caller { Some(v) } else { None })
            .collect()
    })
}

// ============================================================================
// --- Wallet attestation layer ---
// ============================================================================

#[update]
async fn get_attest_nonce(eth_address: String) -> Result<String, String> {
    let _ = caller_or_err()?;
    let addr = parse_addr(&eth_address)?;
    let nonce = nonce::fresh_uuid_v4().await?;
    let entry = NonceEntry { nonce: nonce.clone(), issued_at_ns: now_ns() };
    ATTEST_NONCES.with(|m| m.borrow_mut().insert(addr, entry));
    Ok(nonce)
}

fn ensure_acknowledged(holder: &HolderProfile) -> Result<(), String> {
    if !(holder.consent_group_representation
        && holder.consent_data_use_for_legal
        && holder.ack_engagement_letter_to_follow
        && holder.ack_fee_structure
        && holder.ack_group_strategy_coordinated
        && holder.ack_site_not_affiliated
        && holder.truthfully_attested)
    {
        return Err("holder profile must have all acknowledgments true".into());
    }
    Ok(())
}

fn validate_attest(payload: &AttestPayload) -> Result<(), String> {
    if payload.acquired_post_incident && payload.post_incident_acquisitions.is_empty() {
        return Err(
            "acquired_post_incident is true but post_incident_acquisitions is empty".into(),
        );
    }
    if payload.attempted_bridge_redemption && payload.bridge_attempts.is_empty() {
        return Err("attempted_bridge_redemption is true but bridge_attempts is empty".into());
    }
    if payload.positions.is_empty() {
        return Err("at least one position is required".into());
    }
    if payload.support_tx_hashes.len() > 10 {
        return Err(format!(
            "at most 10 supporting tx hashes per wallet (got {})",
            payload.support_tx_hashes.len()
        ));
    }
    for (i, h) in payload.support_tx_hashes.iter().enumerate() {
        if h.trim().is_empty() {
            return Err(format!("supporting tx hash {i} is empty"));
        }
    }
    for (i, p) in payload.positions.iter().enumerate() {
        match &p.kind {
            PositionType::RawToken => {}
            PositionType::Lp { protocol, pool } => {
                if protocol.trim().is_empty() || pool.trim().is_empty() {
                    return Err(format!(
                        "position {i}: LP positions require both protocol and pool to be filled"
                    ));
                }
            }
            PositionType::Vault { protocol, name } => {
                if protocol.trim().is_empty() || name.trim().is_empty() {
                    return Err(format!(
                        "position {i}: vault positions require both protocol and vault name"
                    ));
                }
            }
            PositionType::Other(text) => {
                if text.trim().is_empty() {
                    return Err(format!(
                        "position {i}: 'Other' positions require a non-empty description (where \
                         the multiBTC is — lending, vault, custodian, etc.)"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn build_attestation(
    payload: AttestPayload,
    principal: Principal,
    revision: u32,
    signed_message: String,
) -> WalletAttestation {
    WalletAttestation {
        revision,
        wallet_address: payload.wallet_address.to_lowercase(),
        linked_principal: principal,
        detected_eth: payload.detected_eth,
        detected_bsc: payload.detected_bsc,
        detected_polygon: payload.detected_polygon,
        detected_canto: payload.detected_canto,
        positions: payload.positions,
        approximate_total_claim: payload.approximate_total_claim,
        held_pre_incident: payload.held_pre_incident,
        acquired_post_incident: payload.acquired_post_incident,
        post_incident_acquisitions: payload.post_incident_acquisitions,
        attempted_bridge_redemption: payload.attempted_bridge_redemption,
        bridge_attempts: payload.bridge_attempts,
        pod_filed_for_this_wallet: payload.pod_filed_for_this_wallet,
        pod_reference_for_this_wallet: payload.pod_reference_for_this_wallet,
        support_tx_hashes: payload.support_tx_hashes,
        signed_message,
        signature: payload.signature,
        nonce: payload.nonce,
        signed_at_iso: payload.signed_at_iso,
        data_commitment_sha256: payload.data_commitment_sha256,
        submitted_at_ns: now_ns(),
    }
}

fn submit_or_update(
    payload: AttestPayload,
    require_existing: bool,
) -> Result<WalletAttestation, String> {
    let caller = caller_or_err()?;
    let addr = parse_addr(&payload.wallet_address)?;
    let addr_lower = addr.to_lower_hex();

    // Principal must be linked to this wallet.
    let bound = WALLET_TO_PRINCIPAL
        .with(|m| m.borrow().get(&addr))
        .ok_or("wallet not linked: call link_wallet first")?;
    if bound.0 != caller {
        return Err("wallet linked to a different principal".into());
    }

    // Holder profile must exist with all acks.
    let holder_rev = HOLDER_LATEST
        .with(|m| m.borrow().get(&PrincipalVal(caller)))
        .ok_or("save your holder profile first")?;
    let holder = HOLDER_REVISIONS
        .with(|m| m.borrow().get(&PrincipalRevKey(caller, holder_rev)))
        .ok_or("holder profile missing")?;
    ensure_acknowledged(&holder)?;

    validate_attest(&payload)?;

    // Revision selection.
    let prev = WALLET_LATEST.with(|m| m.borrow().get(&addr));
    let revision = match (prev, require_existing) {
        (None, true) => return Err("no prior attestation; use submit_wallet_attestation".into()),
        (Some(_), false) => return Err("attestation exists; use update_wallet_attestation".into()),
        (None, false) => 0u32,
        (Some(r), true) => {
            if r >= MAX_EDITS {
                return Err(format!(
                    "edit cap reached: {MAX_EDITS} revisions already saved for this wallet"
                ));
            }
            r + 1
        }
    };

    // Recompute data_commitment_sha256 and compare to payload.
    let expected_commit = commitment::commit_attest(&payload, &caller, revision);
    if expected_commit != payload.data_commitment_sha256.trim_start_matches("0x") {
        return Err("data commitment mismatch (payload was tampered with after signing)".into());
    }

    // Consume nonce.
    ATTEST_NONCES.with(|m| {
        nonexpired_nonce(&addr, &payload.nonce, NONCE_TTL_NS, &mut m.borrow_mut())
    })?;

    // Rebuild canonical attestation message and recover signer.
    let msg = message::build_attestation_message(
        &addr_lower,
        &caller.to_text(),
        revision,
        &expected_commit,
        &payload.signed_at_iso,
        &payload.nonce,
    );
    let recovered = verify::recover_eth_address(&msg, &payload.signature)?;
    if recovered != addr.0 {
        return Err(format!(
            "signature recovered to 0x{recovered_hex} but the wallet under attestation is \
             0x{claimed_hex}.\n\nDiagnostic — backend reconstructed message ({msg_len} bytes), \
             caller principal {caller_text}:\n---8<---\n{msg}\n---8<---\n\nIf your wallet \
             showed exactly that text and is an EOA, please report this. If you're using a \
             smart-contract wallet (Coinbase Smart Wallet, Safe, Argent, ERC-4337) the \
             signature recovers to the owner EOA — connect the EOA directly instead.",
            recovered_hex = hex::encode(recovered),
            claimed_hex = hex::encode(addr.0),
            msg_len = msg.len(),
            caller_text = caller.to_text(),
            msg = msg,
        ));
    }

    let stored = build_attestation(payload, caller, revision, msg);
    WALLET_REVISIONS.with(|m| {
        m.borrow_mut().insert(AddrRevKey(addr, revision), stored.clone())
    });
    WALLET_LATEST.with(|m| m.borrow_mut().insert(addr, revision));
    Ok(stored)
}

#[update]
fn submit_wallet_attestation(payload: AttestPayload) -> Result<WalletAttestation, String> {
    submit_or_update(payload, false)
}

#[update]
fn update_wallet_attestation(payload: AttestPayload) -> Result<WalletAttestation, String> {
    submit_or_update(payload, true)
}

#[query]
fn get_my_wallets() -> Vec<WalletAttestation> {
    let caller = match caller_or_err() {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let addrs: Vec<EthAddress> = PRINCIPAL_WALLETS.with(|m| {
        m.borrow()
            .iter()
            .filter_map(|(k, _)| if k.0 == caller { Some(k.1) } else { None })
            .collect()
    });
    let mut out = Vec::with_capacity(addrs.len());
    for a in addrs {
        if let Some(rev) = WALLET_LATEST.with(|m| m.borrow().get(&a)) {
            if let Some(att) = WALLET_REVISIONS.with(|m| m.borrow().get(&AddrRevKey(a, rev))) {
                out.push(att);
            }
        }
    }
    out
}

#[query]
fn get_wallet_revisions(eth_address: String) -> Vec<WalletAttestation> {
    let addr = match EthAddress::from_hex(&eth_address) {
        Ok(a) => a,
        Err(_) => return vec![],
    };
    WALLET_REVISIONS.with(|m| {
        m.borrow()
            .iter()
            .filter_map(|(k, v)| if k.0 == addr { Some(v) } else { None })
            .collect()
    })
}

// ============================================================================
// --- Public ---
// ============================================================================

#[query]
fn get_public_stats() -> PublicStats {
    let mut s = PublicStats::default();
    HOLDER_LATEST.with(|m| {
        s.total_holders = m.borrow().len();
    });
    HOLDER_REVISIONS.with(|m| {
        for (k, v) in m.borrow().iter() {
            let latest = HOLDER_LATEST.with(|hl| hl.borrow().get(&PrincipalVal(k.0)));
            if Some(k.1) != latest {
                continue;
            }
            if v.has_filed_pod {
                s.pod_filed_holders += 1;
            }
        }
    });
    WALLET_LATEST.with(|m| {
        s.total_wallets = m.borrow().len();
    });
    WALLET_REVISIONS.with(|m| {
        for (k, v) in m.borrow().iter() {
            let latest = WALLET_LATEST.with(|wl| wl.borrow().get(&k.0));
            if Some(k.1) != latest {
                continue;
            }
            s.total_detected_eth = s.total_detected_eth.saturating_add(v.detected_eth);
            s.total_detected_bsc = s.total_detected_bsc.saturating_add(v.detected_bsc);
            s.total_detected_polygon =
                s.total_detected_polygon.saturating_add(v.detected_polygon);
            s.total_detected_canto = s.total_detected_canto.saturating_add(v.detected_canto);
            let claim = v.approximate_total_claim.unwrap_or_else(|| {
                v.detected_eth
                    .saturating_add(v.detected_bsc)
                    .saturating_add(v.detected_polygon)
                    .saturating_add(v.detected_canto)
            });
            s.total_declared_claim = s.total_declared_claim.saturating_add(claim);
            if v.held_pre_incident {
                s.pre_incident_wallets += 1;
            }
            if v.acquired_post_incident {
                s.post_incident_wallets += 1;
            }
            if v.submitted_at_ns > s.last_submission_at_ns {
                s.last_submission_at_ns = v.submitted_at_ns;
            }
        }
    });
    s
}

// ============================================================================
// --- Admin ---
// ============================================================================

#[update]
async fn get_admin_nonce() -> Result<String, String> {
    // Only the bound admin principal may request the nonce — this also gates the
    // II side of the dual-factor admin auth.
    let caller = caller_or_err()?;
    if let Some(p) = current_admin_principal() {
        if p != caller {
            return Err(
                "admin principal mismatch: sign in with the II linked to the admin".into(),
            );
        }
    } else {
        return Err(
            "admin principal not configured yet — a canister controller must call \
             set_admin_principal first"
                .into(),
        );
    }
    let nonce = nonce::fresh_uuid_v4().await?;
    let entry = NonceEntry { nonce: nonce.clone(), issued_at_ns: now_ns() };
    ADMIN_NONCES.with(|m| m.borrow_mut().insert(current_admin_eth(), entry));
    Ok(nonce)
}

fn verify_admin_auth(auth: &AdminAuth) -> Result<(), String> {
    let caller = caller_or_err()?;
    let bound_principal = current_admin_principal()
        .ok_or("admin principal not configured")?;
    if caller != bound_principal {
        return Err("admin principal mismatch".into());
    }
    let admin = current_admin_eth();
    let entry = ADMIN_NONCES
        .with(|m| m.borrow().get(&admin))
        .ok_or("no outstanding admin nonce")?;
    if entry.nonce != auth.nonce {
        return Err("admin nonce mismatch".into());
    }
    if nonce_expired(&entry, ADMIN_NONCE_TTL_NS) {
        return Err("admin nonce expired".into());
    }
    let msg = message::build_admin_message(&auth.signed_at_iso, &auth.nonce);
    let recovered = verify::recover_eth_address(&msg, &auth.signature)?;
    if recovered != admin.0 {
        return Err(format!(
            "admin signature recovered to 0x{recovered_hex}, not the configured admin EVM \
             wallet 0x{admin_hex}. Smart-contract wallets are not supported here — sign with \
             the EOA configured as the admin.",
            recovered_hex = hex::encode(recovered),
            admin_hex = hex::encode(admin.0)
        ));
    }
    ADMIN_NONCES.with(|m| m.borrow_mut().remove(&admin));
    Ok(())
}

// --- Admin config (controller-only) ---

#[query]
fn get_admin_info() -> AdminInfo {
    AdminInfo {
        eth_address: current_admin_eth().to_lower_hex(),
        principal: current_admin_principal(),
        max_edits: MAX_EDITS,
        max_wallets_per_principal: MAX_WALLETS_PER_PRINCIPAL,
    }
}

#[query]
fn am_i_controller() -> bool {
    is_controller(&caller())
}

#[update]
fn set_admin_eth_address(eth_address: String) -> Result<(), String> {
    require_controller()?;
    let addr = EthAddress::from_hex(&eth_address)?;
    ADMIN_ETH.with(|m| m.borrow_mut().insert(ADMIN_KEY, addr));
    Ok(())
}

#[update]
fn set_admin_principal(principal: Option<Principal>) -> Result<(), String> {
    require_controller()?;
    match principal {
        Some(p) => {
            if p == Principal::anonymous() {
                return Err("admin principal cannot be anonymous".into());
            }
            ADMIN_PRINCIPAL.with(|m| m.borrow_mut().insert(ADMIN_KEY, PrincipalVal(p)));
        }
        None => {
            ADMIN_PRINCIPAL.with(|m| m.borrow_mut().remove(&ADMIN_KEY));
        }
    }
    Ok(())
}

#[query]
fn admin_list_holders(auth: AdminAuth) -> Result<Vec<HolderProfile>, String> {
    verify_admin_auth(&auth)?;
    let mut out = Vec::new();
    HOLDER_LATEST.with(|m| {
        for (p, rev) in m.borrow().iter() {
            if let Some(h) =
                HOLDER_REVISIONS.with(|hr| hr.borrow().get(&PrincipalRevKey(p.0, rev)))
            {
                out.push(h);
            }
        }
    });
    Ok(out)
}

#[derive(candid::CandidType, serde::Deserialize, Clone)]
pub struct AdminHolderBundle {
    pub profile: HolderProfile,
    pub wallets: Vec<WalletAttestation>,
    pub holder_revisions: Vec<HolderProfile>,
    pub wallet_revisions: Vec<(String, Vec<WalletAttestation>)>,
}

#[query]
fn admin_list_holders_full(auth: AdminAuth) -> Result<Vec<AdminHolderBundle>, String> {
    verify_admin_auth(&auth)?;
    let mut out = Vec::new();
    let principals: Vec<Principal> =
        HOLDER_LATEST.with(|m| m.borrow().iter().map(|(p, _)| p.0).collect());

    for p in principals {
        let latest = match HOLDER_LATEST.with(|m| m.borrow().get(&PrincipalVal(p))) {
            Some(r) => r,
            None => continue,
        };
        let profile =
            match HOLDER_REVISIONS.with(|m| m.borrow().get(&PrincipalRevKey(p, latest))) {
                Some(h) => h,
                None => continue,
            };
        let holder_revisions: Vec<HolderProfile> = HOLDER_REVISIONS.with(|m| {
            m.borrow()
                .iter()
                .filter_map(|(k, v)| if k.0 == p { Some(v) } else { None })
                .collect()
        });
        let wallet_addrs: Vec<EthAddress> = PRINCIPAL_WALLETS.with(|m| {
            m.borrow()
                .iter()
                .filter_map(|(k, _)| if k.0 == p { Some(k.1) } else { None })
                .collect()
        });
        let mut wallets = Vec::new();
        let mut wallet_revisions = Vec::new();
        for a in wallet_addrs {
            if let Some(rev) = WALLET_LATEST.with(|m| m.borrow().get(&a)) {
                if let Some(att) =
                    WALLET_REVISIONS.with(|m| m.borrow().get(&AddrRevKey(a, rev)))
                {
                    wallets.push(att);
                }
            }
            let revs: Vec<WalletAttestation> = WALLET_REVISIONS.with(|m| {
                m.borrow()
                    .iter()
                    .filter_map(|(k, v)| if k.0 == a { Some(v) } else { None })
                    .collect()
            });
            wallet_revisions.push((a.to_lower_hex(), revs));
        }
        out.push(AdminHolderBundle {
            profile,
            wallets,
            holder_revisions,
            wallet_revisions,
        });
    }
    Ok(out)
}

#[query]
fn admin_export_csv(auth: AdminAuth) -> Result<String, String> {
    verify_admin_auth(&auth)?;
    let mut csv = String::new();
    csv.push_str(
        "principal,wallet_address,wallet_revision,legal_name,date_of_birth,nationality,country_of_residence,\
         email,telegram,detected_eth,detected_bsc,detected_polygon,detected_canto,approximate_total_claim,\
         held_pre_incident,acquired_post_incident,attempted_bridge_redemption,pod_filed_holder,pod_reference,\
         signed_at_iso,signature\n",
    );
    HOLDER_LATEST.with(|m| {
        for (p, latest) in m.borrow().iter() {
            let holder = match HOLDER_REVISIONS
                .with(|hr| hr.borrow().get(&PrincipalRevKey(p.0, latest)))
            {
                Some(h) => h,
                None => continue,
            };
            let wallet_addrs: Vec<EthAddress> = PRINCIPAL_WALLETS.with(|m| {
                m.borrow()
                    .iter()
                    .filter_map(|(k, _)| if k.0 == p.0 { Some(k.1) } else { None })
                    .collect()
            });
            if wallet_addrs.is_empty() {
                // Emit a row for the holder with no wallet info.
                csv.push_str(&csv_row(&holder, None));
                continue;
            }
            for a in wallet_addrs {
                let rev = WALLET_LATEST.with(|m| m.borrow().get(&a));
                let att = rev.and_then(|r| {
                    WALLET_REVISIONS.with(|m| m.borrow().get(&AddrRevKey(a, r)))
                });
                csv.push_str(&csv_row(&holder, att.as_ref()));
            }
        }
    });
    Ok(csv)
}

fn csv_q(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        if c == '"' {
            o.push_str("\"\"");
        } else {
            o.push(c);
        }
    }
    o.push('"');
    o
}
fn csv_qopt(s: &Option<String>) -> String {
    csv_q(s.as_deref().unwrap_or(""))
}
fn csv_row(h: &HolderProfile, w: Option<&WalletAttestation>) -> String {
    let principal = h.principal.to_text();
    let (addr, rev, eth, bsc, poly, canto, claim, pre, post, bridge, signed_at, sig) = match w {
        Some(w) => (
            w.wallet_address.clone(),
            w.revision.to_string(),
            w.detected_eth.to_string(),
            w.detected_bsc.to_string(),
            w.detected_polygon.to_string(),
            w.detected_canto.to_string(),
            w.approximate_total_claim.map(|x| x.to_string()).unwrap_or_default(),
            w.held_pre_incident.to_string(),
            w.acquired_post_incident.to_string(),
            w.attempted_bridge_redemption.to_string(),
            w.signed_at_iso.clone(),
            w.signature.clone(),
        ),
        None => (
            String::new(),
            String::new(),
            "0".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ),
    };
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
        csv_q(&principal),
        csv_q(&addr),
        csv_q(&rev),
        csv_q(&h.legal_name),
        csv_q(&h.date_of_birth_iso),
        csv_q(&h.nationality),
        csv_q(&h.country_of_residence),
        csv_q(&h.email),
        csv_qopt(&h.telegram_handle),
        csv_q(&eth),
        csv_q(&bsc),
        csv_q(&poly),
        csv_q(&canto),
        csv_q(&claim),
        csv_q(&pre),
        csv_q(&post),
        csv_q(&bridge),
        csv_q(&h.has_filed_pod.to_string()),
        csv_qopt(&h.pod_reference),
        csv_q(&signed_at),
        csv_q(&sig),
    )
}

// Export the candid interface.
candid::export_service!();
#[ic_cdk_macros::query(name = "__get_candid_interface_tmp_hack")]
fn export_candid() -> String {
    __export_service()
}
