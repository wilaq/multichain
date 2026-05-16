use candid::{CandidType, Decode, Encode, Principal};
use ic_stable_structures::storable::{Bound, Storable};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

pub const POD_INCIDENT_DATE_ISO: &str = "2023-07-07";
pub const NONCE_TTL_NS: u64 = 15 * 60 * 1_000_000_000; // 15 min
pub const ADMIN_NONCE_TTL_NS: u64 = 5 * 60 * 1_000_000_000; // 5 min
pub const DEFAULT_ADMIN_ETH_ADDRESS_HEX: &str = "d381e358d6b4e176559d3d76109985ed83259aec";

// Per-principal caps to bound stable-memory writes.
pub const MAX_EDITS: u32 = 20; // max number of update_* calls (i.e. revisions 1..=20)
pub const MAX_WALLETS_PER_PRINCIPAL: u64 = 5;

// ============================================================================
// EthAddress — fixed 20 bytes, serialised as lowercase 0x... hex.
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EthAddress(pub [u8; 20]);

impl EthAddress {
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        if s.len() != 40 {
            return Err(format!("invalid eth address length: {}", s.len()));
        }
        let mut out = [0u8; 20];
        hex::decode_to_slice(s, &mut out).map_err(|e| format!("hex: {e}"))?;
        Ok(EthAddress(out))
    }
    pub fn to_lower_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

impl CandidType for EthAddress {
    fn _ty() -> candid::types::Type {
        candid::types::TypeInner::Text.into()
    }
    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        serializer.serialize_text(&self.to_lower_hex())
    }
}

impl<'de> Deserialize<'de> for EthAddress {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        EthAddress::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for EthAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_lower_hex())
    }
}

impl Storable for EthAddress {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.0.to_vec())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let mut a = [0u8; 20];
        a.copy_from_slice(&bytes[..20]);
        EthAddress(a)
    }
    const BOUND: Bound = Bound::Bounded { max_size: 20, is_fixed_size: true };
}

// ============================================================================
// Composite keys — Principal+EthAddress, Principal+u32, EthAddress+u32
// ============================================================================

// Encoded as: 1 byte principal len | principal bytes (max 29) | 20 bytes address.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrincipalAddrKey(pub Principal, pub EthAddress);

impl Storable for PrincipalAddrKey {
    fn to_bytes(&self) -> Cow<[u8]> {
        let p = self.0.as_slice();
        let mut v = Vec::with_capacity(1 + p.len() + 20);
        v.push(p.len() as u8);
        v.extend_from_slice(p);
        v.extend_from_slice(&self.1 .0);
        Cow::Owned(v)
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let plen = bytes[0] as usize;
        let p = Principal::from_slice(&bytes[1..1 + plen]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&bytes[1 + plen..1 + plen + 20]);
        PrincipalAddrKey(p, EthAddress(a))
    }
    // principal max 29 bytes + 1 length + 20 addr = 50
    const BOUND: Bound = Bound::Bounded { max_size: 50, is_fixed_size: false };
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrincipalRevKey(pub Principal, pub u32);

impl Storable for PrincipalRevKey {
    fn to_bytes(&self) -> Cow<[u8]> {
        let p = self.0.as_slice();
        let mut v = Vec::with_capacity(1 + p.len() + 4);
        v.push(p.len() as u8);
        v.extend_from_slice(p);
        v.extend_from_slice(&self.1.to_be_bytes());
        Cow::Owned(v)
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let plen = bytes[0] as usize;
        let p = Principal::from_slice(&bytes[1..1 + plen]);
        let mut r = [0u8; 4];
        r.copy_from_slice(&bytes[1 + plen..1 + plen + 4]);
        PrincipalRevKey(p, u32::from_be_bytes(r))
    }
    const BOUND: Bound = Bound::Bounded { max_size: 34, is_fixed_size: false };
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AddrRevKey(pub EthAddress, pub u32);

impl Storable for AddrRevKey {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut v = Vec::with_capacity(24);
        v.extend_from_slice(&self.0 .0);
        v.extend_from_slice(&self.1.to_be_bytes());
        Cow::Owned(v)
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let mut a = [0u8; 20];
        a.copy_from_slice(&bytes[..20]);
        let mut r = [0u8; 4];
        r.copy_from_slice(&bytes[20..24]);
        AddrRevKey(EthAddress(a), u32::from_be_bytes(r))
    }
    const BOUND: Bound = Bound::Bounded { max_size: 24, is_fixed_size: true };
}

// ============================================================================
// Stored records
// ============================================================================

#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct NonceEntry {
    pub nonce: String,
    pub issued_at_ns: u64,
}

impl Storable for NonceEntry {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).expect("encode NonceEntry"))
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), NonceEntry).expect("decode NonceEntry")
    }
    const BOUND: Bound = Bound::Bounded { max_size: 128, is_fixed_size: false };
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommChannel {
    Email,
    Telegram,
    Other(String),
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize, PartialEq, Eq)]
pub enum FeePreference {
    UpfrontCostShare,
    LitigationFunding,
    /// Each holder contributes proportionally to the size of their declared claim.
    ProportionalToClaim,
    Undecided,
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize, PartialEq, Eq)]
pub enum NamingPreference {
    WillingToBeNamed,
    AnonymousViaRepresentative,
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct HolderProfile {
    pub revision: u32,
    pub principal: Principal,

    // Layer 1 — Identity
    pub legal_name: String,
    pub date_of_birth_iso: String,
    pub nationality: String,
    pub country_of_residence: String,
    pub email: String,
    pub telegram_handle: Option<String>,
    pub preferred_comm_channel: CommChannel,

    // Layer 3 — KPMG PoD summary
    pub has_filed_pod: bool,
    pub pod_filed_date_iso: Option<String>,
    pub pod_reference: Option<String>,
    pub needs_help_filing_pod: bool,

    // Layer 4 — Authorization acknowledgments
    pub consent_group_representation: bool,
    pub consent_data_use_for_legal: bool,
    pub ack_engagement_letter_to_follow: bool,
    pub ack_fee_structure: bool,
    pub ack_group_strategy_coordinated: bool,
    pub ack_site_not_affiliated: bool,
    pub truthfully_attested: bool,

    // Layer 5 — Financial preference
    pub fee_preference: FeePreference,
    pub preferred_payment_method: Option<String>,

    // Layer 6 — Optional
    pub naming_preference: NamingPreference,
    pub other_multichain_claims: Option<String>,
    pub additional_documentation_notes: Option<String>,

    pub submitted_at_ns: u64,
}

impl Storable for HolderProfile {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).expect("encode HolderProfile"))
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), HolderProfile).expect("decode HolderProfile")
    }
    const BOUND: Bound = Bound::Unbounded;
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize, PartialEq, Eq)]
pub enum PositionType {
    RawToken,
    Lp { protocol: String, pool: String },
    Vault { protocol: String, name: String },
    Other(String),
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct PositionDetail {
    pub chain: String,
    pub kind: PositionType,
    pub declared_multibtc: u128,
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct BridgeAttempt {
    pub chain: String,
    pub tx_hash: String,
    pub description: Option<String>,
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct PostIncidentAcquisition {
    pub acquisition_date_iso: String,
    pub chain: String,
    pub amount_multibtc: u128,
    pub price_paid_usd: Option<f64>,
    pub notes: Option<String>,
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct WalletAttestation {
    pub revision: u32,
    pub wallet_address: String, // lowercased 0x...
    pub linked_principal: Principal,

    pub detected_eth: u128,
    pub detected_bsc: u128,
    pub detected_polygon: u128,
    pub detected_canto: u128,

    pub positions: Vec<PositionDetail>,
    pub approximate_total_claim: Option<u128>,

    pub held_pre_incident: bool,
    pub acquired_post_incident: bool,
    pub post_incident_acquisitions: Vec<PostIncidentAcquisition>,

    pub attempted_bridge_redemption: bool,
    pub bridge_attempts: Vec<BridgeAttempt>,

    pub pod_filed_for_this_wallet: bool,
    pub pod_reference_for_this_wallet: Option<String>,

    // Free-form supporting tx hashes (any chain) — evidence for declared totals
    // that exceed what's detected on-chain (e.g. LP deposits, custody, lending).
    // Capped at 10.
    pub support_tx_hashes: Vec<String>,

    pub signed_message: String,
    pub signature: String,
    pub nonce: String,
    pub signed_at_iso: String,
    pub data_commitment_sha256: String,

    pub submitted_at_ns: u64,
}

impl Storable for WalletAttestation {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).expect("encode WalletAttestation"))
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), WalletAttestation).expect("decode WalletAttestation")
    }
    const BOUND: Bound = Bound::Unbounded;
}

// Wrapper for Principal to use as a key/value in StableBTreeMap.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrincipalVal(pub Principal);

impl Storable for PrincipalVal {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.0.as_slice().to_vec())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        PrincipalVal(Principal::from_slice(&bytes))
    }
    const BOUND: Bound = Bound::Bounded { max_size: 29, is_fixed_size: false };
}

// ============================================================================
// Payloads (request types from the frontend)
// ============================================================================

#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct LinkPayload {
    pub wallet_address: String,
    pub signature: String,
    pub nonce: String,
    pub signed_at_iso: String,
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct HolderPayload {
    pub legal_name: String,
    pub date_of_birth_iso: String,
    pub nationality: String,
    pub country_of_residence: String,
    pub email: String,
    pub telegram_handle: Option<String>,
    pub preferred_comm_channel: CommChannel,

    pub has_filed_pod: bool,
    pub pod_filed_date_iso: Option<String>,
    pub pod_reference: Option<String>,
    pub needs_help_filing_pod: bool,

    pub consent_group_representation: bool,
    pub consent_data_use_for_legal: bool,
    pub ack_engagement_letter_to_follow: bool,
    pub ack_fee_structure: bool,
    pub ack_group_strategy_coordinated: bool,
    pub ack_site_not_affiliated: bool,
    pub truthfully_attested: bool,

    pub fee_preference: FeePreference,
    pub preferred_payment_method: Option<String>,

    pub naming_preference: NamingPreference,
    pub other_multichain_claims: Option<String>,
    pub additional_documentation_notes: Option<String>,
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct AttestPayload {
    pub wallet_address: String,

    pub detected_eth: u128,
    pub detected_bsc: u128,
    pub detected_polygon: u128,
    pub detected_canto: u128,

    pub positions: Vec<PositionDetail>,
    pub approximate_total_claim: Option<u128>,

    pub held_pre_incident: bool,
    pub acquired_post_incident: bool,
    pub post_incident_acquisitions: Vec<PostIncidentAcquisition>,

    pub attempted_bridge_redemption: bool,
    pub bridge_attempts: Vec<BridgeAttempt>,

    pub pod_filed_for_this_wallet: bool,
    pub pod_reference_for_this_wallet: Option<String>,

    pub support_tx_hashes: Vec<String>,

    pub signature: String,
    pub nonce: String,
    pub signed_at_iso: String,
    pub data_commitment_sha256: String,
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct AdminAuth {
    pub signature: String,
    pub nonce: String,
    pub signed_at_iso: String,
}

// ============================================================================
// Public aggregate stats
// ============================================================================

#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct AdminInfo {
    pub eth_address: String,                    // lowercase 0x...
    pub principal: Option<Principal>,            // None until a controller links it
    pub max_edits: u32,
    pub max_wallets_per_principal: u64,
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize, Default)]
pub struct PublicStats {
    pub total_holders: u64,
    pub total_wallets: u64,
    pub total_detected_eth: u128,
    pub total_detected_bsc: u128,
    pub total_detected_polygon: u128,
    pub total_detected_canto: u128,
    pub total_declared_claim: u128,
    pub pre_incident_wallets: u64,
    pub post_incident_wallets: u64,
    pub pod_filed_holders: u64,
    pub last_submission_at_ns: u64,
}
