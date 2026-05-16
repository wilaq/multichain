import { Actor, type ActorSubclass, type HttpAgent } from '@dfinity/agent';
import { IDL } from '@dfinity/candid';
import type { Principal } from '@dfinity/principal';

// ---- IDL factory (mirrors src/backend/backend.did) ----

export const idlFactory: IDL.InterfaceFactory = ({ IDL }) => {
  const CommChannel = IDL.Variant({ Email: IDL.Null, Telegram: IDL.Null, Other: IDL.Text });
  const FeePreference = IDL.Variant({
    UpfrontCostShare: IDL.Null,
    LitigationFunding: IDL.Null,
    ProportionalToClaim: IDL.Null,
    Undecided: IDL.Null,
  });
  const NamingPreference = IDL.Variant({
    WillingToBeNamed: IDL.Null,
    AnonymousViaRepresentative: IDL.Null,
  });
  const PositionType = IDL.Variant({
    RawToken: IDL.Null,
    Lp: IDL.Record({ protocol: IDL.Text, pool: IDL.Text }),
    Vault: IDL.Record({ protocol: IDL.Text, name: IDL.Text }),
    Other: IDL.Text,
  });
  const PositionDetail = IDL.Record({
    chain: IDL.Text,
    kind: PositionType,
    declared_multibtc: IDL.Nat,
  });
  const BridgeAttempt = IDL.Record({
    chain: IDL.Text,
    tx_hash: IDL.Text,
    description: IDL.Opt(IDL.Text),
  });
  const PostIncidentAcquisition = IDL.Record({
    acquisition_date_iso: IDL.Text,
    chain: IDL.Text,
    amount_multibtc: IDL.Nat,
    price_paid_usd: IDL.Opt(IDL.Float64),
    notes: IDL.Opt(IDL.Text),
  });
  const HolderProfile = IDL.Record({
    revision: IDL.Nat32,
    principal: IDL.Principal,
    legal_name: IDL.Text,
    date_of_birth_iso: IDL.Text,
    nationality: IDL.Text,
    country_of_residence: IDL.Text,
    email: IDL.Text,
    telegram_handle: IDL.Opt(IDL.Text),
    preferred_comm_channel: CommChannel,
    has_filed_pod: IDL.Bool,
    pod_filed_date_iso: IDL.Opt(IDL.Text),
    pod_reference: IDL.Opt(IDL.Text),
    needs_help_filing_pod: IDL.Bool,
    consent_group_representation: IDL.Bool,
    consent_data_use_for_legal: IDL.Bool,
    ack_engagement_letter_to_follow: IDL.Bool,
    ack_fee_structure: IDL.Bool,
    ack_group_strategy_coordinated: IDL.Bool,
    ack_site_not_affiliated: IDL.Bool,
    truthfully_attested: IDL.Bool,
    fee_preference: FeePreference,
    preferred_payment_method: IDL.Opt(IDL.Text),
    naming_preference: NamingPreference,
    other_multichain_claims: IDL.Opt(IDL.Text),
    additional_documentation_notes: IDL.Opt(IDL.Text),
    submitted_at_ns: IDL.Nat64,
  });
  const WalletAttestation = IDL.Record({
    revision: IDL.Nat32,
    wallet_address: IDL.Text,
    linked_principal: IDL.Principal,
    detected_eth: IDL.Nat,
    detected_bsc: IDL.Nat,
    detected_polygon: IDL.Nat,
    detected_canto: IDL.Nat,
    positions: IDL.Vec(PositionDetail),
    approximate_total_claim: IDL.Opt(IDL.Nat),
    held_pre_incident: IDL.Bool,
    acquired_post_incident: IDL.Bool,
    post_incident_acquisitions: IDL.Vec(PostIncidentAcquisition),
    attempted_bridge_redemption: IDL.Bool,
    bridge_attempts: IDL.Vec(BridgeAttempt),
    pod_filed_for_this_wallet: IDL.Bool,
    pod_reference_for_this_wallet: IDL.Opt(IDL.Text),
    support_tx_hashes: IDL.Vec(IDL.Text),
    signed_message: IDL.Text,
    signature: IDL.Text,
    nonce: IDL.Text,
    signed_at_iso: IDL.Text,
    data_commitment_sha256: IDL.Text,
    submitted_at_ns: IDL.Nat64,
  });
  const LinkPayload = IDL.Record({
    wallet_address: IDL.Text,
    signature: IDL.Text,
    nonce: IDL.Text,
    signed_at_iso: IDL.Text,
  });
  const HolderPayload = IDL.Record({
    legal_name: IDL.Text,
    date_of_birth_iso: IDL.Text,
    nationality: IDL.Text,
    country_of_residence: IDL.Text,
    email: IDL.Text,
    telegram_handle: IDL.Opt(IDL.Text),
    preferred_comm_channel: CommChannel,
    has_filed_pod: IDL.Bool,
    pod_filed_date_iso: IDL.Opt(IDL.Text),
    pod_reference: IDL.Opt(IDL.Text),
    needs_help_filing_pod: IDL.Bool,
    consent_group_representation: IDL.Bool,
    consent_data_use_for_legal: IDL.Bool,
    ack_engagement_letter_to_follow: IDL.Bool,
    ack_fee_structure: IDL.Bool,
    ack_group_strategy_coordinated: IDL.Bool,
    ack_site_not_affiliated: IDL.Bool,
    truthfully_attested: IDL.Bool,
    fee_preference: FeePreference,
    preferred_payment_method: IDL.Opt(IDL.Text),
    naming_preference: NamingPreference,
    other_multichain_claims: IDL.Opt(IDL.Text),
    additional_documentation_notes: IDL.Opt(IDL.Text),
  });
  const AttestPayload = IDL.Record({
    wallet_address: IDL.Text,
    detected_eth: IDL.Nat,
    detected_bsc: IDL.Nat,
    detected_polygon: IDL.Nat,
    detected_canto: IDL.Nat,
    positions: IDL.Vec(PositionDetail),
    approximate_total_claim: IDL.Opt(IDL.Nat),
    held_pre_incident: IDL.Bool,
    acquired_post_incident: IDL.Bool,
    post_incident_acquisitions: IDL.Vec(PostIncidentAcquisition),
    attempted_bridge_redemption: IDL.Bool,
    bridge_attempts: IDL.Vec(BridgeAttempt),
    pod_filed_for_this_wallet: IDL.Bool,
    pod_reference_for_this_wallet: IDL.Opt(IDL.Text),
    support_tx_hashes: IDL.Vec(IDL.Text),
    signature: IDL.Text,
    nonce: IDL.Text,
    signed_at_iso: IDL.Text,
    data_commitment_sha256: IDL.Text,
  });
  const AdminAuth = IDL.Record({
    signature: IDL.Text,
    nonce: IDL.Text,
    signed_at_iso: IDL.Text,
  });
  const PublicStats = IDL.Record({
    total_holders: IDL.Nat64,
    total_wallets: IDL.Nat64,
    total_detected_eth: IDL.Nat,
    total_detected_bsc: IDL.Nat,
    total_detected_polygon: IDL.Nat,
    total_detected_canto: IDL.Nat,
    total_declared_claim: IDL.Nat,
    pre_incident_wallets: IDL.Nat64,
    post_incident_wallets: IDL.Nat64,
    pod_filed_holders: IDL.Nat64,
    last_submission_at_ns: IDL.Nat64,
  });
  const AdminHolderBundle = IDL.Record({
    profile: HolderProfile,
    wallets: IDL.Vec(WalletAttestation),
    holder_revisions: IDL.Vec(HolderProfile),
    wallet_revisions: IDL.Vec(IDL.Tuple(IDL.Text, IDL.Vec(WalletAttestation))),
  });
  const AdminInfo = IDL.Record({
    eth_address: IDL.Text,
    principal: IDL.Opt(IDL.Principal),
    max_edits: IDL.Nat32,
    max_wallets_per_principal: IDL.Nat64,
  });
  const RUnit = IDL.Variant({ Ok: IDL.Null, Err: IDL.Text });
  const RText = IDL.Variant({ Ok: IDL.Text, Err: IDL.Text });
  const RHolder = IDL.Variant({ Ok: HolderProfile, Err: IDL.Text });
  const RWallet = IDL.Variant({ Ok: WalletAttestation, Err: IDL.Text });
  const RHolderList = IDL.Variant({ Ok: IDL.Vec(HolderProfile), Err: IDL.Text });
  const RBundle = IDL.Variant({ Ok: IDL.Vec(AdminHolderBundle), Err: IDL.Text });

  return IDL.Service({
    get_link_nonce: IDL.Func([IDL.Text], [RText], []),
    link_wallet: IDL.Func([LinkPayload], [RUnit], []),
    get_principal_for_wallet: IDL.Func([IDL.Text], [IDL.Opt(IDL.Principal)], ['query']),
    get_wallets_for_principal: IDL.Func([], [IDL.Vec(IDL.Text)], ['query']),

    submit_holder: IDL.Func([HolderPayload], [RHolder], []),
    update_holder: IDL.Func([HolderPayload], [RHolder], []),
    get_my_holder: IDL.Func([], [IDL.Opt(HolderProfile)], ['query']),
    get_holder_revisions: IDL.Func([], [IDL.Vec(HolderProfile)], ['query']),

    get_attest_nonce: IDL.Func([IDL.Text], [RText], []),
    submit_wallet_attestation: IDL.Func([AttestPayload], [RWallet], []),
    update_wallet_attestation: IDL.Func([AttestPayload], [RWallet], []),
    get_my_wallets: IDL.Func([], [IDL.Vec(WalletAttestation)], ['query']),
    get_wallet_revisions: IDL.Func([IDL.Text], [IDL.Vec(WalletAttestation)], ['query']),

    get_public_stats: IDL.Func([], [PublicStats], ['query']),

    get_admin_info: IDL.Func([], [AdminInfo], ['query']),
    am_i_controller: IDL.Func([], [IDL.Bool], ['query']),
    set_admin_eth_address: IDL.Func([IDL.Text], [RUnit], []),
    set_admin_principal: IDL.Func([IDL.Opt(IDL.Principal)], [RUnit], []),

    get_admin_nonce: IDL.Func([], [RText], []),
    admin_list_holders: IDL.Func([AdminAuth], [RHolderList], ['query']),
    admin_list_holders_full: IDL.Func([AdminAuth], [RBundle], ['query']),
    admin_export_csv: IDL.Func([AdminAuth], [RText], ['query']),
  });
};

// ---- TypeScript types ----

export type CommChannel = { Email: null } | { Telegram: null } | { Other: string };
export type FeePreference =
  | { UpfrontCostShare: null }
  | { LitigationFunding: null }
  | { ProportionalToClaim: null }
  | { Undecided: null };
export type NamingPreferenceVariant =
  | { WillingToBeNamed: null }
  | { AnonymousViaRepresentative: null };

export type PositionTypeVariant =
  | { RawToken: null }
  | { Lp: { protocol: string; pool: string } }
  | { Vault: { protocol: string; name: string } }
  | { Other: string };

export interface PositionDetail {
  chain: string;
  kind: PositionTypeVariant;
  declared_multibtc: bigint;
}

export interface BridgeAttempt {
  chain: string;
  tx_hash: string;
  description: [] | [string];
}

export interface PostIncidentAcquisition {
  acquisition_date_iso: string;
  chain: string;
  amount_multibtc: bigint;
  price_paid_usd: [] | [number];
  notes: [] | [string];
}

export interface HolderProfile {
  revision: number;
  principal: Principal;
  legal_name: string;
  date_of_birth_iso: string;
  nationality: string;
  country_of_residence: string;
  email: string;
  telegram_handle: [] | [string];
  preferred_comm_channel: CommChannel;
  has_filed_pod: boolean;
  pod_filed_date_iso: [] | [string];
  pod_reference: [] | [string];
  needs_help_filing_pod: boolean;
  consent_group_representation: boolean;
  consent_data_use_for_legal: boolean;
  ack_engagement_letter_to_follow: boolean;
  ack_fee_structure: boolean;
  ack_group_strategy_coordinated: boolean;
  ack_site_not_affiliated: boolean;
  truthfully_attested: boolean;
  fee_preference: FeePreference;
  preferred_payment_method: [] | [string];
  naming_preference: NamingPreferenceVariant;
  other_multichain_claims: [] | [string];
  additional_documentation_notes: [] | [string];
  submitted_at_ns: bigint;
}

export interface WalletAttestation {
  revision: number;
  wallet_address: string;
  linked_principal: Principal;
  detected_eth: bigint;
  detected_bsc: bigint;
  detected_polygon: bigint;
  detected_canto: bigint;
  positions: PositionDetail[];
  approximate_total_claim: [] | [bigint];
  held_pre_incident: boolean;
  acquired_post_incident: boolean;
  post_incident_acquisitions: PostIncidentAcquisition[];
  attempted_bridge_redemption: boolean;
  bridge_attempts: BridgeAttempt[];
  pod_filed_for_this_wallet: boolean;
  pod_reference_for_this_wallet: [] | [string];
  support_tx_hashes: string[];
  signed_message: string;
  signature: string;
  nonce: string;
  signed_at_iso: string;
  data_commitment_sha256: string;
  submitted_at_ns: bigint;
}

export interface LinkPayload {
  wallet_address: string;
  signature: string;
  nonce: string;
  signed_at_iso: string;
}

export interface HolderPayload {
  legal_name: string;
  date_of_birth_iso: string;
  nationality: string;
  country_of_residence: string;
  email: string;
  telegram_handle: [] | [string];
  preferred_comm_channel: CommChannel;
  has_filed_pod: boolean;
  pod_filed_date_iso: [] | [string];
  pod_reference: [] | [string];
  needs_help_filing_pod: boolean;
  consent_group_representation: boolean;
  consent_data_use_for_legal: boolean;
  ack_engagement_letter_to_follow: boolean;
  ack_fee_structure: boolean;
  ack_group_strategy_coordinated: boolean;
  ack_site_not_affiliated: boolean;
  truthfully_attested: boolean;
  fee_preference: FeePreference;
  preferred_payment_method: [] | [string];
  naming_preference: NamingPreferenceVariant;
  other_multichain_claims: [] | [string];
  additional_documentation_notes: [] | [string];
}

export interface AttestPayload {
  wallet_address: string;
  detected_eth: bigint;
  detected_bsc: bigint;
  detected_polygon: bigint;
  detected_canto: bigint;
  positions: PositionDetail[];
  approximate_total_claim: [] | [bigint];
  held_pre_incident: boolean;
  acquired_post_incident: boolean;
  post_incident_acquisitions: PostIncidentAcquisition[];
  attempted_bridge_redemption: boolean;
  bridge_attempts: BridgeAttempt[];
  pod_filed_for_this_wallet: boolean;
  pod_reference_for_this_wallet: [] | [string];
  support_tx_hashes: string[];
  signature: string;
  nonce: string;
  signed_at_iso: string;
  data_commitment_sha256: string;
}

export interface AdminAuth {
  signature: string;
  nonce: string;
  signed_at_iso: string;
}

export interface PublicStats {
  total_holders: bigint;
  total_wallets: bigint;
  total_detected_eth: bigint;
  total_detected_bsc: bigint;
  total_detected_polygon: bigint;
  total_detected_canto: bigint;
  total_declared_claim: bigint;
  pre_incident_wallets: bigint;
  post_incident_wallets: bigint;
  pod_filed_holders: bigint;
  last_submission_at_ns: bigint;
}

export interface AdminHolderBundle {
  profile: HolderProfile;
  wallets: WalletAttestation[];
  holder_revisions: HolderProfile[];
  wallet_revisions: [string, WalletAttestation[]][];
}

export interface AdminInfo {
  eth_address: string;
  principal: [] | [Principal];
  max_edits: number;
  max_wallets_per_principal: bigint;
}

export type R<T> = { Ok: T } | { Err: string };

export interface BackendService {
  get_link_nonce: (eth_address: string) => Promise<R<string>>;
  link_wallet: (payload: LinkPayload) => Promise<R<null>>;
  get_principal_for_wallet: (eth_address: string) => Promise<[] | [Principal]>;
  get_wallets_for_principal: () => Promise<string[]>;

  submit_holder: (payload: HolderPayload) => Promise<R<HolderProfile>>;
  update_holder: (payload: HolderPayload) => Promise<R<HolderProfile>>;
  get_my_holder: () => Promise<[] | [HolderProfile]>;
  get_holder_revisions: () => Promise<HolderProfile[]>;

  get_attest_nonce: (eth_address: string) => Promise<R<string>>;
  submit_wallet_attestation: (payload: AttestPayload) => Promise<R<WalletAttestation>>;
  update_wallet_attestation: (payload: AttestPayload) => Promise<R<WalletAttestation>>;
  get_my_wallets: () => Promise<WalletAttestation[]>;
  get_wallet_revisions: (eth_address: string) => Promise<WalletAttestation[]>;

  get_public_stats: () => Promise<PublicStats>;

  get_admin_info: () => Promise<AdminInfo>;
  am_i_controller: () => Promise<boolean>;
  set_admin_eth_address: (eth: string) => Promise<R<null>>;
  set_admin_principal: (p: [] | [Principal]) => Promise<R<null>>;

  get_admin_nonce: () => Promise<R<string>>;
  admin_list_holders: (auth: AdminAuth) => Promise<R<HolderProfile[]>>;
  admin_list_holders_full: (auth: AdminAuth) => Promise<R<AdminHolderBundle[]>>;
  admin_export_csv: (auth: AdminAuth) => Promise<R<string>>;
}

export function createBackendActor(
  canisterId: string,
  agent: HttpAgent,
): ActorSubclass<BackendService> {
  return Actor.createActor<BackendService>(idlFactory, { agent, canisterId });
}

export function unwrap<T>(r: R<T>): T {
  if ('Err' in r) throw new Error(r.Err);
  return r.Ok;
}
