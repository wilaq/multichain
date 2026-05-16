// Byte-for-byte mirror of src/backend/src/commitment.rs.
// Any change here MUST be made in the Rust file too — see parity tests.

export type PositionType =
  | { kind: 'RawToken' }
  | { kind: 'Lp'; protocol: string; pool: string }
  | { kind: 'Vault'; protocol: string; name: string }
  | { kind: 'Other'; text: string };

export interface PositionDetail {
  chain: string;
  kind: PositionType;
  declaredMultibtc: bigint;
}

export interface BridgeAttempt {
  chain: string;
  txHash: string;
  description: string | null;
}

export interface PostIncidentAcquisition {
  acquisitionDateIso: string;
  chain: string;
  amountMultibtc: bigint;
  pricePaidUsd: number | null;
  notes: string | null;
}

export interface AttestPayloadForCommit {
  walletAddress: string;
  detectedEth: bigint;
  detectedBsc: bigint;
  detectedPolygon: bigint;
  detectedCanto: bigint;
  positions: PositionDetail[];
  approximateTotalClaim: bigint | null;
  heldPreIncident: boolean;
  acquiredPostIncident: boolean;
  postIncidentAcquisitions: PostIncidentAcquisition[];
  attemptedBridgeRedemption: boolean;
  bridgeAttempts: BridgeAttempt[];
  podFiledForThisWallet: boolean;
  podReferenceForThisWallet: string | null;
  supportTxHashes: string[];
}

function utf8Hex(s: string): string {
  const enc = new TextEncoder().encode(s);
  let out = '';
  for (const b of enc) out += b.toString(16).padStart(2, '0');
  return out;
}

function h(s: string): string {
  return utf8Hex(s);
}
function oh(s: string | null | undefined): string {
  return s == null ? '' : utf8Hex(s);
}
function ou(v: bigint | null | undefined): string {
  return v == null ? '' : v.toString();
}
function of(v: number | null | undefined): string {
  return v == null ? '' : v.toFixed(6);
}
function positionTypeStr(k: PositionType): string {
  switch (k.kind) {
    case 'RawToken':
      return 'RawToken';
    case 'Lp':
      return `Lp:${utf8Hex(k.protocol)}:${utf8Hex(k.pool)}`;
    case 'Vault':
      return `Vault:${utf8Hex(k.protocol)}:${utf8Hex(k.name)}`;
    case 'Other':
      return `Other:${utf8Hex(k.text)}`;
  }
}

export function serialiseAttest(
  p: AttestPayloadForCommit,
  linkedPrincipalText: string,
  revision: number,
): string {
  const lines: string[] = [];
  lines.push(`acquired_post_incident=${p.acquiredPostIncident}`);
  lines.push(`approximate_total_claim=${ou(p.approximateTotalClaim)}`);
  lines.push(`attempted_bridge_redemption=${p.attemptedBridgeRedemption}`);
  lines.push(`bridge_attempts=${p.bridgeAttempts.length}`);
  p.bridgeAttempts.forEach((a, i) => {
    lines.push(`bridge_attempts.${i}.chain=${h(a.chain)}`);
    lines.push(`bridge_attempts.${i}.description=${oh(a.description)}`);
    lines.push(`bridge_attempts.${i}.tx_hash=${h(a.txHash)}`);
  });
  lines.push(`detected_bsc=${p.detectedBsc}`);
  lines.push(`detected_canto=${p.detectedCanto}`);
  lines.push(`detected_eth=${p.detectedEth}`);
  lines.push(`detected_polygon=${p.detectedPolygon}`);
  lines.push(`held_pre_incident=${p.heldPreIncident}`);
  lines.push(`linked_principal=${linkedPrincipalText}`);
  lines.push(`pod_filed_for_this_wallet=${p.podFiledForThisWallet}`);
  lines.push(`pod_reference_for_this_wallet=${oh(p.podReferenceForThisWallet)}`);
  lines.push(`positions=${p.positions.length}`);
  p.positions.forEach((pos, i) => {
    lines.push(`positions.${i}.chain=${h(pos.chain)}`);
    lines.push(`positions.${i}.declared_multibtc=${pos.declaredMultibtc}`);
    lines.push(`positions.${i}.kind=${positionTypeStr(pos.kind)}`);
  });
  lines.push(`post_incident_acquisitions=${p.postIncidentAcquisitions.length}`);
  p.postIncidentAcquisitions.forEach((a, i) => {
    lines.push(`post_incident_acquisitions.${i}.acquisition_date_iso=${h(a.acquisitionDateIso)}`);
    lines.push(`post_incident_acquisitions.${i}.amount_multibtc=${a.amountMultibtc}`);
    lines.push(`post_incident_acquisitions.${i}.chain=${h(a.chain)}`);
    lines.push(`post_incident_acquisitions.${i}.notes=${oh(a.notes)}`);
    lines.push(`post_incident_acquisitions.${i}.price_paid_usd=${of(a.pricePaidUsd)}`);
  });
  lines.push(`revision=${revision}`);
  lines.push(`support_tx_hashes=${p.supportTxHashes.length}`);
  p.supportTxHashes.forEach((hash, i) => {
    lines.push(`support_tx_hashes.${i}=${h(hash)}`);
  });
  lines.push(`wallet_address=${p.walletAddress.toLowerCase()}`);
  return lines.join('\n');
}

export async function sha256Hex(s: string): Promise<string> {
  const bytes = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function commitAttest(
  p: AttestPayloadForCommit,
  linkedPrincipalText: string,
  revision: number,
): Promise<string> {
  return sha256Hex(serialiseAttest(p, linkedPrincipalText, revision));
}
