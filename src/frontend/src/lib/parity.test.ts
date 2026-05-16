import { describe, it, expect } from 'vitest';
import { buildAdminMessage, buildAttestationMessage, buildLinkMessage } from './message';
import {
  serialiseAttest,
  sha256Hex,
  commitAttest,
  type AttestPayloadForCommit,
  type PositionDetail,
} from './dataCommitment';

const ADMIN_ADDR = '0xd381e358d6b4e176559d3d76109985ed83259aec';
const NIL_PRINCIPAL = 'aaaaa-aa';
const NONCE = '11111111-1111-4111-8111-111111111111';
const ISO = '2026-05-13T18:00:00Z';

describe('canonical message parity (mirrors src/backend/src/message.rs)', () => {
  it('link message matches golden', () => {
    const m = buildLinkMessage(ADMIN_ADDR, NIL_PRINCIPAL, ISO, NONCE);
    expect(m).toBe(
      'multiBTC Holders Group — Identity Binding\n' +
        '\n' +
        'I bind this Ethereum wallet to my Internet Identity principal so that\n' +
        'only I can view and edit my verification record.\n' +
        '\n' +
        `Wallet:    ${ADMIN_ADDR}\n` +
        `Principal: ${NIL_PRINCIPAL}\n` +
        `Timestamp: ${ISO}\n` +
        `Nonce:     ${NONCE}`,
    );
  });

  it('attestation message matches Rust golden byte-for-byte', () => {
    const commit = '0'.repeat(64);
    const m = buildAttestationMessage(ADMIN_ADDR, NIL_PRINCIPAL, 0, commit, ISO, NONCE);
    // Must stay identical to ATTESTATION_GOLDEN in src/backend/src/message.rs.
    const expected =
      'multiBTC Holders Group — Verification & Authorization\n' +
      '\n' +
      'I, the controller of this wallet, declare:\n' +
      '\n' +
      '1. I hold or have held multiBTC tokens at this address.\n' +
      '2. I support the coordinated pursuit of asset-specific recovery\n' +
      '   for multiBTC holders in the Multichain Foundation Ltd. liquidation.\n' +
      '3. I authorize the appointed legal representative of the multiBTC\n' +
      '   Holders Group to act on my behalf in proceedings related to the\n' +
      '   Multichain liquidation (Singapore HC/CWU 134/2025;\n' +
      '   U.S. Bankruptcy Court SDNY 25-12340-DSJ).\n' +
      '4. I understand this is a group coordination effort with shared costs\n' +
      '   (either upfront cost-share or litigation funding, per my preference).\n' +
      '5. I attest under penalty of perjury that the information I have\n' +
      '   provided alongside this signature is true, accurate, and complete\n' +
      '   to the best of my knowledge.\n' +
      '\n' +
      `Wallet:           ${ADMIN_ADDR}\n` +
      `Linked principal: ${NIL_PRINCIPAL}\n` +
      `Revision:         0\n` +
      `Data commitment:  0x${commit}\n` +
      `Timestamp:        ${ISO}\n` +
      `Nonce:            ${NONCE}`;
    expect(m).toBe(expected);
  });

  it('admin message matches golden', () => {
    const m = buildAdminMessage(ISO, 'abc');
    expect(m).toBe(
      'multiBTC Holders Group — Admin Access\n' +
        '\n' +
        'I am authenticating as the admin operator.\n' +
        `Timestamp: ${ISO}\n` +
        `Nonce:     abc`,
    );
  });
});

function emptyPayload(): AttestPayloadForCommit {
  return {
    walletAddress: ADMIN_ADDR,
    detectedEth: 0n,
    detectedBsc: 0n,
    detectedPolygon: 0n,
    detectedCanto: 0n,
    positions: [],
    approximateTotalClaim: null,
    heldPreIncident: false,
    acquiredPostIncident: false,
    postIncidentAcquisitions: [],
    attemptedBridgeRedemption: false,
    bridgeAttempts: [],
    podFiledForThisWallet: false,
    podReferenceForThisWallet: null,
    supportTxHashes: [],
  };
}

describe('data commitment parity (mirrors src/backend/src/commitment.rs)', () => {
  it('empty payload serialises byte-for-byte identical to Rust golden', () => {
    const s = serialiseAttest(emptyPayload(), NIL_PRINCIPAL, 0);
    expect(s).toBe(
      `acquired_post_incident=false
approximate_total_claim=
attempted_bridge_redemption=false
bridge_attempts=0
detected_bsc=0
detected_canto=0
detected_eth=0
detected_polygon=0
held_pre_incident=false
linked_principal=${NIL_PRINCIPAL}
pod_filed_for_this_wallet=false
pod_reference_for_this_wallet=
positions=0
post_incident_acquisitions=0
revision=0
support_tx_hashes=0
wallet_address=${ADMIN_ADDR}`,
    );
  });

  it('positions + post-incident match the Rust spot-checks', () => {
    const p: AttestPayloadForCommit = {
      ...emptyPayload(),
      detectedEth: 100_000_000n,
      heldPreIncident: true,
      acquiredPostIncident: true,
      positions: [
        {
          chain: 'ethereum',
          kind: { kind: 'RawToken' },
          declaredMultibtc: 100_000_000n,
        },
        {
          chain: 'bsc',
          kind: { kind: 'Lp', protocol: 'Thena', pool: 'BTCB/multiBTC' },
          declaredMultibtc: 250_000_000n,
        },
      ] satisfies PositionDetail[],
      postIncidentAcquisitions: [
        {
          acquisitionDateIso: '2024-01-15',
          chain: 'bsc',
          amountMultibtc: 50_000_000n,
          pricePaidUsd: 1234.5,
          notes: 'test',
        },
      ],
    };
    const s = serialiseAttest(p, NIL_PRINCIPAL, 2);
    expect(s).toContain('positions=2');
    expect(s).toContain('positions.0.chain=657468657265756d');
    expect(s).toContain('positions.0.kind=RawToken');
    expect(s).toContain('positions.1.kind=Lp:5468656e61:425443422f6d756c7469425443');
    expect(s).toContain('post_incident_acquisitions=1');
    expect(s).toContain('post_incident_acquisitions.0.price_paid_usd=1234.500000');
    expect(s).toContain('revision=2');
  });

  it('sha256Hex of empty payload matches what commitAttest computes', async () => {
    const s = serialiseAttest(emptyPayload(), NIL_PRINCIPAL, 0);
    const expected = await sha256Hex(s);
    const got = await commitAttest(emptyPayload(), NIL_PRINCIPAL, 0);
    expect(got).toBe(expected);
    expect(got).toMatch(/^[0-9a-f]{64}$/);
  });
});
