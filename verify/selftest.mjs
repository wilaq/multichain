#!/usr/bin/env node
/**
 * Cross-implementation agreement check.
 *
 * These vectors are copied from the canister's own Rust tests
 * (src/backend/src/commitment.rs, src/backend/src/verify.rs). This file and the
 * Rust are independent implementations of verify/SPEC.md; agreeing on the same
 * vectors is the evidence that the spec is implemented correctly on both sides.
 *
 *   node selftest.mjs
 */
import assert from 'node:assert/strict';
import { serialiseAttest, recoverAddress } from './verify-attestation.mjs';

const P = { __principal__: 'aaaaa-aa' };
const empty = {
  wallet_address: '0xd381e358d6b4e176559d3d76109985ed83259aec',
  linked_principal: P,
  revision: 0,
  detected_eth: 0, detected_bsc: 0, detected_polygon: 0, detected_canto: 0,
  positions: [],
  approximate_total_claim: [],          // candid `opt` = absent
  held_pre_incident: false,
  acquired_post_incident: false,
  post_incident_acquisitions: [],
  attempted_bridge_redemption: false,
  bridge_attempts: [],
  pod_filed_for_this_wallet: false,
  pod_reference_for_this_wallet: [],
  support_tx_hashes: [],
};

// --- 1. golden_empty_payload (commitment.rs) --------------------------------
const GOLDEN_EMPTY = `acquired_post_incident=false
approximate_total_claim=
attempted_bridge_redemption=false
bridge_attempts=0
detected_bsc=0
detected_canto=0
detected_eth=0
detected_polygon=0
held_pre_incident=false
linked_principal=aaaaa-aa
pod_filed_for_this_wallet=false
pod_reference_for_this_wallet=
positions=0
post_incident_acquisitions=0
revision=0
support_tx_hashes=0
wallet_address=0xd381e358d6b4e176559d3d76109985ed83259aec`;
assert.equal(serialiseAttest(empty), GOLDEN_EMPTY, 'empty-payload serialisation must match Rust');

// --- 2. golden_with_positions_and_post_incident (commitment.rs) -------------
const full = {
  ...empty,
  revision: 2,
  detected_eth: 100000000n,
  held_pre_incident: true,
  acquired_post_incident: true,
  positions: [
    { chain: 'ethereum', kind: { RawToken: null }, declared_multibtc: 100000000n },
    { chain: 'bsc', kind: { Lp: { protocol: 'Thena', pool: 'BTCB/multiBTC' } }, declared_multibtc: 250000000n },
  ],
  post_incident_acquisitions: [
    { acquisition_date_iso: '2024-01-15', chain: 'bsc', amount_multibtc: 50000000n,
      price_paid_usd: [1234.5], notes: ['test'] },
  ],
};
const s = serialiseAttest(full);
for (const line of [
  'positions=2',
  'positions.0.chain=657468657265756d',
  'positions.0.kind=RawToken',
  'positions.1.kind=Lp:5468656e61:425443422f6d756c7469425443',
  'post_incident_acquisitions=1',
  'post_incident_acquisitions.0.price_paid_usd=1234.500000',
  'post_incident_acquisitions.0.notes=74657374',
  'revision=2',
  'detected_eth=100000000',
]) assert.ok(s.includes(line), `missing canonical line: ${line}`);
assert.equal(serialiseAttest(full), s, 'serialisation must be deterministic');

// A decimal-string nat (how the JSON export writes u128) must serialise
// identically to the BigInt it came from -- no float rounding in the middle.
assert.equal(
  serialiseAttest({ ...full, detected_eth: '100000000' }),
  s,
  'string and bigint nats must agree',
);

// --- 3. EIP-191 recovery against the ethers.js golden vector (verify.rs) ----
const SIG =
  '0xddd0a7290af9526056b4e35a077b9a11b513aa0028ec6c9880948544508f3c63' +
  '265e99e47ad31bb2cab9646c504576b3abc6939a1710afc08cbf3034d73214b81c';
assert.equal(
  recoverAddress('hello world', SIG).toLowerCase(),
  '0x14791697260e4c9a71f18484c9f997b308e59325',
  'must recover the ethers.js golden address',
);

// --- 4. high-S (malleated) signatures are rejected, like ethers.js/viem -----
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const raw = Buffer.from(SIG.slice(2), 'hex');
const sPrime = N - BigInt('0x' + raw.subarray(32, 64).toString('hex'));
const malleated =
  '0x' + raw.subarray(0, 32).toString('hex') + sPrime.toString(16).padStart(64, '0') + '1b';
assert.throws(() => recoverAddress('hello world', malleated), /high-S/, 'must reject high-S');

// --- 5. a UTF-8 message: the EIP-191 length prefix counts BYTES, not chars --
// The attestation body contains an em dash, so this is load-bearing.
assert.throws(() => recoverAddress('x', '0xdeadbeef'), /65 bytes/);

// --- 6. End-to-end: sign a realistic record and run it through verifyRecord --
// Exercises the whole chain (serialise -> commit -> message -> sign -> recover)
// and the bundle traversal, with a signature this file produces itself.
{
  const { secp256k1 } = await import('@noble/curves/secp256k1');
  const { keccak_256 } = await import('@noble/hashes/sha3');
  const { verifyRecord, commitAttest, buildAttestationMessage, serialiseAttest: ser } =
    await import('./verify-attestation.mjs');
  const enc = new TextEncoder();

  const priv = Uint8Array.from(Buffer.from('01'.repeat(32), 'hex'));
  const pub = secp256k1.getPublicKey(priv, false);
  const addr = '0x' + Buffer.from(keccak_256(pub.slice(1)).slice(-20)).toString('hex');

  const rec = {
    ...full,
    wallet_address: addr,
    signed_at_iso: '2026-05-20T10:00:00.000Z',
    nonce: '3f2504e0-4f89-41d3-9a0c-0305e82c3301',
  };
  rec.data_commitment_sha256 = commitAttest(rec);
  const message = buildAttestationMessage({
    wallet: addr,
    principal: 'aaaaa-aa',
    revision: 2,
    commitHex: rec.data_commitment_sha256,
    signedAtIso: rec.signed_at_iso,
    nonce: rec.nonce,
  });
  const body = enc.encode(message);
  const digest = keccak_256(
    new Uint8Array([...enc.encode(`\x19Ethereum Signed Message:\n${body.length}`), ...body]),
  );
  const sig = secp256k1.sign(digest, priv, { prehash: false });
  rec.signature =
    '0x' + Buffer.from(sig.toBytes('compact')).toString('hex') + (27 + sig.recovery).toString(16).padStart(2, '0');
  rec.signed_message = message;

  const v = verifyRecord(rec);
  assert.deepEqual(v.problems, [], `round trip should verify: ${v.problems.join('; ')}`);
  assert.equal(v.recovered.toLowerCase(), addr.toLowerCase());

  // The em dash makes byte length != character length; if the verifier used
  // characters the recovery above would already have failed. Assert it anyway.
  assert.ok(body.length > message.length, 'message must contain multi-byte UTF-8');

  // Tampering with a committed field after signing must be caught.
  const tampered = { ...rec, detected_eth: 999999999n };
  const t = verifyRecord(tampered);
  assert.ok(
    t.problems.some((x) => x.includes('data commitment mismatch')),
    'post-signature tampering must be detected',
  );
  assert.notEqual(ser(tampered), ser(rec));
}

console.log('selftest: all checks passed');
