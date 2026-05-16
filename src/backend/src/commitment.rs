use crate::types::*;
use candid::Principal;
use sha2::{Digest, Sha256};

fn h(s: &str) -> String {
    hex::encode(s.as_bytes())
}
fn oh(s: &Option<String>) -> String {
    s.as_ref().map(|x| hex::encode(x.as_bytes())).unwrap_or_default()
}
fn ou(v: &Option<u128>) -> String {
    v.map(|x| x.to_string()).unwrap_or_default()
}
fn of(v: &Option<f64>) -> String {
    // Fixed 6 decimal places so Rust + TS render identically.
    v.map(|x| format!("{:.6}", x)).unwrap_or_default()
}
fn position_type_str(k: &PositionType) -> String {
    match k {
        PositionType::RawToken => "RawToken".to_string(),
        PositionType::Lp { protocol, pool } => {
            format!("Lp:{}:{}", hex::encode(protocol.as_bytes()), hex::encode(pool.as_bytes()))
        }
        PositionType::Vault { protocol, name } => format!(
            "Vault:{}:{}",
            hex::encode(protocol.as_bytes()),
            hex::encode(name.as_bytes())
        ),
        PositionType::Other(s) => format!("Other:{}", hex::encode(s.as_bytes())),
    }
}

/// Deterministic, line-oriented serialisation of every consequential field in
/// the attestation payload. Format:
///
///   `field_name=value`
///
/// Lines emitted in fixed lexicographic order; strings hex-encoded as UTF-8
/// bytes to avoid newline / `=` ambiguity. Vec fields are emitted as
/// `<name>=<count>` followed by `<name>.<i>.<subfield>=...` lines (subfields
/// sorted lexicographically).
///
/// The frontend implements this same function so both sides can independently
/// recompute the sha256 commitment.
pub fn serialise_attest(
    payload: &AttestPayload,
    linked_principal: &Principal,
    revision: u32,
) -> String {
    let mut lines: Vec<String> = Vec::with_capacity(64);

    lines.push(format!("acquired_post_incident={}", payload.acquired_post_incident));
    lines.push(format!("approximate_total_claim={}", ou(&payload.approximate_total_claim)));
    lines.push(format!("attempted_bridge_redemption={}", payload.attempted_bridge_redemption));
    lines.push(format!("bridge_attempts={}", payload.bridge_attempts.len()));
    for (i, a) in payload.bridge_attempts.iter().enumerate() {
        lines.push(format!("bridge_attempts.{i}.chain={}", h(&a.chain)));
        lines.push(format!("bridge_attempts.{i}.description={}", oh(&a.description)));
        lines.push(format!("bridge_attempts.{i}.tx_hash={}", h(&a.tx_hash)));
    }
    lines.push(format!("detected_bsc={}", payload.detected_bsc));
    lines.push(format!("detected_canto={}", payload.detected_canto));
    lines.push(format!("detected_eth={}", payload.detected_eth));
    lines.push(format!("detected_polygon={}", payload.detected_polygon));
    lines.push(format!("held_pre_incident={}", payload.held_pre_incident));
    lines.push(format!("linked_principal={}", linked_principal.to_text()));
    lines.push(format!("pod_filed_for_this_wallet={}", payload.pod_filed_for_this_wallet));
    lines.push(format!(
        "pod_reference_for_this_wallet={}",
        oh(&payload.pod_reference_for_this_wallet)
    ));
    lines.push(format!("positions={}", payload.positions.len()));
    for (i, p) in payload.positions.iter().enumerate() {
        lines.push(format!("positions.{i}.chain={}", h(&p.chain)));
        lines.push(format!("positions.{i}.declared_multibtc={}", p.declared_multibtc));
        lines.push(format!("positions.{i}.kind={}", position_type_str(&p.kind)));
    }
    lines.push(format!(
        "post_incident_acquisitions={}",
        payload.post_incident_acquisitions.len()
    ));
    for (i, a) in payload.post_incident_acquisitions.iter().enumerate() {
        lines.push(format!(
            "post_incident_acquisitions.{i}.acquisition_date_iso={}",
            h(&a.acquisition_date_iso)
        ));
        lines.push(format!(
            "post_incident_acquisitions.{i}.amount_multibtc={}",
            a.amount_multibtc
        ));
        lines.push(format!("post_incident_acquisitions.{i}.chain={}", h(&a.chain)));
        lines.push(format!("post_incident_acquisitions.{i}.notes={}", oh(&a.notes)));
        lines.push(format!(
            "post_incident_acquisitions.{i}.price_paid_usd={}",
            of(&a.price_paid_usd)
        ));
    }
    lines.push(format!("revision={}", revision));
    lines.push(format!("support_tx_hashes={}", payload.support_tx_hashes.len()));
    for (i, h) in payload.support_tx_hashes.iter().enumerate() {
        lines.push(format!("support_tx_hashes.{i}={}", hex::encode(h.as_bytes())));
    }
    lines.push(format!("wallet_address={}", payload.wallet_address.to_lowercase()));

    lines.join("\n")
}

pub fn commit_attest(
    payload: &AttestPayload,
    linked_principal: &Principal,
    revision: u32,
) -> String {
    let s = serialise_attest(payload, linked_principal, revision);
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> Principal {
        Principal::from_text("aaaaa-aa").unwrap()
    }

    fn empty_payload() -> AttestPayload {
        AttestPayload {
            wallet_address: "0xd381e358d6b4e176559d3d76109985ed83259aec".to_string(),
            detected_eth: 0,
            detected_bsc: 0,
            detected_polygon: 0,
            detected_canto: 0,
            positions: vec![],
            approximate_total_claim: None,
            held_pre_incident: false,
            acquired_post_incident: false,
            post_incident_acquisitions: vec![],
            attempted_bridge_redemption: false,
            bridge_attempts: vec![],
            pod_filed_for_this_wallet: false,
            pod_reference_for_this_wallet: None,
            support_tx_hashes: vec![],
            signature: String::new(),
            nonce: String::new(),
            signed_at_iso: String::new(),
            data_commitment_sha256: String::new(),
        }
    }

    #[test]
    fn golden_empty_payload() {
        let s = serialise_attest(&empty_payload(), &p(), 0);
        // Stable golden — if this changes, the frontend mirror must change too.
        let expected = "\
acquired_post_incident=false
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
wallet_address=0xd381e358d6b4e176559d3d76109985ed83259aec";
        assert_eq!(s, expected);
    }

    #[test]
    fn golden_with_positions_and_post_incident() {
        let mut p1 = empty_payload();
        p1.detected_eth = 100_000_000; // 1 multiBTC raw
        p1.held_pre_incident = true;
        p1.acquired_post_incident = true;
        p1.positions = vec![
            PositionDetail {
                chain: "ethereum".to_string(),
                kind: PositionType::RawToken,
                declared_multibtc: 100_000_000,
            },
            PositionDetail {
                chain: "bsc".to_string(),
                kind: PositionType::Lp {
                    protocol: "Thena".to_string(),
                    pool: "BTCB/multiBTC".to_string(),
                },
                declared_multibtc: 250_000_000,
            },
        ];
        p1.post_incident_acquisitions = vec![PostIncidentAcquisition {
            acquisition_date_iso: "2024-01-15".to_string(),
            chain: "bsc".to_string(),
            amount_multibtc: 50_000_000,
            price_paid_usd: Some(1234.5),
            notes: Some("test".to_string()),
        }];
        let s = serialise_attest(&p1, &p(), 2);
        // Spot-check key lines:
        assert!(s.contains("positions=2"));
        assert!(s.contains("positions.0.chain=657468657265756d")); // hex("ethereum")
        assert!(s.contains("positions.0.kind=RawToken"));
        assert!(s.contains("positions.1.kind=Lp:5468656e61:425443422f6d756c7469425443")); // hex("Thena"):hex("BTCB/multiBTC")
        assert!(s.contains("post_incident_acquisitions=1"));
        assert!(s.contains("post_incident_acquisitions.0.price_paid_usd=1234.500000"));
        assert!(s.contains("revision=2"));
        // Determinism: serialise twice, identical output.
        assert_eq!(serialise_attest(&p1, &p(), 2), s);
    }

    #[test]
    fn commitment_is_stable_sha256() {
        let s = serialise_attest(&empty_payload(), &p(), 0);
        let c = commit_attest(&empty_payload(), &p(), 0);
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        assert_eq!(c, hex::encode(hasher.finalize()));
    }
}
