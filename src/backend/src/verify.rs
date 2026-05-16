use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

/// EIP-191 personal_sign recovery. Returns the recovered 20-byte Ethereum address.
pub fn recover_eth_address(message: &str, sig_hex: &str) -> Result<[u8; 20], String> {
    let sig_hex = sig_hex.trim_start_matches("0x").trim_start_matches("0X");
    let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("hex: {e}"))?;
    if sig_bytes.len() != 65 {
        return Err(format!("signature must be 65 bytes, got {}", sig_bytes.len()));
    }
    let (r_s, v) = sig_bytes.split_at(64);
    let v_byte = v[0];
    // Accept both legacy (27/28) and EIP-155-style (0/1) recovery ids.
    let rid = if v_byte >= 27 { v_byte - 27 } else { v_byte };
    let recovery_id = RecoveryId::try_from(rid).map_err(|e| format!("recovery id: {e}"))?;
    let signature = Signature::try_from(r_s).map_err(|e| format!("sig parse: {e}"))?;

    // Apply EIP-191 prefix: "\x19Ethereum Signed Message:\n" || len || message.
    let prefixed = format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message);
    let mut hasher = Keccak256::new();
    hasher.update(prefixed.as_bytes());
    let digest = hasher.finalize();

    let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .map_err(|e| format!("recover: {e}"))?;

    // Ethereum address = last 20 bytes of keccak256(uncompressed_pubkey[1..]).
    let encoded = vk.to_encoded_point(false);
    let pk_bytes = &encoded.as_bytes()[1..]; // strip 0x04
    let mut kh = Keccak256::new();
    kh.update(pk_bytes);
    let hash = kh.finalize();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// Vector taken from a known good ethers.js signMessage call:
    ///   privkey 0x0123456789012345678901234567890123456789012345678901234567890123
    ///   address 0x14791697260E4c9A71f18484C9f997B308e59325
    ///   message "hello world"
    ///   signature 0xddd0a7290af9526056b4e35a077b9a11b513aa0028ec6c9880948544508f3c63
    ///             265e99e47ad31bb2cab9646c504576b3abc6939a1710afc08cbf3034d73214b8
    ///             1c
    #[test]
    fn recovers_known_address() {
        let addr = recover_eth_address(
            "hello world",
            "0xddd0a7290af9526056b4e35a077b9a11b513aa0028ec6c9880948544508f3c63\
             265e99e47ad31bb2cab9646c504576b3abc6939a1710afc08cbf3034d73214b81c",
        )
        .expect("recover");
        assert_eq!(addr, hex!("14791697260E4c9A71f18484C9f997B308e59325"));
    }

    #[test]
    fn rejects_wrong_length_signature() {
        assert!(recover_eth_address("hello", "0xdeadbeef").is_err());
    }

    #[test]
    fn rejects_malformed_hex() {
        assert!(recover_eth_address("hello", "not-hex").is_err());
    }
}
