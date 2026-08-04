use crate::base58;
use crate::SomaError;

/// Ed25519 multicodec prefix: 0xed01
const ED25519_MULTICODEC: &[u8] = &[0xed, 0x01];

/// Convert a raw Ed25519 public key to a did:key identifier.
///
/// Format: `did:key:z<base58btc(0xED 0x01 || pubkey)>`, per GENESIS.md §5.
///
/// This previously base64-encoded while still emitting the `z` multibase prefix,
/// which claims base58btc. The result was not a did:key at all -- it was a
/// different identifier scheme wearing the same name, and every identity minted
/// by this implementation was unrecognisable to any other. A round-trip test
/// cannot catch that, because both halves share the mistake.
pub fn public_key_to_did(public_key: &[u8]) -> String {
    let mut multicodec = Vec::with_capacity(ED25519_MULTICODEC.len() + public_key.len());
    multicodec.extend_from_slice(ED25519_MULTICODEC);
    multicodec.extend_from_slice(public_key);
    format!("did:key:z{}", base58::encode(&multicodec))
}

/// Extract the raw Ed25519 public key from a did:key identifier.
pub fn did_to_public_key(did: &str) -> Result<Vec<u8>, SomaError> {
    let encoded = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| SomaError::InvalidDid(format!("invalid did:key format: {did}")))?;
    let multicodec = base58::decode(encoded)?;
    // Exactly 34 bytes: the two-byte multicodec prefix and a 32-byte key. A
    // length check that only demands "at least the prefix" would accept a
    // truncated or padded key.
    if multicodec.len() != ED25519_MULTICODEC.len() + 32 {
        return Err(SomaError::InvalidDid(format!(
            "did:key must carry exactly 34 bytes, found {}: {did}",
            multicodec.len()
        )));
    }
    if &multicodec[..ED25519_MULTICODEC.len()] != ED25519_MULTICODEC {
        return Err(SomaError::InvalidDid(format!(
            "did:key multicodec prefix mismatch: {did}"
        )));
    }
    Ok(multicodec[ED25519_MULTICODEC.len()..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;

    /// The vector from GENESIS.md §7.1. A round-trip test passes with any
    /// encoding, because both halves share whatever mistake is present -- which
    /// is how base64 shipped here while claiming base58btc. Fixed expected
    /// output is the only thing that catches it, and it is the whole reason a
    /// second independent implementation is required before the core is frozen.
    #[test]
    fn matches_the_genesis_identity_vector() {
        let key = hex_to_bytes("46b14b7854fede602d8b07841989db17bd7e710227163d0bdc4f5de6e83817e5");
        let did = public_key_to_did(&key);
        assert_eq!(
            did,
            "did:key:z6MkjDDPGYQdTcFQ8ecCf7zwP1rKvG7cdH5d8kxYqy7kaNBN",
            "this Rust implementation must produce the identifier the specification defines"
        );
        assert_eq!(did_to_public_key(&did).unwrap(), key);
    }

    #[test]
    fn rejects_an_identifier_that_carries_no_key() {
        assert!(did_to_public_key("did:soma:opaque").is_err());
        assert!(did_to_public_key("did:key:6MkjDDPGYQdTcFQ8ecCf7zwP1rKvG7cdH5d8kxYqy7kaNBN").is_err());
        // Base64 of the same bytes -- what this implementation used to emit.
        assert!(did_to_public_key("did:key:z7QFGsUt4VP7eYC2LB4QZidsXvX5xAicWPQvcT13m6DgX5Q==").is_err());
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn roundtrip_did() {
        let (_sk, pk) = generate_keypair();
        let did = public_key_to_did(&pk);
        assert!(did.starts_with("did:key:z"));
        let recovered = did_to_public_key(&did).unwrap();
        assert_eq!(pk, recovered);
    }
}
