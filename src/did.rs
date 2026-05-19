use crate::crypto::{decode_base64, encode_base64};
use crate::SomaError;

/// Ed25519 multicodec prefix: 0xed01
const ED25519_MULTICODEC: &[u8] = &[0xed, 0x01];

/// Convert a raw Ed25519 public key to a did:key identifier.
/// Format: did:key:z<base64(multicodec_prefix + pubkey)>
pub fn public_key_to_did(public_key: &[u8]) -> String {
    let mut multicodec = Vec::with_capacity(ED25519_MULTICODEC.len() + public_key.len());
    multicodec.extend_from_slice(ED25519_MULTICODEC);
    multicodec.extend_from_slice(public_key);
    format!("did:key:z{}", encode_base64(&multicodec))
}

/// Extract the raw Ed25519 public key from a did:key identifier.
pub fn did_to_public_key(did: &str) -> Result<Vec<u8>, SomaError> {
    let encoded = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| SomaError::InvalidDid(format!("invalid did:key format: {did}")))?;
    let multicodec = decode_base64(encoded)?;
    if multicodec.len() < ED25519_MULTICODEC.len() {
        return Err(SomaError::InvalidDid(format!("did:key too short: {did}")));
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

    #[test]
    fn roundtrip_did() {
        let (_sk, pk) = generate_keypair();
        let did = public_key_to_did(&pk);
        assert!(did.starts_with("did:key:z"));
        let recovered = did_to_public_key(&did).unwrap();
        assert_eq!(pk, recovered);
    }
}
