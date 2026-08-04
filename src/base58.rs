//! base58btc, per GENESIS.md §4.
//!
//! Implemented here rather than pulled from a crate so that this file can be
//! checked line by line against the specification, and so a revival needs
//! nothing but the document.
//!
//! The alphabet is not interchangeable. Ripple and Flickr order the same 58
//! characters differently, and using one of those produces identifiers that are
//! wrong while looking entirely plausible.

use crate::SomaError;

const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode bytes as base58btc.
///
/// Uses the classic byte-array long division rather than a big integer, so it
/// depends on nothing and behaves identically on every platform.
pub fn encode(data: &[u8]) -> String {
    if data.is_empty() {
        return "1".to_string();
    }

    let leading_zeros = data.iter().take_while(|b| **b == 0).count();

    // log(256)/log(58) ≈ 1.365, so 138/100 is a safe upper bound.
    let mut digits = vec![0u8; data.len() * 138 / 100 + 1];
    let mut length = 0usize;

    for byte in data {
        let mut carry = *byte as u32;
        let mut i = 0usize;
        for digit in digits.iter_mut().rev() {
            if i >= length && carry == 0 {
                break;
            }
            carry += 256 * (*digit as u32);
            *digit = (carry % 58) as u8;
            carry /= 58;
            i += 1;
        }
        length = i;
    }

    let start = digits.len() - length;
    let mut out = String::with_capacity(leading_zeros + length);
    for _ in 0..leading_zeros {
        out.push('1');
    }
    for digit in &digits[start..] {
        out.push(ALPHABET[*digit as usize] as char);
    }
    out
}

/// Decode base58btc.
pub fn decode(text: &str) -> Result<Vec<u8>, SomaError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }

    let leading_ones = text.chars().take_while(|c| *c == '1').count();

    let mut bytes = vec![0u8; text.len() * 733 / 1000 + 1];
    let mut length = 0usize;

    for character in text.chars() {
        let value = ALPHABET
            .iter()
            .position(|c| *c as char == character)
            .ok_or_else(|| {
                SomaError::InvalidDid(format!("character outside the base58btc alphabet: {character}"))
            })? as u32;

        let mut carry = value;
        let mut i = 0usize;
        for byte in bytes.iter_mut().rev() {
            if i >= length && carry == 0 {
                break;
            }
            carry += 58 * (*byte as u32);
            *byte = (carry % 256) as u8;
            carry /= 256;
            i += 1;
        }
        length = i;
    }

    let start = bytes.len() - length;
    let mut out = vec![0u8; leading_ones];
    out.extend_from_slice(&bytes[start..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed vectors from GENESIS.md §7.1. A round-trip test cannot catch a
    /// wrong alphabet or a wrong base, because both halves share the mistake --
    /// which is exactly how this implementation shipped base64 while claiming
    /// base58btc. Only fixed expected output catches that.
    #[test]
    fn matches_the_genesis_vector() {
        let prefixed =
            hex_to_bytes("ed0146b14b7854fede602d8b07841989db17bd7e710227163d0bdc4f5de6e83817e5");
        assert_eq!(
            encode(&prefixed),
            "6MkjDDPGYQdTcFQ8ecCf7zwP1rKvG7cdH5d8kxYqy7kaNBN"
        );
        assert_eq!(decode("6MkjDDPGYQdTcFQ8ecCf7zwP1rKvG7cdH5d8kxYqy7kaNBN").unwrap(), prefixed);
    }

    #[test]
    fn leading_zeros_become_ones() {
        assert_eq!(encode(&[0x00, 0x00, 0x01]), "112");
        assert_eq!(decode("112").unwrap(), vec![0x00, 0x00, 0x01]);
    }

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        // 0, O, I and l are deliberately absent.
        for bad in ["0abc", "Oabc", "Iabc", "labc"] {
            assert!(decode(bad).is_err(), "{bad} should be rejected");
        }
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
