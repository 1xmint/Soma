use serde::{Deserialize, Serialize};

use crate::crypto::{decode_base64, encode_base64, random_bytes, sha256_hex, sign, verify};
use crate::SomaError;

/// One authorized spend against a delegation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendReceipt {
    pub delegation_id: String,
    pub sequence: u64,
    pub previous_hash: String,
    pub amount: f64,
    pub cumulative: f64,
    pub capability: String,
    pub timestamp: u64,
    pub nonce: String,
    pub hash: String,
    pub subject_did: String,
    pub subject_public_key: String,
    pub subject_signature: String,
}

/// Append-only spend log for a single delegation.
#[derive(Serialize, Deserialize)]
pub struct SpendLog {
    delegation_id: String,
    receipts: Vec<SpendReceipt>,
    current_hash: String,
    cumulative: f64,
}

impl SpendLog {
    pub fn new(delegation_id: &str) -> Self {
        let genesis = sha256_hex(&format!("soma-spend-log:genesis:{delegation_id}"));
        Self {
            delegation_id: delegation_id.to_string(),
            receipts: Vec::new(),
            current_hash: genesis,
            cumulative: 0.0,
        }
    }

    /// Record a spend. The subject signs the receipt.
    pub fn record(
        &mut self,
        amount: f64,
        capability: &str,
        subject_did: &str,
        subject_secret_key: &[u8],
        subject_public_key: &[u8],
    ) -> Result<SpendReceipt, SomaError> {
        let sequence = self.receipts.len() as u64;
        let cumulative = self.cumulative + amount;
        let nonce = hex::encode(random_bytes(16));
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let canonical = serde_json::json!({
            "delegationId": self.delegation_id,
            "sequence": sequence,
            "previousHash": self.current_hash,
            "amount": amount,
            "cumulative": cumulative,
            "capability": capability,
            "timestamp": timestamp,
            "nonce": nonce,
            "subjectDid": subject_did,
        });

        let payload = format!("soma/spend/v1:{}", canonical);
        let sig = sign(subject_secret_key, payload.as_bytes())?;
        let hash = sha256_hex(&format!("{payload}:{}", encode_base64(&sig)));

        let receipt = SpendReceipt {
            delegation_id: self.delegation_id.clone(),
            sequence,
            previous_hash: self.current_hash.clone(),
            amount,
            cumulative,
            capability: capability.to_string(),
            timestamp,
            nonce,
            hash: hash.clone(),
            subject_did: subject_did.to_string(),
            subject_public_key: encode_base64(subject_public_key),
            subject_signature: encode_base64(&sig),
        };

        self.current_hash = hash;
        self.cumulative = cumulative;
        self.receipts.push(receipt.clone());
        Ok(receipt)
    }

    pub fn cumulative(&self) -> f64 {
        self.cumulative
    }

    pub fn receipts(&self) -> &[SpendReceipt] {
        &self.receipts
    }

    pub fn last_activity_ms(&self) -> u64 {
        self.receipts.last().map(|r| r.timestamp).unwrap_or(0)
    }

    pub fn delegation_id(&self) -> &str {
        &self.delegation_id
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    /// Verify the integrity of the spend chain.
    pub fn verify_chain(&self) -> Result<bool, SomaError> {
        let genesis = sha256_hex(&format!("soma-spend-log:genesis:{}", self.delegation_id));
        let mut expected_prev = genesis;
        let mut cumulative = 0.0;

        for receipt in &self.receipts {
            if receipt.previous_hash != expected_prev {
                return Ok(false);
            }
            cumulative += receipt.amount;
            if (receipt.cumulative - cumulative).abs() > f64::EPSILON {
                return Ok(false);
            }

            // Verify signature
            let pk = decode_base64(&receipt.subject_public_key)?;
            let sig = decode_base64(&receipt.subject_signature)?;
            let canonical = serde_json::json!({
                "delegationId": receipt.delegation_id,
                "sequence": receipt.sequence,
                "previousHash": receipt.previous_hash,
                "amount": receipt.amount,
                "cumulative": receipt.cumulative,
                "capability": receipt.capability,
                "timestamp": receipt.timestamp,
                "nonce": receipt.nonce,
                "subjectDid": receipt.subject_did,
            });
            let payload = format!("soma/spend/v1:{}", canonical);
            if !verify(&pk, payload.as_bytes(), &sig)? {
                return Ok(false);
            }

            expected_prev = receipt.hash.clone();
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;
    use crate::did::public_key_to_did;

    #[test]
    fn spend_log_tracks_cumulative() {
        let (sk, pk) = generate_keypair();
        let did = public_key_to_did(&pk);
        let mut log = SpendLog::new("dlg_test123");

        log.record(10.0, "route:select", &did, &sk, &pk).unwrap();
        log.record(25.0, "route:execute", &did, &sk, &pk).unwrap();

        assert_eq!(log.cumulative(), 35.0);
        assert_eq!(log.receipts().len(), 2);
        assert!(log.verify_chain().unwrap());
    }
}
