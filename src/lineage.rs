use serde::{Deserialize, Serialize};

use crate::crypto::{decode_base64, encode_base64, random_bytes, sign, verify};
use crate::identity::GenomeCommitment;
use crate::SomaError;

const LINEAGE_DOMAIN: &str = "soma/lineage/v1";

/// A single link in the lineage chain — parent signs over child's identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageCertificate {
    pub id: String,
    pub parent_did: String,
    pub parent_genome_hash: String,
    pub child_did: String,
    pub child_genome_hash: String,
    pub capabilities: Vec<String>,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub budget_credits: Option<f64>,
    pub nonce: String,
    pub signature: String,
    pub parent_public_key: String,
}

/// The full lineage chain: root → ... → direct parent → this heart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartLineage {
    pub did: String,
    pub root_did: String,
    pub chain: Vec<LineageCertificate>,
}

/// Create a lineage certificate — parent signs over child's identity.
pub fn create_lineage_certificate(
    parent_secret_key: &[u8],
    parent: &GenomeCommitment,
    child: &GenomeCommitment,
    capabilities: Vec<String>,
    ttl_ms: Option<u64>,
    budget_credits: Option<f64>,
) -> Result<LineageCertificate, SomaError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let nonce = encode_base64(&random_bytes(16));
    let id = format!("lc-{}", encode_base64(&random_bytes(12)));

    let payload = serde_json::json!({
        "id": id,
        "parentDid": parent.did,
        "parentGenomeHash": parent.hash,
        "childDid": child.did,
        "childGenomeHash": child.hash,
        "capabilities": capabilities,
        "issuedAt": now,
        "expiresAt": ttl_ms.map(|t| now + t),
        "budgetCredits": budget_credits,
        "nonce": nonce,
        "parentPublicKey": parent.public_key,
    });

    let signing_input = format!("{LINEAGE_DOMAIN}:{payload}");
    let sig = sign(parent_secret_key, signing_input.as_bytes())?;

    Ok(LineageCertificate {
        id,
        parent_did: parent.did.clone(),
        parent_genome_hash: parent.hash.clone(),
        child_did: child.did.clone(),
        child_genome_hash: child.hash.clone(),
        capabilities,
        issued_at: now,
        expires_at: ttl_ms.map(|t| now + t),
        budget_credits,
        nonce,
        signature: encode_base64(&sig),
        parent_public_key: parent.public_key.clone(),
    })
}

/// Verify a lineage certificate's signature.
pub fn verify_lineage_certificate(cert: &LineageCertificate) -> Result<bool, SomaError> {
    let pk = decode_base64(&cert.parent_public_key)?;
    let sig = decode_base64(&cert.signature)?;

    let payload = serde_json::json!({
        "id": cert.id,
        "parentDid": cert.parent_did,
        "parentGenomeHash": cert.parent_genome_hash,
        "childDid": cert.child_did,
        "childGenomeHash": cert.child_genome_hash,
        "capabilities": cert.capabilities,
        "issuedAt": cert.issued_at,
        "expiresAt": cert.expires_at,
        "budgetCredits": cert.budget_credits,
        "nonce": cert.nonce,
        "parentPublicKey": cert.parent_public_key,
    });

    let signing_input = format!("{LINEAGE_DOMAIN}:{payload}");
    verify(&pk, signing_input.as_bytes(), &sig)
}

/// Verify an entire lineage chain.
pub fn verify_lineage_chain(lineage: &HeartLineage) -> Result<bool, SomaError> {
    if lineage.chain.is_empty() {
        return Ok(false);
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    for (i, cert) in lineage.chain.iter().enumerate() {
        if !verify_lineage_certificate(cert)? {
            return Ok(false);
        }
        if let Some(expires) = cert.expires_at {
            if now > expires {
                return Ok(false);
            }
        }
        // Chain linkage: each cert's child must be the next cert's parent
        if i + 1 < lineage.chain.len() {
            let next = &lineage.chain[i + 1];
            if cert.child_did != next.parent_did {
                return Ok(false);
            }
        }
    }

    // Last cert's child must be the lineage owner
    if lineage.chain.last().unwrap().child_did != lineage.did {
        return Ok(false);
    }

    // First cert's parent must be the root
    if lineage.chain[0].parent_did != lineage.root_did {
        return Ok(false);
    }

    Ok(true)
}

/// Compute effective capabilities by intersecting each link in the chain.
pub fn effective_capabilities(lineage: &HeartLineage) -> Vec<String> {
    if lineage.chain.is_empty() {
        return vec![];
    }

    let mut caps: Option<Vec<String>> = None;
    for cert in &lineage.chain {
        if cert.capabilities.is_empty() {
            continue; // empty = inherit all
        }
        caps = Some(match caps {
            None => cert.capabilities.clone(),
            Some(prev) => prev
                .into_iter()
                .filter(|c| cert.capabilities.contains(c))
                .collect(),
        });
    }

    caps.unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::HeartIdentity;

    #[test]
    fn create_and_verify_lineage() {
        let parent = HeartIdentity::new("heyvera", "root", "root-v1").unwrap();
        let child = HeartIdentity::new("heyvera", "cortex-router", "cortex-v0.1").unwrap();

        let cert = create_lineage_certificate(
            &parent.secret_key,
            &parent.genome,
            &child.genome,
            vec!["route:*".into(), "chat:*".into(), "spend:*".into()],
            None,
            Some(10000.0),
        )
        .unwrap();

        assert!(verify_lineage_certificate(&cert).unwrap());

        let lineage = HeartLineage {
            did: child.did.clone(),
            root_did: parent.did.clone(),
            chain: vec![cert],
        };
        assert!(verify_lineage_chain(&lineage).unwrap());

        let caps = effective_capabilities(&lineage);
        assert_eq!(caps, vec!["route:*", "chat:*", "spend:*"]);
    }
}
