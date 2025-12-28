/*
 * Copyright Nitro Agility S.r.l.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! TrustPlane - the Causal Authority for Trust (CAT) in the Sovereign federation.

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use pic::pca::{
    CatProvenance, Constraints, CoseSigned, Executor, ExecutorBinding, ExecutorProvenance,
    PcaPayload, Provenance, SignedPca, SignedPoc, TemporalConstraints,
};

use super::WorkloadIdentity;

pub struct TrustPlane {
    identity: WorkloadIdentity,
    signing_key: SigningKey,
}

impl TrustPlane {
    pub fn new(identity: WorkloadIdentity) -> Result<Self> {
        let signing_key = identity
            .private_key
            .clone()
            .ok_or_else(|| anyhow!("TrustPlane requires a private key"))?;

        Ok(Self {
            identity,
            signing_key,
        })
    }

    /// Creates with fallback to deterministic key (for testing without real keys)
    pub fn new_with_fallback(identity: WorkloadIdentity) -> Self {
        let signing_key = identity.private_key.clone().unwrap_or_else(|| {
            // Fallback: deterministic key from kid (for testing)
            let mut seed = [0u8; 32];
            let kid_bytes = identity.kid.as_bytes();
            for (i, byte) in kid_bytes.iter().enumerate().take(32) {
                seed[i] = *byte;
            }
            SigningKey::from_bytes(&seed)
        });

        Self {
            identity,
            signing_key,
        }
    }

    pub fn create_pca_0(
        &self,
        p_0: &str,
        ops: Vec<String>,
        executor_binding: ExecutorBinding,
    ) -> Result<Vec<u8>> {
        let pca = PcaPayload {
            hop: 0,
            p_0: p_0.to_string(),
            ops,
            executor: Executor {
                binding: executor_binding,
            },
            provenance: None,
            constraints: Some(Constraints {
                temporal: Some(TemporalConstraints {
                    iat: Some(chrono::Utc::now().to_rfc3339()),
                    exp: Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()),
                    nbf: None,
                }),
            }),
        };

        let signed: SignedPca =
            CoseSigned::sign_ed25519(&pca, &self.identity.kid, &self.signing_key)?;
        Ok(signed.to_bytes()?)
    }

    pub fn process_poc(&self, poc_bytes: &[u8]) -> Result<Vec<u8>> {
        let signed_poc: SignedPoc = CoseSigned::from_bytes(poc_bytes)?;
        let poc = signed_poc.payload_unverified()?;

        let signed_pred: SignedPca = CoseSigned::from_bytes(&poc.predecessor)?;
        let pred_pca = signed_pred.payload_unverified()?;

        let executor_binding = poc.successor.executor.clone().unwrap_or_default();

        let new_pca = PcaPayload {
            hop: pred_pca.hop + 1,
            p_0: pred_pca.p_0.clone(),
            ops: poc.successor.ops.clone(),
            executor: Executor {
                binding: executor_binding,
            },
            provenance: Some(Provenance {
                cat: CatProvenance {
                    kid: self.identity.kid.clone(),
                    signature: signed_pred
                        .to_bytes()?
                        .get(..64)
                        .unwrap_or(&[0u8; 64])
                        .to_vec(),
                },
                executor: ExecutorProvenance {
                    kid: signed_poc.kid().unwrap_or_default(),
                    signature: poc_bytes.get(..64).unwrap_or(&[0u8; 64]).to_vec(),
                },
            }),
            constraints: poc
                .successor
                .constraints
                .clone()
                .or(pred_pca.constraints.clone()),
        };

        let signed: SignedPca =
            CoseSigned::sign_ed25519(&new_pca, &self.identity.kid, &self.signing_key)?;
        Ok(signed.to_bytes()?)
    }

    pub fn kid(&self) -> &str {
        &self.identity.kid
    }

    pub fn did(&self) -> &str {
        &self.identity.did
    }

    pub fn has_real_key(&self) -> bool {
        self.identity.private_key.is_some()
    }
}