use anyhow::Result;
use chrono::Utc;
use ssi::claims::jws::JwsPayload;
use ssi::jwk::JWK;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Clone)]
#[allow(dead_code)]
pub struct Identity {
    pub did: String,
    pub signing_key: JWK,
    pub signing_kid: String,
}

/// TrustPlane has two keys: issuer (for VC) + cat (for PCA)
#[derive(Clone)]
#[allow(dead_code)]
pub struct TrustPlaneIdentity {
    pub did: String,
    pub issuer_key: JWK,
    pub issuer_kid: String,
    pub cat_key: JWK,
    pub cat_kid: String,
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fixtures")
        .join("workload-credentials-test-keys")
}

fn key_id_with_date(did: &str, purpose: &str) -> String {
    let date = Utc::now().format("%Y%m");
    format!("{}#{}-{}", did, purpose, date)
}

/// Generate TrustPlane identity with two keys
pub async fn trustplane_gen(
    name: &str,
    domain: &str,
) -> Result<TrustPlaneIdentity> {
    let dir = fixtures_dir().join(name);
    fs::create_dir_all(&dir)?;

    let did = format!("did:web:{}", domain);

    // Generate two Ed25519 keys
    let mut issuer_key = JWK::generate_ed25519().expect("failed to generate issuer key");
    let mut cat_key = JWK::generate_ed25519().expect("failed to generate cat key");

    // Set key IDs with date for rotation
    let issuer_kid = key_id_with_date(&did, "issuer-key");
    let cat_kid = key_id_with_date(&did, "cat-key");

    issuer_key.key_id = Some(issuer_kid.clone());
    cat_key.key_id = Some(cat_kid.clone());

    // Create DID Document with both keys
    let did_doc = serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": &did,
        "verificationMethod": [
            {
                "id": &issuer_kid,
                "type": "Ed25519VerificationKey2020",
                "controller": &did,
                "publicKeyJwk": serde_json::to_value(&issuer_key.to_public())?
            },
            {
                "id": &cat_kid,
                "type": "Ed25519VerificationKey2020",
                "controller": &did,
                "publicKeyJwk": serde_json::to_value(&cat_key.to_public())?
            }
        ],
        "assertionMethod": [&issuer_kid, &cat_kid],
        "authentication": [&issuer_kid, &cat_kid]
    });

    // Self-issued VC for TrustPlane
    let vc = create_vc(
        &did,
        name,
        "TrustAnchor",
        &did,
        &issuer_kid,
        &issuer_key,
    ).await?;

    // Write files
    fs::write(
        dir.join("issuer-key.private.jwk"),
        serde_json::to_string_pretty(&issuer_key)?,
    )?;
    fs::write(
        dir.join("issuer-key.public.jwk"),
        serde_json::to_string_pretty(&issuer_key.to_public())?,
    )?;
    fs::write(
        dir.join("cat-key.private.jwk"),
        serde_json::to_string_pretty(&cat_key)?,
    )?;
    fs::write(
        dir.join("cat-key.public.jwk"),
        serde_json::to_string_pretty(&cat_key.to_public())?,
    )?;
    fs::write(
        dir.join("did.json"),
        serde_json::to_string_pretty(&did_doc)?,
    )?;
    fs::write(
        dir.join("credential.vc.json"),
        serde_json::to_string_pretty(&vc)?,
    )?;

    println!("📦 {} (TrustPlane/CAT)", name);
    println!("   DID: {}", did);
    println!("   Issuer kid: {}", issuer_kid);
    println!("   CAT kid: {}", cat_kid);

    Ok(TrustPlaneIdentity {
        did,
        issuer_key,
        issuer_kid,
        cat_key,
        cat_kid,
    })
}

/// Generate workload (executor) identity
pub async fn workload_gen(
    name: &str,
    domain: &str,
    issuer: &TrustPlaneIdentity,
) -> Result<Identity> {
    let dir = fixtures_dir().join(name);
    fs::create_dir_all(&dir)?;

    let mut signing_key = JWK::generate_ed25519().expect("failed to generate key");
    let did = format!("did:web:{}", domain);
    let signing_kid = key_id_with_date(&did, "key");
    signing_key.key_id = Some(signing_kid.clone());

    // DID Document
    let did_doc = serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": &did,
        "verificationMethod": [{
            "id": &signing_kid,
            "type": "Ed25519VerificationKey2020",
            "controller": &did,
            "publicKeyJwk": serde_json::to_value(&signing_key.to_public())?
        }],
        "authentication": [&signing_kid],
        "assertionMethod": [&signing_kid]
    });

    // VC issued by TrustPlane
    let vc = create_vc(
        &did,
        name,
        "Executor",
        &issuer.did,
        &issuer.issuer_kid,
        &issuer.issuer_key,
    ).await?;

    // Write files
    fs::write(
        dir.join("private.jwk"),
        serde_json::to_string_pretty(&signing_key)?,
    )?;
    fs::write(
        dir.join("public.jwk"),
        serde_json::to_string_pretty(&signing_key.to_public())?,
    )?;
    fs::write(
        dir.join("did.json"),
        serde_json::to_string_pretty(&did_doc)?,
    )?;
    fs::write(
        dir.join("credential.vc.json"),
        serde_json::to_string_pretty(&vc)?,
    )?;

    println!("📦 {} (Executor)", name);
    println!("   DID: {}", did);
    println!("   Signing kid: {}", signing_kid);
    println!("   VC issuer: {}", issuer.issuer_kid);

    Ok(Identity {
        did,
        signing_key,
        signing_kid,
    })
}

async fn create_vc(
    subject_did: &str,
    name: &str,
    role: &str,
    issuer_did: &str,
    issuer_kid: &str,
    issuer_key: &JWK,
) -> Result<serde_json::Value> {
    let now = Utc::now().to_rfc3339();
    let credential_id = format!("urn:uuid:{}", Uuid::new_v4());

    let vc_without_proof = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": credential_id,
        "type": ["VerifiableCredential", "PICWorkloadCredential"],
        "issuer": issuer_did,
        "issuanceDate": &now,
        "credentialSubject": {
            "id": subject_did,
            "name": name,
            "role": role
        }
    });

    // Sign
    let payload = serde_json::to_vec(&vc_without_proof)?;
    let jws = payload.sign(issuer_key).await?;

    let mut vc = vc_without_proof;
    vc["proof"] = serde_json::json!({
        "type": "Ed25519Signature2020",
        "created": &now,
        "verificationMethod": issuer_kid,
        "proofPurpose": "assertionMethod",
        "jws": jws.as_str()
    });

    Ok(vc)
}