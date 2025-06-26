use chrono::Utc;
use num_bigint::BigUint;
use pod2::{
    backends::plonky2::{
        primitives::ec::{curve::Point, schnorr::SecretKey}, signedpod::Signer,
    },
    frontend::{SignedPod, SignedPodBuilder},
    middleware::{KEY_SIGNER, Params},
};
use std::{fs, path::Path, sync::OnceLock};

// Server's secret key for signing timestamp pods (in production, load from secure storage)
static SERVER_SECRET_KEY: OnceLock<SecretKey> = OnceLock::new();

pub fn get_server_secret_key() -> &'static SecretKey {
    SERVER_SECRET_KEY.get_or_init(|| {
        load_or_generate_server_key()
    })
}

pub fn get_server_public_key() -> Point {
    get_server_secret_key().public_key()
}

fn load_or_generate_server_key() -> SecretKey {
    let key_path = "server_key.secret";
    
    if Path::new(key_path).exists() {
        // Load existing key
        if let Ok(key_data) = fs::read_to_string(key_path) {
            if let Some(key_bigint) = BigUint::parse_bytes(key_data.trim().as_bytes(), 10) {
                log::info!("Loaded existing server key from {key_path}");
                return SecretKey(key_bigint);
            }
        }
        log::warn!("Failed to load server key from {key_path}, generating new one");
    }
    
    // Generate new key
    log::info!("Generating new server key");
    let seed = b"podnet_server_timestamp_key_v1";
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..seed.len().min(32)].copy_from_slice(&seed[..seed.len().min(32)]);
    let sk_bigint = BigUint::from_bytes_le(&seed_bytes);
    let secret_key = SecretKey(sk_bigint);
    
    // Save the key
    if let Err(e) = fs::write(key_path, secret_key.0.to_string()) {
        log::error!("Failed to save server key to {key_path}: {e}");
    } else {
        log::info!("Saved server key to {key_path}");
    }
    
    secret_key
}

pub fn create_timestamp_pod(
    document_pod: &SignedPod,
    _content_hash: &str,
    _mock_mode: bool,
) -> Result<SignedPod, Box<dyn std::error::Error>> {
    log::info!("Creating timestamp pod");

    let params = Params::default();
    let server_sk = get_server_secret_key();
    let _server_pk = server_sk.public_key();

    // Extract data from document pod
    let doc_content_hash = document_pod
        .get("content_hash")
        .ok_or("Document pod missing content_hash")?;
    let doc_signer = document_pod
        .get(KEY_SIGNER)
        .ok_or("Document pod missing signer")?;

    log::info!("Document pod content_hash: {doc_content_hash}");
    log::info!("Document pod signer: {doc_signer}");

    // The content hash verification will be done in the main pod proof
    // For now, just proceed with creating the timestamp pod

    // Create timestamp pod signed by server
    let timestamp = Utc::now().to_rfc3339();
    log::info!("Creating timestamp pod with timestamp: {timestamp}");

    let mut timestamp_builder = SignedPodBuilder::new(&params);
    timestamp_builder.insert("document-pod", document_pod.id());
    timestamp_builder.insert("timestamp", timestamp.as_str());

    let mut server_signer = Signer(SecretKey(server_sk.0.clone()));
    let timestamp_pod = timestamp_builder.sign(&mut server_signer)?;
    timestamp_pod.verify()?;

    log::info!("Timestamp pod created and verified");

    Ok(timestamp_pod)
}
