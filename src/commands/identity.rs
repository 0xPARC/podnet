use crate::commands::keygen::KeypairData;
use crate::utils::handle_error_response;
use pod2::backends::plonky2::{primitives::ec::curve::Point as PublicKey, signedpod::Signer};
use pod2::frontend::{SignedPod, SignedPodBuilder};
use pod2::middleware::Params;
use serde::{Deserialize, Serialize};
use std::fs::File;

#[derive(Debug, Deserialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub server_id: String,
    pub server_public_key: PublicKey,
}

#[derive(Debug, Serialize)]
pub struct ChallengeRequest {
    pub username: String,
    pub user_public_key: PublicKey,
}

#[derive(Debug, Deserialize)]
pub struct IdentityResponse {
    pub identity_pod: SignedPod,
}

#[derive(Debug, Serialize)]
pub struct IdentityRequest {
    pub challenge_response: SignedPod,
}

pub async fn get_identity(
    keypair_file: &str,
    identity_server_url: &str,
    username: &str,
    output_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Getting identity from identity server...");
    println!("Username: {}", username);
    println!("Identity Server: {}", identity_server_url);

    // Load keypair from file
    let file = File::open(keypair_file)?;
    let keypair_data: KeypairData = serde_json::from_reader(file)?;

    let public_key = keypair_data.public_key;

    // Step 1: Request challenge from identity server
    println!("Requesting challenge from identity server...");

    let challenge_request = ChallengeRequest {
        username: username.to_string(),
        user_public_key: public_key,
    };

    let client = reqwest::Client::new();
    let challenge_response = client
        .post(format!("{}/challenge", identity_server_url))
        .header("Content-Type", "application/json")
        .json(&challenge_request)
        .send()
        .await?;

    if !challenge_response.status().is_success() {
        let status = challenge_response.status();
        let error_text = challenge_response.text().await?;
        handle_error_response(status, &error_text, "request challenge");
        return Ok(());
    }

    let challenge_data: ChallengeResponse = challenge_response.json().await?;
    println!("Received challenge: {}", challenge_data.challenge);

    // Step 2: Sign the challenge and send back to get identity pod
    println!("Signing challenge response...");

    // Parse secret key from hex
    let secret_key_bytes = hex::decode(&keypair_data.secret_key)?;
    let secret_key_bigint = num_bigint::BigUint::from_bytes_le(&secret_key_bytes);
    let secret_key = pod2::backends::plonky2::primitives::ec::schnorr::SecretKey(secret_key_bigint);

    // Create challenge response pod
    let params = Params::default();
    let mut challenge_builder = SignedPodBuilder::new(&params);

    challenge_builder.insert("challenge", challenge_data.challenge.as_str());
    challenge_builder.insert("username", username);

    // Sign the challenge response
    let mut user_signer = Signer(secret_key);
    let challenge_response_pod = challenge_builder.sign(&mut user_signer)?;

    let identity_request = IdentityRequest {
        challenge_response: challenge_response_pod,
    };

    // Step 3: Submit signed challenge to get identity pod
    println!("Submitting signed challenge to get identity pod...");
    println!("Pod is: {}", identity_request.challenge_response);

    let identity_response = client
        .post(format!("{}/identity", identity_server_url))
        .header("Content-Type", "application/json")
        .json(&identity_request)
        .send()
        .await?;

    if !identity_response.status().is_success() {
        let status = identity_response.status();
        let error_text = identity_response.text().await?;
        handle_error_response(status, &error_text, "get identity pod");
        return Ok(());
    }

    let identity_data: IdentityResponse = identity_response.json().await?;

    // Verify the identity pod
    identity_data.identity_pod.verify()?;
    println!("✓ Identity pod verification successful");

    // Save identity pod to file
    let identity_json = serde_json::to_string_pretty(&identity_data.identity_pod)?;
    std::fs::write(output_file, identity_json)?;

    println!("✓ Identity pod saved to: {}", output_file);
    println!("✓ Identity acquired successfully!");
    println!("Username: {}", username);
    println!("Identity Server: {}", challenge_data.server_id);

    Ok(())
}

