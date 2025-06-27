use super::keygen::KeypairData;

use crate::utils::handle_error_response;
use std::fs::File;

pub async fn register_user(
    keypair_file: &str,
    server_url: &str,
    user_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Registering user {user_id} with server...");

    // Load keypair from file
    let file = File::open(keypair_file)?;
    let keypair_data: KeypairData = serde_json::from_reader(file)?;

    let public_key = keypair_data.public_key;

    let payload = serde_json::json!({
        "user_id": user_id,
        "public_key": public_key
    });

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{server_url}/register"))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        println!("Successfully registered user: {user_id}");
        println!("Public Key: {public_key}");

        if let Some(server_pk) = result.get("public_key").and_then(|v| v.as_str()) {
            println!("Server Public Key: {server_pk}");
        }
    } else {
        let status = response.status();
        let error_text = response.text().await?;
        handle_error_response(status, &error_text, "register user");
    }

    Ok(())
}
