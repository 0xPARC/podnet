use pod2::frontend::SignedPod;

pub fn verify_timestamp_pod_signature(
    timestamp_pod: &serde_json::Value,
    server_public_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Deserialize timestamp pod
    let signed_pod: SignedPod = serde_json::from_value(timestamp_pod.clone())?;

    // Verify signature
    signed_pod.verify()?;

    // Check that the signer matches the server public key
    let pod_signer = signed_pod
        .get("_signer")
        .ok_or("Timestamp pod missing signer")?;

    let pod_signer_str = format!("{pod_signer}");
    let server_public_key = format!("pk:{server_public_key}");
    if pod_signer_str != server_public_key {
        return Err(format!(
            "Timestamp pod signer {pod_signer_str} does not match server public key {server_public_key}"
        )
        .into());
    }

    println!("✓ Timestamp pod signature verified");
    Ok(())
}

