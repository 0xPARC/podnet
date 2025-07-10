use pod2::frontend::{MainPod, SignedPod};
use pod2::middleware::{
    Hash, Key, Value,
    containers::{Dictionary, Set},
};
use podnet_models::mainpod::publish::verify_publish_verification_with_solver;
use podnet_models::mainpod::upvote::verify_upvote_count_with_solver;
use std::collections::{HashMap, HashSet};

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

pub fn verify_upvote_count(
    upvote_count_pod: &MainPod,
    expected_count: i64,
    expected_content_hash: &Hash,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use the new solver-based verification function
    verify_upvote_count_with_solver(upvote_count_pod, expected_count, expected_content_hash)
        .map_err(|e| format!("Upvote count verification failed: {e}"))?;

    println!("✓ Upvote count verification successful (count: {expected_count})");
    Ok(())
}

pub fn verify_publish_verification(
    main_pod: &MainPod,
    expected_content_hash: &Hash,
    expected_username: &str,
    expected_post_id: Option<i64>,
    expected_tags: &HashSet<String>,
    expected_authors: &HashSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use pod2::middleware::Statement;

    let publish_verified_statement = &main_pod.public_statements[1];
    let args = match publish_verified_statement {
        Statement::Custom(_, args) => args,
        _ => panic!(),
    };
    let identity_server_pk = &args[2];

    // Build the expected data dictionary similar to the server
    let mut data_map = HashMap::new();
    data_map.insert(Key::from("content_hash"), Value::from(*expected_content_hash));

    // Convert tags HashSet to Set
    let tags_set = Set::new(
        5,
        expected_tags
            .iter()
            .map(|tag| Value::from(tag.clone()))
            .collect::<HashSet<_>>(),
    )
    .map_err(|e| format!("Failed to create tags set: {:?}", e))?;
    data_map.insert(Key::from("tags"), Value::from(tags_set));

    // Convert authors HashSet to Set
    let authors_set = Set::new(
        5,
        expected_authors
            .iter()
            .map(|author| Value::from(author.clone()))
            .collect::<HashSet<_>>(),
    )
    .map_err(|e| format!("Failed to create authors set: {:?}", e))?;
    data_map.insert(Key::from("authors"), Value::from(authors_set));

    // Add reply_to (assume None for CLI verification)
    data_map.insert(Key::from("reply_to"), Value::from(-1i64));

    // Add post_id
    data_map.insert(
        Key::from("post_id"),
        match expected_post_id {
            Some(id) => Value::from(id),
            None => Value::from(-1i64),
        },
    );

    // Create expected data dictionary
    let expected_data = Dictionary::new(6, data_map)
        .map_err(|e| format!("Failed to create expected data dictionary: {:?}", e))?;

    // Use the solver-based verification function
    verify_publish_verification_with_solver(
        main_pod,
        expected_username,
        &expected_data,
        &identity_server_pk,
    )
    .map_err(|e| format!("Publish verification failed: {e}"))?;

    println!("✓ Publish verification successful");
    Ok(())
}
