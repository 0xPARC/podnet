use chrono::Utc;
use num_bigint::BigUint;
use plonky2::hash::hash_types::HashOut;
use pod2::backends::plonky2::mock::mainpod::MockProver;
use pod2::backends::plonky2::primitives::ec::curve::Point;
use pod2::backends::plonky2::primitives::ec::schnorr::SecretKey;
use pod2::backends::plonky2::signedpod::Signer;
use pod2::frontend::{MainPod, MainPodBuilder, SignedPod, SignedPodBuilder};
use pod2::lang::parse;
use pod2::middleware::{Hash, KEY_SIGNER, KEY_TYPE, Params, PodType, VDSet, Value, hash_values};
use pod2::op;
use rand::Rng;

// For hashing
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

/// Test the full upvote verification predicate to identify why it fails
#[test]
fn test_full_upvote_verification_predicate() {
    println!("=== Starting Full Upvote Verification Test ===");

    // This test will go through the complete flow:
    // 1. Generate keypairs
    // 2. Create identity pod
    // 3. Generate content hash
    // 4. Create upvote pod
    // 5. Build upvote verification MainPod
    // 6. Create base case proof
    // 7. Create inductive proof (expected to fail - we want to see why)

    let result = run_full_test();

    match result {
        Ok(_) => println!("✓ Test completed successfully"),
        Err(e) => println!("✗ Test failed with error: {}", e),
    }
}

fn run_full_test() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Generate keypairs
    println!("\n--- Step 1: Generating Keypairs ---");
    let (identity_server_sk, identity_server_pk) = generate_keypair("identity_server")?;
    let (client_sk, client_pk) = generate_keypair("client")?;
    let (server_sk, server_pk) = generate_keypair("server")?;

    // Step 2: Create identity pod
    println!("\n--- Step 2: Creating Identity Pod ---");
    let username = "test_user";
    let identity_pod = create_identity_pod(&identity_server_sk, username, &client_pk)?;
    println!("✓ Identity pod created and verified");

    // Step 3: Generate content hash
    println!("\n--- Step 3: Generating Content Hash ---");
    let content = "test_me";
    let content_hash = hash_values(&[Value::from(content)]);
    println!("✓ Content hash generated: {}", content_hash);

    // Step 4: Create upvote pod
    println!("\n--- Step 4: Creating Upvote Pod ---");
    let post_id = 1i64;
    let upvote_pod = create_upvote_pod(&client_sk, &content_hash, post_id)?;
    println!("✓ Upvote pod created and verified");

    // Step 5: Build verification MainPods in stages
    println!("\n--- Step 5a: Building Identity Verification MainPod ---");
    let identity_verification_main_pod =
        build_identity_verification_main_pod(&identity_pod, username)?;
    println!("✓ Identity verification MainPod created and verified");

    println!("\n--- Step 5b: Building Upvote Verification MainPod ---");
    let upvote_verification_main_pod =
        build_upvote_verification_main_pod(&upvote_pod, &content_hash, post_id)?;
    println!("✓ Upvote verification MainPod created and verified");

    println!("\n--- Step 5c: Building Final Combined Verification MainPod ---");
    let combined_verification_main_pod = build_combined_verification_main_pod(
        &identity_verification_main_pod,
        &upvote_verification_main_pod,
        &identity_pod,
        &upvote_pod,
        &identity_server_pk,
    )?;
    println!("✓ Combined verification MainPod created and verified");

    // Step 6: Create base case proof
    println!("\n--- Step 6: Creating Base Case Upvote Count Proof ---");
    let base_case_main_pod = build_base_case_proof(
        username,
        &content_hash,
        &identity_server_pk,
        post_id,
        &server_sk,
    )?;
    println!("✓ Base case upvote count proof created and verified");

    // Step 7: Create inductive proof (this is where we expect it to fail)
    println!("\n--- Step 7: Creating Inductive Upvote Count Proof ---");
    match build_inductive_proof(&base_case_main_pod, &combined_verification_main_pod, 1) {
        Ok(inductive_pod) => {
            println!("✓ Inductive proof succeeded!");
            println!("Inductive pod: {:?}", inductive_pod);
        }
        Err(e) => {
            println!("✗ Inductive proof failed as expected. Error analysis:");
            println!("Error: {}", e);
            panic!();
        }
    }

    Ok(())
}

fn generate_keypair(name: &str) -> Result<(SecretKey, Point), Box<dyn std::error::Error>> {
    // Generate a random secret key
    let sk_bytes: [u8; 32] = rand::random();
    let sk_bigint = BigUint::from_bytes_le(&sk_bytes);
    let secret_key = SecretKey(sk_bigint);

    // Derive public key
    let public_key = secret_key.public_key();

    println!("Generated keypair for {}: {:?}", name, public_key);

    Ok((secret_key, public_key))
}

fn create_identity_pod(
    identity_server_sk: &SecretKey,
    username: &str,
    user_public_key: &Point,
) -> Result<SignedPod, Box<dyn std::error::Error>> {
    let params = Params::default();
    let mut identity_builder = SignedPodBuilder::new(&params);

    // Add required fields for identity pod
    identity_builder.insert("username", username);
    identity_builder.insert("user_public_key", user_public_key.clone());
    identity_builder.insert("issued_at", Utc::now().timestamp());

    // Sign with identity server's private key
    let signer_key = identity_server_sk.0.clone();
    let identity_pod = identity_builder.sign(&mut Signer(SecretKey(signer_key)))?;

    // Verify the pod
    identity_pod.verify()?;

    Ok(identity_pod)
}

fn create_upvote_pod(
    client_sk: &SecretKey,
    content_hash: &Hash,
    post_id: i64,
) -> Result<SignedPod, Box<dyn std::error::Error>> {
    let params = Params::default();
    let mut upvote_builder = SignedPodBuilder::new(&params);

    // Add required fields for upvote pod (matching CLI implementation)
    upvote_builder.insert("request_type", "upvote");
    upvote_builder.insert("content_hash", *content_hash);
    upvote_builder.insert("post_id", post_id);
    upvote_builder.insert("timestamp", Utc::now().timestamp());

    // Sign with client's private key
    let signer_key = client_sk.0.clone();
    let upvote_pod = upvote_builder.sign(&mut Signer(SecretKey(signer_key)))?;

    // Verify the pod
    upvote_pod.verify()?;

    Ok(upvote_pod)
}

fn get_full_upvote_verification_predicate() -> String {
    // Return the FULL predicate (the commented-out version)
    format!(
        r#"
        identity_verified(username, private: identity_pod) = AND(
            Equal(?identity_pod["{key_type}"], {signed_pod_type})
            Equal(?identity_pod["username"], ?username)
        )

        upvote_verified(content_hash, post_id, private: upvote_pod) = AND(
            Equal(?upvote_pod["{key_type}"], {signed_pod_type})
            Equal(?upvote_pod["content_hash"], ?content_hash)
            Equal(?upvote_pod["post_id"], ?post_id)
            Equal(?upvote_pod["request_type"], "upvote")
        )

        upvote_verification(username, content_hash, identity_server_pk, post_id, private: identity_pod, upvote_pod) = AND(
            identity_verified(?username)
            upvote_verified(?content_hash, ?post_id)
            Equal(?identity_pod["{key_signer}"], ?identity_server_pk)
            Equal(?identity_pod["user_public_key"], ?upvote_pod["{key_signer}"])
        )

        upvote_count_base(count, username, content_hash, identity_server_pk, post_id, private: data_pod) = AND(
            Equal(?count, 0)
            Equal(?data_pod["username"], ?username)
            Equal(?data_pod["content_hash"], ?content_hash)
            Equal(?data_pod["identity_server_pk"], ?identity_server_pk)
            Equal(?data_pod["post_id"], ?post_id)
        )

        upvote_count_ind(count, username, content_hash, identity_server_pk, post_id, private: intermed) = AND(
            upvote_count(?intermed, ?username, ?content_hash, ?identity_server_pk, ?post_id)
            SumOf(?count, ?intermed, 1)
            upvote_verification(?username, ?content_hash, ?identity_server_pk, ?post_id)
        )

        upvote_count(count, username, content_hash, identity_server_pk, post_id) = OR(
            upvote_count_base(?count, ?username, ?content_hash, ?identity_server_pk, ?post_id)
            upvote_count_ind(?count, ?username, ?content_hash, ?identity_server_pk, ?post_id)
        )
        "#,
        key_type = KEY_TYPE,
        key_signer = KEY_SIGNER,
        signed_pod_type = PodType::Signed as usize,
    )
}

fn build_identity_verification_main_pod(
    identity_pod: &SignedPod,
    username: &str,
) -> Result<MainPod, Box<dyn std::error::Error>> {
    let mut params = Params::default();
    params.max_custom_batch_size = 10;

    let mock_prover = MockProver {};
    let vd_set = VDSet::new(8, &[])?;

    // Parse the FULL predicate
    let predicate_str = get_full_upvote_verification_predicate();
    let batch = parse(&predicate_str, &params, &[])?.custom_batch;

    let identity_verified_pred = batch
        .predicate_ref_by_name("identity_verified")
        .ok_or("identity_verified predicate not found")?;

    // Build the main pod
    let mut builder = MainPodBuilder::new(&params, &vd_set);

    // Add the signed pod
    builder.add_signed_pod(identity_pod);

    // Build identity verification
    let identity_type_check =
        builder.priv_op(op!(eq, (identity_pod, KEY_TYPE), PodType::Signed))?;
    let identity_username_check = builder.priv_op(op!(eq, (identity_pod, "username"), username))?;
    let identity_verified_stmt = builder.pub_op(op!(
        custom,
        identity_verified_pred.clone(),
        identity_type_check,
        identity_username_check
    ))?;

    // Prove
    let main_pod = builder.prove(&mock_prover, &params)?;
    main_pod.pod.verify()?;

    Ok(main_pod)
}

fn build_upvote_verification_main_pod(
    upvote_pod: &SignedPod,
    content_hash: &Hash,
    post_id: i64,
) -> Result<MainPod, Box<dyn std::error::Error>> {
    let mut params = Params::default();
    params.max_custom_batch_size = 10;

    let mock_prover = MockProver {};
    let vd_set = VDSet::new(8, &[])?;

    // Parse the FULL predicate
    let predicate_str = get_full_upvote_verification_predicate();
    let batch = parse(&predicate_str, &params, &[])?.custom_batch;

    let upvote_verified_pred = batch
        .predicate_ref_by_name("upvote_verified")
        .ok_or("upvote_verified predicate not found")?;

    // Build the main pod
    let mut builder = MainPodBuilder::new(&params, &vd_set);

    // Add the signed pod
    builder.add_signed_pod(upvote_pod);

    // Build upvote verification
    let upvote_type_check = builder.priv_op(op!(eq, (upvote_pod, KEY_TYPE), PodType::Signed))?;
    let upvote_content_check =
        builder.priv_op(op!(eq, (upvote_pod, "content_hash"), *content_hash))?;
    let upvote_post_check = builder.priv_op(op!(eq, (upvote_pod, "post_id"), post_id))?;
    let upvote_type_req_check = builder.priv_op(op!(eq, (upvote_pod, "request_type"), "upvote"))?;
    let upvote_verified_stmt = builder.pub_op(op!(
        custom,
        upvote_verified_pred.clone(),
        upvote_type_check,
        upvote_content_check,
        upvote_post_check,
        upvote_type_req_check
    ))?;

    // Prove
    let main_pod = builder.prove(&mock_prover, &params)?;
    main_pod.pod.verify()?;

    Ok(main_pod)
}

fn build_combined_verification_main_pod(
    identity_verification_pod: &MainPod,
    upvote_verification_pod: &MainPod,
    identity_pod: &SignedPod,
    upvote_pod: &SignedPod,
    identity_server_pk: &Point,
) -> Result<MainPod, Box<dyn std::error::Error>> {
    let mut params = Params::default();
    params.max_custom_batch_size = 10;

    let mock_prover = MockProver {};
    let vd_set = VDSet::new(8, &[])?;

    // Parse the FULL predicate
    let predicate_str = get_full_upvote_verification_predicate();
    let batch = parse(&predicate_str, &params, &[])?.custom_batch;

    let upvote_verification_pred = batch
        .predicate_ref_by_name("upvote_verification")
        .ok_or("upvote_verification predicate not found")?;

    // Build the main pod
    let mut builder = MainPodBuilder::new(&params, &vd_set);

    // Add the signed pods (needed for cross verification)
    builder.add_signed_pod(identity_pod);
    builder.add_signed_pod(upvote_pod);

    // Add the recursive pods
    builder.add_recursive_pod(identity_verification_pod.clone());
    builder.add_recursive_pod(upvote_verification_pod.clone());

    // Get the recursive statements
    let identity_verified_stmt = if !identity_verification_pod.public_statements.is_empty() {
        identity_verification_pod.public_statements
            [identity_verification_pod.public_statements.len() - 1]
            .clone()
    } else {
        return Err("Identity verification pod has no public statements".into());
    };

    let upvote_verified_stmt = if !upvote_verification_pod.public_statements.is_empty() {
        upvote_verification_pod.public_statements
            [upvote_verification_pod.public_statements.len() - 1]
            .clone()
    } else {
        return Err("Upvote verification pod has no public statements".into());
    };

    // Build cross verification constraints
    let identity_server_check = builder.priv_op(op!(
        eq,
        (identity_pod, KEY_SIGNER),
        identity_server_pk.clone()
    ))?;
    let user_key_check = builder.priv_op(op!(
        eq,
        (identity_pod, "user_public_key"),
        (upvote_pod, KEY_SIGNER)
    ))?;

    // Build the final upvote verification statement using recursive statements
    let upvote_verification_stmt = builder.pub_op(op!(
        custom,
        upvote_verification_pred.clone(),
        identity_verified_stmt,
        upvote_verified_stmt,
        identity_server_check,
        user_key_check
    ))?;

    // Prove
    let main_pod = builder.prove(&mock_prover, &params)?;
    main_pod.pod.verify()?;

    Ok(main_pod)
}

fn build_base_case_proof(
    username: &str,
    content_hash: &Hash,
    identity_server_pk: &Point,
    post_id: i64,
    server_sk: &SecretKey,
) -> Result<MainPod, Box<dyn std::error::Error>> {
    let mut params = Params::default();
    params.max_custom_batch_size = 10;

    let mock_prover = MockProver {};
    let vd_set = VDSet::new(8, &[])?;

    // Parse the FULL predicate
    let predicate_str = get_full_upvote_verification_predicate();
    let batch = parse(&predicate_str, &params, &[])?.custom_batch;

    let upvote_count_base_pred = batch
        .predicate_ref_by_name("upvote_count_base")
        .ok_or("upvote_count_base predicate not found")?;
    let upvote_count_pred = batch
        .predicate_ref_by_name("upvote_count")
        .ok_or("upvote_count predicate not found")?;

    // Build a signed pod containing the user data
    let mut base_case_data = SignedPodBuilder::new(&params);
    base_case_data.insert("username", username);
    base_case_data.insert("content_hash", *content_hash);
    base_case_data.insert("identity_server_pk", *identity_server_pk);
    base_case_data.insert("post_id", post_id);

    // Sign with server's private key
    let signer_key = server_sk.0.clone();
    let base_case_data = base_case_data.sign(&mut Signer(SecretKey(signer_key)))?;

    // Build the main pod
    let mut builder = MainPodBuilder::new(&params, &vd_set);
    builder.add_signed_pod(&base_case_data);

    // Base case: count = 0
    let zero_check = builder.priv_op(op!(eq, 0, 0))?;
    let username_stmt = builder.pub_op(op!(eq, (&base_case_data, "username"), username))?;
    let content_hash_stmt =
        builder.pub_op(op!(eq, (&base_case_data, "content_hash"), *content_hash))?;
    let identity_server_pk_stmt = builder.pub_op(op!(
        eq,
        (&base_case_data, "identity_server_pk"),
        *identity_server_pk
    ))?;
    let post_id_stmt = builder.pub_op(op!(eq, (&base_case_data, "post_id"), post_id))?;
    let base_case_stmt = builder.priv_op(op!(
        custom,
        upvote_count_base_pred.clone(),
        zero_check,
        username_stmt,
        content_hash_stmt,
        identity_server_pk_stmt,
        post_id_stmt
    ))?;

    // Public upvote_count statement
    let public_stmt = builder.pub_op(op!(
        custom,
        upvote_count_pred.clone(),
        base_case_stmt.clone(),
        base_case_stmt
    ))?;

    // Prove
    let main_pod = builder.prove(&mock_prover, &params)?;
    main_pod.pod.verify()?;

    Ok(main_pod)
}

fn build_inductive_proof(
    base_case_pod: &MainPod,
    upvote_verification_pod: &MainPod,
    current_count: i64,
) -> Result<MainPod, Box<dyn std::error::Error>> {
    let mut params = Params::default();
    params.max_custom_batch_size = 10;

    let mock_prover = MockProver {};
    let vd_set = VDSet::new(8, &[])?;

    // Parse the FULL predicate
    let predicate_str = get_full_upvote_verification_predicate();
    let batch = parse(&predicate_str, &params, &[])?.custom_batch;

    let upvote_count_ind_pred = batch
        .predicate_ref_by_name("upvote_count_ind")
        .ok_or("upvote_count_ind predicate not found")?;
    let upvote_count_pred = batch
        .predicate_ref_by_name("upvote_count")
        .ok_or("upvote_count predicate not found")?;

    // Build the main pod
    let mut builder = MainPodBuilder::new(&params, &vd_set);

    // Add recursive pods
    builder.add_recursive_pod(base_case_pod.clone());
    builder.add_recursive_pod(upvote_verification_pod.clone());

    // Get the recursive statements
    let previous_count_stmt = if !base_case_pod.public_statements.is_empty() {
        base_case_pod.public_statements[base_case_pod.public_statements.len() - 1].clone()
    } else {
        return Err("Base case pod has no public statements".into());
    };

    let verification_stmt = if !upvote_verification_pod.public_statements.is_empty() {
        upvote_verification_pod.public_statements
            [upvote_verification_pod.public_statements.len() - 1]
            .clone()
    } else {
        return Err("Upvote verification pod has no public statements".into());
    };

    // SumOf: current_count = previous_count + 1
    let previous_count = current_count - 1;
    let sum_stmt = builder.priv_op(op!(sum_of, current_count, previous_count, 1))?;

    // Build inductive case (THIS IS WHERE IT SHOULD FAIL)
    let inductive_stmt = builder.priv_op(op!(
        custom,
        upvote_count_ind_pred.clone(),
        previous_count_stmt,
        sum_stmt,
        verification_stmt
    ))?;

    // Public statement
    let public_stmt = builder.pub_op(op!(
        custom,
        upvote_count_pred.clone(),
        inductive_stmt.clone(),
        inductive_stmt
    ))?;

    // Prove (this should fail)
    let main_pod = builder.prove(&mock_prover, &params)?;
    main_pod.pod.verify()?;

    Ok(main_pod)
}
