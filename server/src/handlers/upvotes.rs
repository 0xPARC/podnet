use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use pod_utils::ValueExt;
use pod2::backends::plonky2::{
    primitives::ec::{curve::Point, schnorr::SecretKey},
    signedpod::Signer,
};
use pod2::frontend::{MainPod, SignedPod, SignedPodBuilder};
use pod2::middleware::Hash;
use podnet_models::{UpvoteRequest, get_upvote_verification_predicate};
use std::sync::Arc;

use crate::pod::get_server_secret_key;

pub async fn upvote_document(
    Path(document_id): Path<i64>,
    State(state): State<Arc<crate::AppState>>,
    Json(payload): Json<UpvoteRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    use pod2::lang::parse;
    use pod2::middleware::Statement;

    log::info!("Processing upvote for document {document_id} with main pod verification");

    let params = state.pod_config.get_params();
    let (_vd_set, _prover) = state.pod_config.get_prover_setup()?;

    // Verify main pod proof
    log::info!("Verifying upvote main pod proof");
    payload.upvote_main_pod.pod.verify().map_err(|e| {
        log::error!("Failed to verify upvote main pod: {e}");
        StatusCode::UNAUTHORIZED
    })?;
    log::info!("✓ Upvote main pod proof verified");

    // Verify the main pod contains the expected public statements
    log::info!("Verifying upvote main pod public statements");

    // Get predicate definition from shared models
    let predicate_input = get_upvote_verification_predicate();
    log::info!("Upvote predicate text is: {predicate_input}");

    log::info!("Parsing custom predicates");
    let batch = parse(&predicate_input, &params, &[])
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .custom_batch;
    let upvote_verification_pred = batch.predicate_ref_by_name("upvote_verification").unwrap();

    let upvote_verification_args = payload
        .upvote_main_pod
        .public_statements
        .iter()
        .find_map(|v| match v {
            Statement::Custom(pred, args) if *pred == upvote_verification_pred => Some(args),
            _ => None,
        })
        .ok_or_else(|| {
            log::error!("Upvote main pod public statements missing upvote_verification predicate");
            StatusCode::BAD_REQUEST
        })?;

    log::info!("✓ Upvote main pod public statements present");

    // Extract public data directly from main pod
    log::info!("Extracting public data from upvote main pod");
    let username = upvote_verification_args[0]
        .as_str()
        .ok_or_else(|| {
            log::error!("upvote_verification predicate missing username argument");
            StatusCode::BAD_REQUEST
        })?
        .to_string();
    let content_hash = upvote_verification_args[1].as_hash().ok_or_else(|| {
        log::error!("upvote_verification predicate missing content_hash argument");
        StatusCode::BAD_REQUEST
    })?;
    let identity_server_pk = upvote_verification_args[2].as_public_key().ok_or_else(|| {
        log::error!("upvote_verification predicate missing identity_server_pk argument");
        StatusCode::BAD_REQUEST
    })?;

    log::info!(
        "✓ Extracted public data: username={}, content_hash={}",
        username,
        content_hash,
    );

    // Verify the identity server public key is registered in our database
    log::info!("Verifying identity server is registered");

    // Convert identity server public key to JSON for database lookup
    let identity_server_pk_json = serde_json::to_string(&identity_server_pk).map_err(|e| {
        log::error!("Failed to serialize identity server public key: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Find the identity server by public key
    let identity_server = state
        .db
        .get_identity_server_by_public_key(&identity_server_pk_json)
        .map_err(|e| {
            log::error!("Database error retrieving identity server: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            log::error!("Identity server with public key not registered");
            StatusCode::UNAUTHORIZED
        })?;

    log::info!(
        "✓ Identity server {} verified as registered",
        identity_server.server_id
    );

    // Get the actual document to verify content hash and post ID
    let document = state
        .db
        .get_document_metadata(document_id)
        .map_err(|e| {
            log::error!("Database error retrieving document {document_id}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            log::error!("Document {document_id} not found");
            StatusCode::NOT_FOUND
        })?;

    // Verify the content hash matches the actual document's content hash
    if document.content_id != content_hash {
        log::error!(
            "Content hash mismatch: document={} vs upvote={}",
            document.content_id,
            content_hash
        );
        return Err(StatusCode::BAD_REQUEST);
    }
    log::info!("✓ Content hash verified");

    // Check if user has already upvoted this document (by username)
    let already_upvoted = state
        .db
        .user_has_upvoted(document_id, &username)
        .map_err(|e| {
            log::error!("Database error checking existing upvote: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if already_upvoted {
        log::warn!(
            "User {} has already upvoted document {document_id}",
            username
        );
        return Err(StatusCode::CONFLICT);
    }

    // Store the upvote with the main pod (no user public key needed)
    let upvote_main_pod_json = serde_json::to_string(&payload.upvote_main_pod).map_err(|e| {
        log::error!("Failed to serialize upvote main pod: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let upvote_id = state
        .db
        .create_upvote(document_id, &username, &upvote_main_pod_json)
        .map_err(|e| {
            log::error!("Failed to store upvote: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    log::info!("✓ Upvote stored with ID: {upvote_id}");

    // Get updated upvote count
    let upvote_count = state.db.get_upvote_count(document_id).map_err(|e| {
        log::error!("Failed to get upvote count: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    log::info!("Document {document_id} now has {upvote_count} upvotes");

    // Spawn background task to generate inductive upvote count pod
    let state_clone = state.clone();
    let doc_id = document_id;
    let hash = content_hash;
    let current_count = upvote_count;

    tokio::spawn(async move {
        if let Err(e) = generate_inductive_upvote_pod(
            state_clone,
            doc_id,
            &hash,
            current_count,
            &payload.upvote_main_pod,
        )
        .await
        {
            log::error!(
                "Failed to generate inductive upvote count pod for document {}: {}",
                doc_id,
                e
            );
        }
    });

    Ok(Json(serde_json::json!({
        "success": true,
        "upvote_id": upvote_id,
        "document_id": document_id,
        "upvote_count": upvote_count
    })))
}

pub async fn generate_base_case_upvote_pod(
    state: Arc<crate::AppState>,
    document_id: i64,
    content_hash: &Hash,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use pod2::frontend::MainPodBuilder;
    use pod2::op;

    tracing::info!(
        "Generating base case upvote count pod for document {}",
        document_id
    );

    let server_sk = get_server_secret_key();

    // Get predicate batch and parameters (similar to existing code)
    let predicate_str = podnet_models::get_upvote_verification_predicate();
    let params = state.pod_config.get_params();
    let batch = pod2::lang::parse(&predicate_str, &params, &[])
        .map_err(|e| format!("Failed to parse predicate: {}", e))?;

    let (vd_set, prover) = state
        .pod_config
        .get_prover_setup()
        .map_err(|e| format!("Failed to get prover setup: {:?}", e))?;

    // create signed pod with public data
    let mut data_builder = SignedPodBuilder::new(&params);
    data_builder.insert("content_hash", *content_hash);
    let mut server_signer = Signer(SecretKey(server_sk.0.clone()));
    let data_pod = data_builder.sign(&mut server_signer)?;

    let upvote_count_base = batch
        .custom_batch
        .predicate_ref_by_name("upvote_count_base")
        .ok_or("upvote_count_base predicate not found")?;
    let upvote_count = batch
        .custom_batch
        .predicate_ref_by_name("upvote_count")
        .ok_or("upvote_count predicate not found")?;

    // Build base case main pod (count = 0)
    log::info!("Building base case upvote count pod (count=0)...");
    let mut base_builder = MainPodBuilder::new(&params, vd_set);
    base_builder.add_signed_pod(&data_pod);

    // Create the base case: Equal(count, 0)
    let equals_zero_stmt = base_builder.priv_op(op!(eq, 0, 0))?;
    let content_hash_stmt =
        base_builder.priv_op(op!(eq, (&data_pod, "content_hash"), *content_hash))?;
    let upvote_count_base_stmt = base_builder.priv_op(op!(
        custom,
        upvote_count_base.clone(),
        equals_zero_stmt,
        content_hash_stmt
    ))?;
    let _count_stmt = base_builder.pub_op(op!(
        custom,
        upvote_count.clone(),
        upvote_count_base_stmt.clone(),
        upvote_count_base_stmt
    ))?;

    // Generate the proof
    let main_pod = base_builder.prove(&*prover, &params)?;
    main_pod.pod.verify()?;
    log::info!(
        "✓ Successfully proved upvote_count(0) for document {}",
        document_id
    );

    // Store the pod in the database
    let pod_json = serde_json::to_string(&main_pod)
        .map_err(|e| format!("Failed to serialize main pod: {}", e))?;

    state
        .db
        .update_upvote_count_pod(document_id, &pod_json)
        .map_err(|e| format!("Failed to store upvote count pod: {}", e))?;

    log::info!(
        "✓ Stored base case upvote count pod for document {}",
        document_id
    );

    Ok(())
}

async fn generate_inductive_upvote_pod(
    state: Arc<crate::AppState>,
    document_id: i64,
    content_hash: &Hash,
    current_count: i64,
    upvote_verification_pod: &MainPod,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use pod2::frontend::MainPodBuilder;
    use pod2::op;

    log::info!(
        "Generating inductive upvote count pod for document {} (count={})",
        document_id,
        current_count
    );

    // Get the previous upvote count pod from database (for recursive proof)
    let previous_pod_json = state
        .db
        .get_upvote_count_pod(document_id)
        .map_err(|e| format!("Failed to get previous upvote count pod: {}", e))?;

    let previous_pod = match previous_pod_json {
        Some(json) => serde_json::from_str::<pod2::frontend::MainPod>(&json)
            .map_err(|e| format!("Failed to parse previous main pod: {}", e))?,
        None => {
            log::warn!(
                "No previous upvote count pod found for document {}, generating base case first",
                document_id
            );
            // If no previous pod exists, generate base case first
            generate_base_case_upvote_pod(state.clone(), document_id, content_hash).await?;

            // Then get the newly created base case pod
            let base_pod_json = state
                .db
                .get_upvote_count_pod(document_id)
                .map_err(|e| format!("Failed to get base case pod after generation: {}", e))?
                .ok_or("Base case pod not found after generation")?;

            serde_json::from_str::<pod2::frontend::MainPod>(&base_pod_json)
                .map_err(|e| format!("Failed to parse base case main pod: {}", e))?
        }
    };

    // Get predicate batch and parameters
    let predicate_str = podnet_models::get_upvote_verification_predicate();
    let params = state.pod_config.get_params();
    let batch = pod2::lang::parse(&predicate_str, &params, &[])
        .map_err(|e| format!("Failed to parse predicate: {}", e))?;

    let (vd_set, prover) = state
        .pod_config
        .get_prover_setup()
        .map_err(|e| format!("Failed to get prover setup: {:?}", e))?;

    let upvote_count_ind = batch
        .custom_batch
        .predicate_ref_by_name("upvote_count_ind")
        .ok_or("upvote_count_ind predicate not found")?;
    let upvote_count = batch
        .custom_batch
        .predicate_ref_by_name("upvote_count")
        .ok_or("upvote_count predicate not found")?;

    // Build inductive case main pod (count = previous_count + 1)
    log::info!(
        "Building inductive upvote count pod (count={})...",
        current_count
    );
    let mut ind_builder = MainPodBuilder::new(&params, vd_set);

    // Add the previous pod as a recursive dependency
    ind_builder.add_recursive_pod(previous_pod.clone());
    ind_builder.add_recursive_pod(upvote_verification_pod.clone());

    // Create SumOf operation: current_count = previous_count + 1
    let previous_count = current_count - 1;
    let sum_of_stmt = ind_builder.priv_op(op!(sum_of, current_count, previous_count, 1))?;

    // Get the recursive statement from the previous pod (should be the public upvote_count statement)
    let recursive_statement = if !previous_pod.public_statements.is_empty() {
        previous_pod.public_statements.last().unwrap()
    } else {
        return Err("Previous pod has no public statements".into());
    };

    // Get the upvote verification predicate from the previous pod
    let upvote_verification_stmt = if !upvote_verification_pod.public_statements.is_empty() {
        upvote_verification_pod.public_statements.last().unwrap()
    } else {
        return Err("Upvote verification pod has no public statements".into());
    };

    // Create the inductive case statement
    let ind_count_stmt = ind_builder.priv_op(op!(
        custom,
        upvote_count_ind.clone(),
        recursive_statement,
        sum_of_stmt,
        upvote_verification_stmt
    ))?;

    // Create the public upvote_count statement
    let _count_stmt = ind_builder.pub_op(op!(
        custom,
        upvote_count.clone(),
        ind_count_stmt.clone(),
        ind_count_stmt
    ))?;

    // Generate the proof
    let main_pod = ind_builder.prove(&*prover, &params)?;
    main_pod.pod.verify()?;
    log::info!(
        "✓ Successfully proved upvote_count({}) for document {}",
        current_count,
        document_id
    );

    // Store the pod in the database
    let pod_json = serde_json::to_string(&main_pod)
        .map_err(|e| format!("Failed to serialize main pod: {}", e))?;

    state
        .db
        .update_upvote_count_pod(document_id, &pod_json)
        .map_err(|e| format!("Failed to store upvote count pod: {}", e))?;

    log::info!(
        "✓ Stored inductive upvote count pod for document {} (count={})",
        document_id,
        current_count
    );

    Ok(())
}
