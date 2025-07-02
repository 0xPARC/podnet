use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use hex::ToHex;
use pulldown_cmark::{Event, Options, Parser, html};
use std::sync::Arc;

use pod2::frontend::{MainPod, MainPodBuilder, SignedPod, SignedPodBuilder};
use pod2::middleware::Hash;
use pod2::op;

use pod_utils::ValueExt;
use podnet_models::{
    Document, DocumentMetadata, IdentityServerRegistration, PostWithDocuments, PublishRequest,
    ServerInfo, UpvoteRequest, UserRegistration, get_publish_verification_predicate,
    get_upvote_verification_predicate,
};

pub async fn root() -> Json<ServerInfo> {
    let public_key = crate::pod::get_server_public_key();
    Json(ServerInfo { public_key })
}

pub async fn get_posts(
    State(state): State<Arc<crate::AppState>>,
) -> Result<Json<Vec<PostWithDocuments>>, StatusCode> {
    let posts = state
        .db
        .get_all_posts()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut posts_with_documents = Vec::new();
    for post in posts {
        if post.id.is_none() {
            continue; // Skip posts without an ID
        }

        let post_id = post.id.unwrap();
        let documents_metadata = state
            .db
            .get_documents_metadata_by_post_id(post_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        posts_with_documents.push(PostWithDocuments {
            id: post.id,
            created_at: post.created_at,
            last_edited_at: post.last_edited_at,
            documents: documents_metadata,
        });
    }
    Ok(Json(posts_with_documents))
}

pub async fn get_documents(
    State(state): State<Arc<crate::AppState>>,
) -> Result<Json<Vec<DocumentMetadata>>, StatusCode> {
    let documents_metadata = state
        .db
        .get_all_documents_metadata()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(documents_metadata))
}

async fn get_post_with_documents_from_db(
    post_id: i64,
    state: Arc<crate::AppState>,
) -> Result<PostWithDocuments, StatusCode> {
    let post = state
        .db
        .get_post(post_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let documents_metadata = state
        .db
        .get_documents_metadata_by_post_id(post_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(PostWithDocuments {
        id: post.id,
        created_at: post.created_at,
        last_edited_at: post.last_edited_at,
        documents: documents_metadata,
    })
}

async fn get_document_from_db(
    document_id: i64,
    state: Arc<crate::AppState>,
) -> Result<Document, StatusCode> {
    let document = state
        .db
        .get_document(document_id, &*state.storage)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(document)
}

pub async fn get_post_by_id(
    Path(id): Path<i64>,
    State(state): State<Arc<crate::AppState>>,
) -> Result<Json<PostWithDocuments>, StatusCode> {
    let post_with_documents = get_post_with_documents_from_db(id, state).await?;
    Ok(Json(post_with_documents))
}

pub async fn get_document_by_id(
    Path(id): Path<i64>,
    State(state): State<Arc<crate::AppState>>,
) -> Result<Json<Document>, StatusCode> {
    let document = get_document_from_db(id, state).await?;
    Ok(Json(document))
}

pub async fn get_rendered_document_by_id(
    Path(id): Path<i64>,
    State(state): State<Arc<crate::AppState>>,
) -> Result<Json<Document>, StatusCode> {
    let mut document = get_document_from_db(id, state).await?;

    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_FOOTNOTES);
    options.insert(Options::ENABLE_SUPERSCRIPT);
    options.insert(Options::ENABLE_TASKLISTS);
    options.insert(Options::ENABLE_GFM);
    options.insert(Options::ENABLE_SMART_PUNCTUATION);
    options.insert(Options::ENABLE_HEADING_ATTRIBUTES);

    let content = &document.content;

    let parser = Parser::new_ext(content, options);
    let mut events = Vec::new();
    let mut in_math = false;
    let mut math_content = String::new();

    // skip math
    for event in parser {
        match event {
            Event::Text(text) => {
                let text_str = text.as_ref();
                if text_str.starts_with("$$") {
                    in_math = true;
                    math_content = text_str.to_string();
                } else if text_str.ends_with("$$") && in_math {
                    math_content.push_str(text_str);
                    events.push(Event::Html(math_content.clone().into()));
                    math_content.clear();
                    in_math = false;
                } else if in_math {
                    math_content.push_str(text_str);
                } else {
                    events.push(Event::Text(text));
                }
            }
            _ if in_math => {
                // Skip other events while in math mode
                continue;
            }
            other => events.push(other),
        }
    }

    let mut html_output = String::new();
    html::push_html(&mut html_output, events.into_iter());
    document.content = html_output.clone();

    Ok(Json(document))
}

#[axum::debug_handler]
pub async fn publish_document(
    State(state): State<Arc<crate::AppState>>,
    Json(payload): Json<PublishRequest>,
) -> Result<Json<Document>, StatusCode> {
    use pod2::backends::plonky2::{
        basetypes::DEFAULT_VD_SET, mainpod::Prover, mock::mainpod::MockProver,
    };
    use pod2::frontend::MainPodBuilder;
    use pod2::lang::parse;
    use pod2::middleware::Statement;
    use pod2::middleware::{KEY_SIGNER, KEY_TYPE, Params, PodProver, PodType};
    use pod2::op;

    log::info!("Starting document publish with main pod verification");
    log::debug!("Content length: {} bytes", payload.content.len());

    let mut params = Params::default();

    // Choose prover based on mock flag
    let mock_prover = MockProver {};
    let real_prover = Prover {};
    let use_mock = false;
    let (vd_set, prover): (_, &dyn PodProver) = if use_mock {
        println!("Using MockMainPod for publish verification");
        (
            &pod2::middleware::VDSet::new(8, &[]).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            &mock_prover,
        )
    } else {
        println!("Using MainPod for publish verification");
        (&*DEFAULT_VD_SET, &real_prover)
    };

    // Verify main pod proof
    log::info!("Verifying main pod proof");
    payload.main_pod.pod.verify().map_err(|e| {
        log::error!("Failed to verify main pod: {e}");
        StatusCode::UNAUTHORIZED
    })?;
    log::info!("✓ Main pod proof verified");

    // Verify the main pod contains the expected public statements
    log::info!("Verifying main pod public statements");

    // Get predicate definition from shared pod-utils
    let predicate_input = get_publish_verification_predicate();
    log::info!("Publish predicate text is: {predicate_input}");

    log::info!("Parsing custom predicates");
    let batch = parse(&predicate_input, &params, &[])
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .custom_batch;
    let publish_verification_pred = batch.predicate_ref_by_name("publish_verification").unwrap();

    let publish_verification_args = payload
        .main_pod
        .public_statements
        .iter()
        .find_map(|v| match v {
            Statement::Custom(pred, args) if *pred == publish_verification_pred => Some(args),
            _ => None,
        })
        .ok_or_else(|| {
            log::error!("Main pod public statements missing publish_verification predicate");
            StatusCode::BAD_REQUEST
        })?;

    log::info!("✓ Main pod public statements present");

    // Extract public data directly from main pod
    log::info!("Extracting public data from main pod");
    let username = publish_verification_args[0].as_str().ok_or_else(|| {
        log::error!("publish_verification predicate missing username argument");
        StatusCode::BAD_REQUEST
    })?;
    let content_hash = publish_verification_args[1].as_hash().ok_or_else(|| {
        log::error!("publish_verification predicate missing content_hash argument");
        StatusCode::BAD_REQUEST
    })?;
    let identity_server_pk = publish_verification_args[2]
        .as_public_key()
        .ok_or_else(|| {
            log::error!("publish_verification predicate missing identity_server_pk argument");
            StatusCode::BAD_REQUEST
        })?;
    let post_id = publish_verification_args[3].as_i64().ok_or_else(|| {
        log::error!("publish_verification predicate missing post_id argument");
        StatusCode::BAD_REQUEST
    })?;

    log::info!(
        "✓ Extracted public data: username={}, content_hash={}, post_id={}",
        username,
        content_hash,
        post_id
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

    // Store the content and get its hash
    log::info!("Storing content in content-addressed storage");
    let stored_content_hash = state.storage.store(&payload.content).map_err(|e| {
        log::error!("Failed to store content: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    log::info!("Content stored successfully with hash: {stored_content_hash}");

    // Verify content hash matches what's in the main pod
    if stored_content_hash != content_hash {
        log::error!(
            "Content hash mismatch: stored={} vs main_pod={}",
            stored_content_hash,
            content_hash
        );
        return Err(StatusCode::BAD_REQUEST);
    }
    log::info!("✓ Content hash verified");

    // Store the main pod instead of a temporary pod
    let pod_json = serde_json::to_string(&payload.main_pod).map_err(|e| {
        log::error!("Failed to convert main pod to JSON: {e}");
        StatusCode::BAD_REQUEST
    })?;

    // Determine post_id: either create new post or use existing
    log::info!("Determining post ID");
    let final_post_id = if post_id != -1 {
        log::info!("Using existing post ID: {post_id}");
        // Verify the post exists
        state
            .db
            .get_post(post_id)
            .map_err(|e| {
                log::error!("Database error checking post {post_id}: {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .ok_or_else(|| {
                log::error!("Post {post_id} not found");
                StatusCode::NOT_FOUND
            })?;
        log::info!("Post {post_id} exists");
        post_id
    } else {
        log::info!("Creating new post");
        let id = state.db.create_post().map_err(|e| {
            log::error!("Failed to create new post: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        log::info!("New post created with ID: {id}");
        id
    };

    // Create document with timestamp pod in a single transaction
    log::info!("Creating document for post {final_post_id}");
    let document = state
        .db
        .create_document(
            &content_hash,
            final_post_id,
            &payload.main_pod,
            &username,
            &*state.storage,
        )
        .map_err(|e| {
            log::error!("Failed to create document: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    log::info!("Document created with ID: {:?}", document.metadata.id);

    // Spawn background task to generate base case upvote count pod
    if let Some(document_id) = document.metadata.id {
        let state_clone = state.clone();
        let content_hash = document.metadata.content_id.clone();
        let post_id = document.metadata.post_id;

        tokio::spawn(async move {
            if let Err(e) =
                generate_base_case_upvote_pod(state_clone, document_id, &content_hash, post_id)
                    .await
            {
                log::error!(
                    "Failed to generate base case upvote count pod for document {}: {}",
                    document_id,
                    e
                );
            }
        });
    }

    log::info!("Document publish completed successfully using main pod verification");
    Ok(Json(document))
}

pub async fn register_user(
    State(state): State<Arc<crate::AppState>>,
    Json(payload): Json<UserRegistration>,
) -> Result<Json<ServerInfo>, StatusCode> {
    log::info!("Registering user: {}", payload.user_id);

    // Check if user already exists
    if let Ok(Some(_)) = state.db.get_user_by_id(&payload.user_id) {
        log::warn!("User {} already exists", payload.user_id);
        return Err(StatusCode::CONFLICT);
    }

    let pk_string = serde_json::to_string(&payload.public_key).map_err(|_e| {
        log::warn!("Unable to serialize public key: {}", payload.public_key);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Create user
    state
        .db
        .create_user(&payload.user_id, &pk_string)
        .map_err(|e| {
            log::error!("Failed to create user {}: {}", payload.user_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    log::info!("User {} registered successfully", payload.user_id);

    // Return server info
    let server_pk = crate::pod::get_server_public_key();
    Ok(Json(ServerInfo {
        public_key: server_pk,
    }))
}

pub async fn register_identity_server(
    State(state): State<Arc<crate::AppState>>,
    Json(payload): Json<IdentityServerRegistration>,
) -> Result<Json<ServerInfo>, StatusCode> {
    // Verify the challenge response pod
    payload.challenge_response.verify().map_err(|e| {
        log::error!("Failed to verify identity server challenge response: {e}");
        StatusCode::BAD_REQUEST
    })?;

    // Extract data from the signed pod
    let signer = payload
        .challenge_response
        .get("_signer")
        .map(|v| v.as_public_key())
        .ok_or_else(|| {
            log::error!("Challenge response pod missing signer");
            StatusCode::BAD_REQUEST
        })?;

    let server_id = payload
        .challenge_response
        .get("server_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            log::error!("Challenge response pod missing server_id");
            StatusCode::BAD_REQUEST
        })?;

    // TODO: Verify the challenge was actually sent by this server
    payload.challenge_response.get("challenge").ok_or_else(|| {
        log::error!("Challenge response pod missing challenge");
        StatusCode::BAD_REQUEST
    })?;

    log::info!("Registering identity server: {}", server_id);

    // Check if identity server already exists
    if let Ok(Some(_)) = state.db.get_identity_server_by_id(server_id) {
        log::warn!("Identity server {} already exists", server_id);
        return Err(StatusCode::CONFLICT);
    }

    let pk_string = serde_json::to_string(&signer).map_err(|e| {
        log::error!("Unable to serialize identity server public key: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let registration_pod_string =
        serde_json::to_string(&payload.challenge_response).map_err(|e| {
            log::error!("Unable to serialize registration pod: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Create identity server
    state
        .db
        .create_identity_server(server_id, &pk_string, &registration_pod_string)
        .map_err(|e| {
            log::error!("Failed to create identity server {}: {}", server_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    log::info!("Identity server {} registered successfully", server_id);

    // Return server info
    let server_pk = crate::pod::get_server_public_key();
    Ok(Json(ServerInfo {
        public_key: server_pk,
    }))
}

pub async fn upvote_document(
    Path(document_id): Path<i64>,
    State(state): State<Arc<crate::AppState>>,
    Json(payload): Json<UpvoteRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    use pod2::backends::plonky2::{
        basetypes::DEFAULT_VD_SET, mainpod::Prover, mock::mainpod::MockProver,
    };
    use pod2::lang::parse;
    use pod2::middleware::{Params, PodProver, Statement};

    log::info!("Processing upvote for document {document_id} with main pod verification");

    let mut params = Params::default();
    params.max_custom_batch_size = 6;

    // Choose prover based on mock flag
    let mock_prover = MockProver {};
    let real_prover = Prover {};
    let use_mock = true;
    let (vd_set, prover): (_, &dyn PodProver) = if use_mock {
        println!("Using MockMainPod for upvote verification");
        (
            &pod2::middleware::VDSet::new(8, &[]).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            &mock_prover,
        )
    } else {
        println!("Using MainPod for upvote verification");
        (&*DEFAULT_VD_SET, &real_prover)
    };

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
    let post_id = upvote_verification_args[3].as_i64().ok_or_else(|| {
        log::error!("upvote_verification predicate missing post_id argument");
        StatusCode::BAD_REQUEST
    })?;

    log::info!(
        "✓ Extracted public data: username={}, content_hash={}, post_id={}",
        username,
        content_hash,
        post_id
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

    // Verify post ID matches
    if document.post_id != post_id {
        log::error!(
            "Post ID mismatch: document={} vs upvote={}",
            document.post_id,
            post_id
        );
        return Err(StatusCode::BAD_REQUEST);
    }
    log::info!("✓ Post ID verified");

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
    let p_id = post_id;
    let current_count = upvote_count;

    tokio::spawn(async move {
        if let Err(e) =
            generate_inductive_upvote_pod(state_clone, doc_id, &hash, p_id, current_count).await
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

async fn generate_base_case_upvote_pod(
    state: Arc<crate::AppState>,
    document_id: i64,
    content_hash: &Hash,
    post_id: i64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use pod2::backends::plonky2::mainpod::Prover;
    use pod2::backends::plonky2::mock::mainpod::MockProver;
    use pod2::frontend::MainPodBuilder;
    use pod2::op;

    log::info!(
        "Generating base case upvote count pod for document {}",
        document_id
    );

    // Get predicate batch and parameters (similar to existing code)
    let predicate_str = podnet_models::get_upvote_verification_predicate();
    let mut params = pod2::middleware::Params::default();
    params.max_custom_batch_size = 6; // Set appropriate batch size
    let batch = pod2::lang::parse(&predicate_str, &params, &[])
        .map_err(|e| format!("Failed to parse predicate: {}", e))?;

    // Choose prover based on mock flag
    let mock_prover = MockProver {};
    let real_prover = Prover {};
    let use_mock = true;
    let (vd_set, prover): (_, &dyn pod2::middleware::PodProver) = if use_mock {
        log::info!("Using MockMainPod for base case upvote verification");
        (
            &pod2::middleware::VDSet::new(8, &[])
                .map_err(|e| format!("Failed to create VDSet: {}", e))?,
            &mock_prover,
        )
    } else {
        log::info!("Using MainPod for base case upvote verification");
        (
            &*pod2::backends::plonky2::basetypes::DEFAULT_VD_SET,
            &real_prover,
        )
    };

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

    // Create the base case: Equal(count, 0)
    let equals_zero_stmt = base_builder.priv_op(op!(eq, 0, 0))?;
    let upvote_count_base_stmt =
        base_builder.priv_op(op!(custom, upvote_count_base.clone(), equals_zero_stmt))?;
    let count_stmt = base_builder.pub_op(op!(
        custom,
        upvote_count.clone(),
        upvote_count_base_stmt.clone(),
        upvote_count_base_stmt
    ))?;

    // Generate the proof
    let main_pod = base_builder.prove(prover, &params)?;
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
    post_id: i64,
    current_count: i64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use pod2::backends::plonky2::mainpod::Prover;
    use pod2::backends::plonky2::mock::mainpod::MockProver;
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
            generate_base_case_upvote_pod(state.clone(), document_id, content_hash, post_id)
                .await?;

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
    let mut params = pod2::middleware::Params::default();
    params.max_custom_batch_size = 6; // Set appropriate batch size
    let batch = pod2::lang::parse(&predicate_str, &params, &[])
        .map_err(|e| format!("Failed to parse predicate: {}", e))?;

    // Choose prover based on mock flag
    let mock_prover = MockProver {};
    let real_prover = Prover {};
    let use_mock = true;
    let (vd_set, prover): (_, &dyn pod2::middleware::PodProver) = if use_mock {
        log::info!("Using MockMainPod for inductive upvote verification");
        (
            &pod2::middleware::VDSet::new(8, &[])
                .map_err(|e| format!("Failed to create VDSet: {}", e))?,
            &mock_prover,
        )
    } else {
        log::info!("Using MainPod for inductive upvote verification");
        (
            &*pod2::backends::plonky2::basetypes::DEFAULT_VD_SET,
            &real_prover,
        )
    };

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

    // Create SumOf operation: current_count = previous_count + 1
    let previous_count = current_count - 1;
    let sum_of_stmt = ind_builder.priv_op(op!(sum_of, current_count, previous_count, 1))?;

    // Get the recursive statement from the previous pod (should be the public upvote_count statement)
    let recursive_statement = if !previous_pod.public_statements.is_empty() {
        previous_pod.public_statements[previous_pod.public_statements.len() - 1].clone()
    } else {
        return Err("Previous pod has no public statements".into());
    };

    // Create the inductive case statement
    let ind_count_stmt = ind_builder.priv_op(op!(
        custom,
        upvote_count_ind.clone(),
        recursive_statement,
        sum_of_stmt
    ))?;

    // Create the public upvote_count statement
    let count_stmt = ind_builder.pub_op(op!(
        custom,
        upvote_count.clone(),
        ind_count_stmt.clone(),
        ind_count_stmt
    ))?;

    // Generate the proof
    let main_pod = ind_builder.prove(prover, &params)?;
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
