use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use pulldown_cmark::{Event, Options, Parser, html};
use std::sync::Arc;

use pod2::{frontend::SignedPod, middleware::KEY_TYPE};

use crate::models::{
    DocumentMetadata, DocumentWithContent, IdentityServerRegistration, PostWithDocuments,
    PublishRequest, ServerInfo, UserRegistration,
};
use pod_utils::{ValueExt, get_publish_verification_predicate};

/// This function ensures the signed pod json has the expected podType array
/// which gives its type as a number and "Signed" string.
fn validate_signed_pod_json(pod: &serde_json::Value) -> Result<(), StatusCode> {
    // Check if podType exists and is an array
    let pod_type = pod
        .get("podType")
        .and_then(|v| v.as_array())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Verify podType has exactly 2 elements
    if pod_type.len() != 2 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check first element is the number 4
    let type_number = pod_type[0].as_i64().ok_or(StatusCode::BAD_REQUEST)?;
    if type_number != 4 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check second element is the string "Signed"
    let type_string = pod_type[1].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    if type_string != "Signed" {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Verify pod has required structure (data field with signature)
    pod.get("data")
        .and_then(|d| d.get("signature"))
        .ok_or(StatusCode::BAD_REQUEST)?;

    Ok(())
}

fn validate_signed_pod(pod: &SignedPod) -> Result<(), StatusCode> {
    // Check if podType is valid
    let ty = pod.get(KEY_TYPE).ok_or(StatusCode::BAD_REQUEST)?;
    if *ty != 4.into() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Verify the pod signature
    log::info!("Verifying document pod signature");
    pod.verify().map_err(|e| {
        log::error!("Signed pod signature verification failed: {e}");
        StatusCode::UNAUTHORIZED
    })?;
    log::info!("Document pod signature verified");

    Ok(())
}

fn verify_public_key(pod: &serde_json::Value, provided_public_key: &str) -> Result<(), StatusCode> {
    // Extract the public key from the pod's signer field
    let pod_public_key = pod
        .pointer("/data/kvs/kvs/_signer/PublicKey")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Verify the provided public key matches the one in the pod
    if pod_public_key != provided_public_key {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(())
}

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
        let documents = state
            .db
            .get_documents_by_post_id(post_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let mut documents_with_content = Vec::new();
        for document in documents {
            let pod_value: serde_json::Value = serde_json::from_str(&document.pod)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            let timestamp_pod_value = serde_json::from_str(&document.timestamp_pod).ok();

            documents_with_content.push(DocumentWithContent {
                id: document.id,
                content_id: document.content_id,
                post_id: document.post_id,
                revision: document.revision,
                created_at: document.created_at,
                pod: pod_value,
                content: None, // Don't load content for list view
                timestamp_pod: timestamp_pod_value,
                user_id: document.user_id,
            });
        }

        posts_with_documents.push(PostWithDocuments {
            id: post.id,
            created_at: post.created_at,
            last_edited_at: post.last_edited_at,
            documents: documents_with_content,
        });
    }
    Ok(Json(posts_with_documents))
}

pub async fn get_documents(
    State(state): State<Arc<crate::AppState>>,
) -> Result<Json<Vec<DocumentMetadata>>, StatusCode> {
    let documents = state
        .db
        .get_all_documents()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut documents_metadata = Vec::new();
    for document in documents {
        let pod_value: serde_json::Value =
            serde_json::from_str(&document.pod).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let timestamp_pod_value = serde_json::from_str(&document.timestamp_pod)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        documents_metadata.push(DocumentMetadata {
            id: document.id,
            content_id: document.content_id,
            post_id: document.post_id,
            revision: document.revision,
            created_at: document.created_at,
            pod: pod_value,
            timestamp_pod: timestamp_pod_value,
            user_id: document.user_id,
        });
    }
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

    let documents = state
        .db
        .get_documents_by_post_id(post_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut documents_with_content = Vec::new();
    for document in documents {
        let content = state.storage.retrieve(&document.content_id).ok().flatten();
        let pod_value: serde_json::Value =
            serde_json::from_str(&document.pod).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let timestamp_pod_value = serde_json::from_str(&document.timestamp_pod)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        documents_with_content.push(DocumentWithContent {
            id: document.id,
            content_id: document.content_id,
            post_id: document.post_id,
            revision: document.revision,
            created_at: document.created_at,
            pod: pod_value,
            content,
            timestamp_pod: timestamp_pod_value,
            user_id: document.user_id,
        });
    }

    Ok(PostWithDocuments {
        id: post.id,
        created_at: post.created_at,
        last_edited_at: post.last_edited_at,
        documents: documents_with_content,
    })
}

async fn get_document_from_db(
    document_id: i64,
    state: Arc<crate::AppState>,
) -> Result<DocumentWithContent, StatusCode> {
    let document = state
        .db
        .get_document(document_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let content = state.storage.retrieve(&document.content_id).ok().flatten();
    let pod_value: serde_json::Value =
        serde_json::from_str(&document.pod).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let timestamp_pod_value = serde_json::from_str(&document.timestamp_pod)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(DocumentWithContent {
        id: document.id,
        content_id: document.content_id,
        post_id: document.post_id,
        revision: document.revision,
        created_at: document.created_at,
        pod: pod_value,
        content,
        timestamp_pod: timestamp_pod_value,
        user_id: document.user_id,
    })
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
) -> Result<Json<DocumentWithContent>, StatusCode> {
    let document = get_document_from_db(id, state).await?;
    Ok(Json(document))
}

pub async fn get_rendered_document_by_id(
    Path(id): Path<i64>,
    State(state): State<Arc<crate::AppState>>,
) -> Result<Json<DocumentWithContent>, StatusCode> {
    let mut document = get_document_from_db(id, state).await?;

    if document.content.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

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

    let content = &document.content.unwrap();

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
    document.content = Some(html_output.clone());

    Ok(Json(document))
}

#[axum::debug_handler]
pub async fn publish_document(
    State(state): State<Arc<crate::AppState>>,
    Json(payload): Json<PublishRequest>,
) -> Result<Json<DocumentWithContent>, StatusCode> {
    use pod_utils::{ValueExt, get_publish_verification_predicate};
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
    let use_mock = true;
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
    let content_hash = publish_verification_args[1].as_str().ok_or_else(|| {
        log::error!("publish_verification predicate missing content_hash argument");
        StatusCode::BAD_REQUEST
    })?;
    let identity_server_pk = publish_verification_args[2]
        .as_public_key()
        .ok_or_else(|| {
            log::error!("publish_verification predicate missing identity_server_pk argument");
            StatusCode::BAD_REQUEST
        })?;

    log::info!(
        "✓ Extracted public data: username={}, content_hash={}",
        username,
        content_hash
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

    // Extract post_id from main pod if present
    let post_id = payload.main_pod.get("post_id").and_then(|v| v.as_i64());
    log::debug!("Post ID: {:?}", post_id);

    // Store the main pod instead of a temporary pod
    let pod_json = serde_json::to_string(&payload.main_pod).map_err(|e| {
        log::error!("Failed to convert main pod to JSON: {e}");
        StatusCode::BAD_REQUEST
    })?;

    // Determine post_id: either create new post or use existing
    log::info!("Determining post ID");
    let final_post_id = match post_id {
        Some(id) => {
            log::info!("Using existing post ID: {id}");
            // Verify the post exists
            state
                .db
                .get_post(id)
                .map_err(|e| {
                    log::error!("Database error checking post {id}: {e}");
                    StatusCode::INTERNAL_SERVER_ERROR
                })?
                .ok_or_else(|| {
                    log::error!("Post {id} not found");
                    StatusCode::NOT_FOUND
                })?;
            log::info!("Post {id} exists");
            id
        }
        None => {
            log::info!("Creating new post");
            let id = state.db.create_post().map_err(|e| {
                log::error!("Failed to create new post: {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            log::info!("New post created with ID: {id}");
            id
        }
    };

    // Create document with timestamp pod in a single transaction
    log::info!("Creating document for post {final_post_id}");
    let document_id = state
        .db
        .create_document_with_timestamp_pod(
            &content_hash,
            final_post_id,
            &pod_json,
            &username,
            |post_id, doc_id| {
                log::info!("Creating timestamp pod for main pod (post_id: {post_id}, document_id: {doc_id})");
                let timestamp_pod = crate::pod::create_timestamp_pod_for_main_pod(
                    &payload.main_pod,
                    post_id,
                    doc_id,
                )?;
                serde_json::to_string(&timestamp_pod)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send+Sync>)
            },
        )
        .map_err(|e| {
            log::error!("Failed to create document with timestamp pod: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    log::info!("Document created with ID: {document_id}");

    let document = state
        .db
        .get_document(document_id)
        .map_err(|e| {
            log::error!("Failed to retrieve created document {document_id}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            log::error!("Document {document_id} not found after creation");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    log::info!("Retrieved created document");
    let pod_value: serde_json::Value = serde_json::from_str(&document.pod).map_err(|e| {
        log::error!("Failed to parse document pod JSON: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    log::info!("Document publish completed successfully using main pod verification");
    Ok(Json(DocumentWithContent {
        id: document.id,
        content_id: document.content_id,
        post_id: document.post_id,
        revision: document.revision,
        created_at: document.created_at,
        pod: pod_value,
        content: Some(payload.content),
        timestamp_pod: serde_json::from_str(&document.timestamp_pod).ok(),
        user_id: document.user_id,
    }))
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
