use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use pulldown_cmark::{Options, Parser, html};
use std::sync::Arc;

use pod2::backends::plonky2::primitives::ec::curve::Point;
use pod2::{
    frontend::SignedPod,
    middleware::TypedValue,
    middleware::{KEY_SIGNER, KEY_TYPE},
};

use crate::models::{
    DocumentMetadata, DocumentWithContent, PostWithDocuments, PublishRequest, ServerInfo,
    UserRegistration,
};

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

            let timestamp_pod_value = document
                .timestamp_pod
                .as_ref()
                .and_then(|tp| serde_json::from_str(tp).ok());

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

        let timestamp_pod_value = document
            .timestamp_pod
            .as_ref()
            .and_then(|tp| serde_json::from_str(tp).ok());

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

        let timestamp_pod_value = document
            .timestamp_pod
            .as_ref()
            .and_then(|tp| serde_json::from_str(tp).ok());

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

    let timestamp_pod_value = document
        .timestamp_pod
        .as_ref()
        .and_then(|tp| serde_json::from_str(tp).ok());

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
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_FOOTNOTES);

    let content = &document.content.unwrap();
    let parser = Parser::new_ext(content, options);
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);
    document.content = Some(html_output.clone());

    Ok(Json(document))
}

pub async fn publish_document(
    State(state): State<Arc<crate::AppState>>,
    Json(payload): Json<PublishRequest>,
) -> Result<Json<DocumentWithContent>, StatusCode> {
    log::info!("Starting document publish");
    log::debug!("Content length: {} bytes", payload.content.len());
    log::debug!("Post ID: {:?}", payload.post_id);

    // Validate pod type and structure
    log::info!("Validating signed pod structure");
    validate_signed_pod_json(&payload.signed_pod)?;
    log::info!("Pod validation successful");

    // Convert the json back into a POD
    let signed_pod: SignedPod =
        serde_json::from_value(payload.signed_pod.clone()).map_err(|e| {
            log::error!("Failed to deserialize signed pod for verification: {e}");
            StatusCode::BAD_REQUEST
        })?;
    validate_signed_pod(&signed_pod)?;

    let signer = signed_pod
        .get(KEY_SIGNER)
        .map(|v| v.typed())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let public_key = if let TypedValue::PublicKey(key) = signer {
        Ok(key)
    } else {
        Err(StatusCode::BAD_REQUEST)
    }?;

    // We will store the public key inside the database in JSON
    let public_key_json = serde_json::to_string(&public_key).map_err(|e| {
        log::error!("Failed to serialize public key: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Verify the user is registered and the public key matches
    log::info!("Verifying user registration");
    let user = state
        .db
        .get_user_by_public_key(&public_key_json)
        .map_err(|e| {
            log::error!("Database error checking user registration: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            log::error!("User with public key {public_key} not registered");
            StatusCode::UNAUTHORIZED
        })?;
    log::info!("User {} verified for publishing", user.user_id);

    // Store the content and get its hash
    log::info!("Storing content in content-addressed storage");
    let content_hash = state.storage.store(&payload.content).map_err(|e| {
        log::error!("Failed to store content: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    log::info!("Content stored successfully with hash: {content_hash}");

    // Convert signed pod to JSON string
    log::info!("Converting signed pod to JSON");
    let pod_json = serde_json::to_string(&payload.signed_pod).map_err(|e| {
        log::error!("Failed to convert pod to JSON: {e}");
        StatusCode::BAD_REQUEST
    })?;
    log::info!("Pod JSON conversion successful");

    // Determine post_id: either create new post or use existing
    log::info!("Determining post ID");
    let post_id = match payload.post_id {
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

    // Create document (revision) for the post
    log::info!("Creating document for post {post_id}");
    let document_id = state
        .db
        .create_document(&content_hash, post_id, &pod_json, &user.user_id)
        .map_err(|e| {
            log::error!("Failed to create document: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    log::info!("Document created with ID: {document_id}");

    // Create timestamp pod
    log::info!("Creating timestamp pod");
    let timestamp_pod = crate::pod::create_timestamp_pod(&signed_pod).map_err(|e| {
        log::error!("Failed to create timestamp pod: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    log::info!("Successfully created timestamp pod");

    let timestamp_pod_json =
        serde_json::to_string(&timestamp_pod).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .db
        .update_document_timestamp_pod(document_id, &timestamp_pod_json)
        .map_err(|e| {
            log::error!("Failed to update document timestamp pod: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    log::info!("Updated document with timestamp pod");

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

    let timestamp_pod_value = document
        .timestamp_pod
        .as_ref()
        .ok_or_else(|| {
            log::error!("Document missing required timestamp pod");
            StatusCode::INTERNAL_SERVER_ERROR
        })
        .and_then(|tp| {
            serde_json::from_str(tp).map_err(|e| {
                log::error!("Failed to parse timestamp pod JSON: {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })
        })?;

    log::info!("Document publish completed successfully");
    Ok(Json(DocumentWithContent {
        id: document.id,
        content_id: document.content_id,
        post_id: document.post_id,
        revision: document.revision,
        created_at: document.created_at,
        pod: pod_value,
        content: Some(payload.content),
        timestamp_pod: Some(timestamp_pod_value),
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

    let pk_string = serde_json::to_string(&payload.public_key).map_err(|e| {
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
