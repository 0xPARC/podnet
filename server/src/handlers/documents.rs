use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use pod_utils::ValueExt;
use podnet_models::{
    Document, DocumentMetadata, PublishRequest, get_publish_verification_predicate,
};
use pulldown_cmark::{Event, Options, Parser, html};
use std::sync::Arc;

pub async fn get_documents(
    State(state): State<Arc<crate::AppState>>,
) -> Result<Json<Vec<DocumentMetadata>>, StatusCode> {
    let documents_metadata = state
        .db
        .get_all_documents_metadata()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(documents_metadata))
}

async fn get_document_from_db(
    document_id: i64,
    state: Arc<crate::AppState>,
) -> Result<Document, StatusCode> {
    let document = state
        .db
        .get_document(document_id, &state.storage)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(document)
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

pub async fn publish_document(
    State(state): State<Arc<crate::AppState>>,
    Json(payload): Json<PublishRequest>,
) -> Result<Json<Document>, StatusCode> {

    log::info!("Starting document publish with main pod verification");
    log::debug!("Content length: {} bytes", payload.content.len());

    let (_vd_set, _prover) = state.pod_config.get_prover_setup()?;

    // Verify main pod proof
    log::info!("Verifying main pod proof");
    payload.main_pod.pod.verify().map_err(|e| {
        log::error!("Failed to verify main pod: {e}");
        StatusCode::UNAUTHORIZED
    })?;
    log::info!("✓ Main pod proof verified");

    // Extract public data using the macro
    log::info!("Extracting public data from main pod");
    let (uploader_username, content_hash, identity_server_pk, post_id, _tags) = podnet_models::extract_mainpod_args!(
        &payload.main_pod,
        get_publish_verification_predicate(),
        "publish_verification",
        username: as_str,
        content_hash: as_hash,
        identity_server_pk: as_public_key,
        post_id: as_i64,
        tags: as_set
    ).map_err(|e| {
        log::error!("Failed to extract publish verification arguments: {e}");
        StatusCode::BAD_REQUEST
    })?;

    log::info!(
        "✓ Extracted public data: uploader_username={uploader_username}, content_hash={content_hash}, post_id={post_id}"
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
            "Content hash mismatch: stored={stored_content_hash} vs main_pod={content_hash}"
        );
        return Err(StatusCode::BAD_REQUEST);
    }
    log::info!("✓ Content hash verified");

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

    // Validate reply_to if provided
    if let Some(reply_to_id) = payload.reply_to {
        log::info!("Validating reply_to document ID: {reply_to_id}");
        // Verify the document being replied to exists
        state
            .db
            .get_document_metadata(reply_to_id)
            .map_err(|e| {
                log::error!("Database error checking reply_to document {reply_to_id}: {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .ok_or_else(|| {
                log::error!("Reply_to document {reply_to_id} not found");
                StatusCode::NOT_FOUND
            })?;
        log::info!("Reply_to document {reply_to_id} exists");
    }

    // Create document with timestamp pod in a single transaction
    log::info!("Creating document for post {final_post_id}");
    let document = state
        .db
        .create_document(
            &content_hash,
            final_post_id,
            &payload.main_pod,
            uploader_username,
            &payload.tags,
            &payload.authors,
            payload.reply_to,
            &state.storage,
        )
        .map_err(|e| {
            log::error!("Failed to create document: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    log::info!("Document created with ID: {:?}", document.metadata.id);

    // Spawn background task to generate base case upvote count pod
    if let Some(document_id) = document.metadata.id {
        let state_clone = state.clone();
        let content_hash = document.metadata.content_id;

        tokio::spawn(async move {
            if let Err(e) = super::upvotes::generate_base_case_upvote_pod(
                state_clone,
                document_id,
                &content_hash,
            )
            .await
            {
                log::error!(
                    "Failed to generate base case upvote count pod for document {document_id}: {e}"
                );
            }
        });
    }

    log::info!("Document publish completed successfully using main pod verification");
    Ok(Json(document))
}

pub async fn get_document_replies(
    Path(id): Path<i64>,
    State(state): State<Arc<crate::AppState>>,
) -> Result<Json<Vec<DocumentMetadata>>, StatusCode> {
    let raw_replies = state
        .db
        .get_replies_to_document(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut replies = Vec::new();
    for raw_reply in raw_replies {
        let reply_metadata = state
            .db
            .raw_document_to_metadata(raw_reply)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        replies.push(reply_metadata);
    }

    Ok(Json(replies))
}
