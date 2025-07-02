use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use std::sync::Arc;
use pod_utils::ValueExt;
use podnet_models::{IdentityServerRegistration, ServerInfo, UserRegistration};

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