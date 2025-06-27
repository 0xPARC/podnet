use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use pod2::backends::plonky2::{
    primitives::ec::{curve::Point as PublicKey, schnorr::SecretKey},
    signedpod::Signer,
};
use pod2::frontend::{SignedPod, SignedPodBuilder};
use pod2::middleware::Params;
use pod_utils::ValueExt;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::fs;
use tower_http::cors::CorsLayer;

// Identity server state
pub struct IdentityServerState {
    pub server_id: String,
    pub server_secret_key: Arc<SecretKey>,
    pub server_public_key: PublicKey,
    // Store pending challenges: challenge -> (username, user_public_key)
    pub pending_challenges: Arc<Mutex<HashMap<String, (String, PublicKey)>>>,
}

impl Clone for IdentityServerState {
    fn clone(&self) -> Self {
        Self {
            server_id: self.server_id.clone(),
            server_secret_key: Arc::clone(&self.server_secret_key),
            server_public_key: self.server_public_key,
            pending_challenges: Arc::clone(&self.pending_challenges),
        }
    }
}

// Request/Response models
#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub username: String,
    pub user_public_key: PublicKey,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub server_id: String,
    pub server_public_key: PublicKey,
}

#[derive(Debug, Deserialize)]
pub struct IdentityRequest {
    /// SignedPod containing:
    /// - challenge: String (challenge sent by identity server)
    /// - username: String (requested username)
    /// - _signer: Point (user's public key, automatically added by SignedPod)
    pub challenge_response: SignedPod,
}

#[derive(Debug, Serialize)]
pub struct IdentityResponse {
    /// SignedPod containing:
    /// - username: String (user's chosen username)
    /// - user_public_key: Point (user's public key)
    /// - identity_server_id: String (ID of this identity server)
    /// - _signer: Point (identity server's public key, automatically added by SignedPod)
    pub identity_pod: SignedPod,
}

#[derive(Debug, Serialize)]
pub struct ServerInfo {
    pub server_id: String,
    pub public_key: PublicKey,
}

// Registration models for registering with podnet-server
#[derive(Debug, Serialize)]
pub struct RegistrationRequest {
    pub challenge_response: SignedPod,
}

#[derive(Debug, Deserialize)]
pub struct PodNetServerInfo {
    pub public_key: PublicKey,
}

// Keypair persistence models
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityServerKeypair {
    pub server_id: String,
    pub secret_key: String, // hex encoded
    pub public_key: PublicKey,
    pub created_at: String,
}

// Root endpoint
async fn root(State(state): State<IdentityServerState>) -> Json<ServerInfo> {
    Json(ServerInfo {
        server_id: state.server_id.clone(),
        public_key: state.server_public_key,
    })
}

// Step 1: Client requests a challenge
async fn request_challenge(
    State(state): State<IdentityServerState>,
    Json(payload): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, StatusCode> {
    log::info!("Challenge requested for username: {}", payload.username);

    // Generate a random challenge
    let challenge: String = (0..32)
        .map(|_| rand::thread_rng().gen::<u8>())
        .map(|b| format!("{:02x}", b))
        .collect();

    // Store the challenge with associated user info
    {
        let mut pending = state.pending_challenges.lock().unwrap();
        pending.insert(
            challenge.clone(),
            (payload.username.clone(), payload.user_public_key),
        );
    }

    log::info!(
        "Generated challenge for {}: {}",
        payload.username,
        challenge
    );

    Ok(Json(ChallengeResponse {
        challenge,
        server_id: state.server_id.clone(),
        server_public_key: state.server_public_key,
    }))
}

// Step 2: Client submits signed challenge response, gets identity pod
async fn issue_identity(
    State(state): State<IdentityServerState>,
    Json(payload): Json<IdentityRequest>,
) -> Result<Json<IdentityResponse>, StatusCode> {
    // Verify the challenge response pod
    payload.challenge_response.verify().map_err(|e| {
        log::error!("Failed to verify challenge response pod: {e}");
        StatusCode::BAD_REQUEST
    })?;

    // Extract challenge and username from the pod using ValueExt trait
    let challenge = payload
        .challenge_response
        .get("challenge")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            log::error!("Challenge response pod missing challenge");
            StatusCode::BAD_REQUEST
        })?;

    let username = payload
        .challenge_response
        .get("username")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            log::error!("Challenge response pod missing username");
            StatusCode::BAD_REQUEST
        })?;

    // Get the signer (user's public key) using ValueExt trait
    let user_public_key = payload
        .challenge_response
        .get("_signer")
        .and_then(|v| v.as_public_key())
        .copied()
        .ok_or_else(|| {
            log::error!("Challenge response pod missing signer");
            StatusCode::BAD_REQUEST
        })?;

    // Verify the challenge exists and matches
    let expected_user_info = {
        let mut pending = state.pending_challenges.lock().unwrap();
        pending.remove(&challenge).ok_or_else(|| {
            log::error!("Invalid or expired challenge: {}", challenge);
            StatusCode::BAD_REQUEST
        })?
    };

    // Verify the username and public key match what was requested
    if expected_user_info.0 != username {
        log::error!(
            "Username mismatch: expected {}, got {}",
            expected_user_info.0,
            username
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Compare public keys directly
    if expected_user_info.1 != user_public_key {
        log::error!("Public key mismatch for user {}", username);
        return Err(StatusCode::BAD_REQUEST);
    }

    log::info!("Challenge verification successful for user: {}", username);

    // Create identity pod using SignedPodBuilder
    let params = Params::default();
    let mut identity_builder = SignedPodBuilder::new(&params);

    identity_builder.insert("username", username.as_str());
    identity_builder.insert("user_public_key", user_public_key);
    identity_builder.insert("identity_server_id", state.server_id.as_str());
    identity_builder.insert("issued_at", chrono::Utc::now().to_rfc3339().as_str());

    // Sign the identity pod with the identity server's key
    let mut server_signer = Signer(SecretKey(state.server_secret_key.0.clone()));
    let identity_pod = identity_builder.sign(&mut server_signer).map_err(|e| {
        log::error!("Failed to sign identity pod: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    log::info!("Identity pod issued for user: {}", username);

    Ok(Json(IdentityResponse { identity_pod }))
}

// Register this identity server with the podnet-server
async fn register_with_podnet_server(
    server_id: &str,
    secret_key: &SecretKey,
    podnet_server_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Registering with podnet-server at: {}", podnet_server_url);

    // First, generate a mock challenge (in a real implementation, this would come from the podnet-server)
    let challenge = format!("challenge_{}", chrono::Utc::now().timestamp());
    log::info!("Using challenge: {}", challenge);

    // Create challenge response pod
    let params = Params::default();
    let mut challenge_builder = SignedPodBuilder::new(&params);

    challenge_builder.insert("challenge", challenge.as_str());
    challenge_builder.insert("server_id", server_id);

    // Sign the challenge response
    let mut server_signer = Signer(SecretKey(secret_key.0.clone()));
    let challenge_response_pod = challenge_builder.sign(&mut server_signer)?;

    let registration_request = RegistrationRequest {
        challenge_response: challenge_response_pod,
    };

    // Submit registration to podnet-server
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/identity/register", podnet_server_url))
        .header("Content-Type", "application/json")
        .json(&registration_request)
        .send()
        .await?;

    if response.status().is_success() {
        let server_info: PodNetServerInfo = response.json().await?;
        log::info!("✓ Successfully registered with podnet-server!");
        log::info!("PodNet Server Public Key: {}", server_info.public_key);
        Ok(())
    } else {
        let status = response.status();
        let error_text = response.text().await?;

        if status == reqwest::StatusCode::CONFLICT {
            log::info!("✓ Identity server already registered with podnet-server");
            Ok(())
        } else {
            log::error!("Failed to register with podnet-server. Status: {}", status);
            log::error!("Error: {}", error_text);
            Err(format!("Registration failed: {} - {}", status, error_text).into())
        }
    }
}

// Keypair management functions
fn load_or_create_keypair(keypair_file: &str) -> anyhow::Result<(String, SecretKey, PublicKey)> {
    let server_id = "strawman-identity-server".to_string();
    
    if fs::metadata(keypair_file).is_ok() {
        log::info!("Loading existing keypair from: {}", keypair_file);
        let keypair_json = fs::read_to_string(keypair_file)?;
        let keypair: IdentityServerKeypair = serde_json::from_str(&keypair_json)?;
        
        // Verify server_id matches
        if keypair.server_id != server_id {
            return Err(anyhow::anyhow!(
                "Keypair server_id mismatch: expected {}, found {}",
                server_id,
                keypair.server_id
            ));
        }
        
        // Decode secret key
        let secret_key_bytes = hex::decode(&keypair.secret_key)?;
        let secret_key_bigint = num_bigint::BigUint::from_bytes_le(&secret_key_bytes);
        let secret_key = SecretKey(secret_key_bigint);
        
        // Verify public key matches
        let expected_public_key = secret_key.public_key();
        if expected_public_key != keypair.public_key {
            return Err(anyhow::anyhow!("Keypair public key mismatch"));
        }
        
        log::info!("✓ Keypair loaded successfully");
        log::info!("Created at: {}", keypair.created_at);
        
        Ok((server_id, secret_key, keypair.public_key))
    } else {
        log::info!("Creating new keypair and saving to: {}", keypair_file);
        
        // Generate new keypair
        let secret_key = SecretKey::new_rand();
        let public_key = secret_key.public_key();
        
        // Save keypair to file
        let keypair = IdentityServerKeypair {
            server_id: server_id.clone(),
            secret_key: hex::encode(secret_key.0.to_bytes_le()),
            public_key,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        
        let keypair_json = serde_json::to_string_pretty(&keypair)?;
        fs::write(keypair_file, keypair_json)?;
        
        log::info!("✓ New keypair created and saved");
        
        Ok((server_id, secret_key, public_key))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    log::info!("Starting PodNet Identity Server (Strawman Implementation)...");

    // Load or create server keypair
    let keypair_file = std::env::var("IDENTITY_KEYPAIR_FILE")
        .unwrap_or_else(|_| "identity-server-keypair.json".to_string());
    
    let (server_id, server_secret_key, server_public_key) = load_or_create_keypair(&keypair_file)?;

    log::info!("Identity Server ID: {}", server_id);
    log::info!("Server Public Key: {}", server_public_key);

    // Attempt to register with podnet-server
    let podnet_server_url =
        std::env::var("PODNET_SERVER_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

    log::info!("Attempting to register with podnet-server...");
    if let Err(e) =
        register_with_podnet_server(&server_id, &server_secret_key, &podnet_server_url).await
    {
        log::warn!("Failed to register with podnet-server: {}", e);
        log::warn!("Identity server will continue running, but won't be registered.");
        log::warn!("Issued identity pods may not be accepted by podnet-server.");
    }

    let state = IdentityServerState {
        server_id: server_id.clone(),
        server_secret_key: Arc::new(server_secret_key),
        server_public_key,
        pending_challenges: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/", get(root))
        .route("/challenge", post(request_challenge))
        .route("/identity", post(issue_identity))
        .layer(CorsLayer::permissive())
        .with_state(state);

    log::info!("Binding to 0.0.0.0:3001...");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await?;
    log::info!("Identity server running on http://localhost:3001");
    log::info!("Available endpoints:");
    log::info!("  GET  /           - Server info");
    log::info!("  POST /challenge  - Request challenge for identity");
    log::info!("  POST /identity   - Submit challenge response, get identity pod");

    axum::serve(listener, app).await?;
    Ok(())
}
