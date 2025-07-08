mod config;
mod db;
mod handlers;
mod pod;
mod storage;

use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub struct AppState {
    pub db: Arc<db::Database>,
    pub storage: Arc<storage::ContentAddressedStorage>,
    pub config: config::ServerConfig,
    pub pod_config: pod::PodConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "podnet_server=debug,tower_http=debug,axum::routing=trace".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting PodNet Server...");

    // Load configuration
    let config = config::ServerConfig::load();
    tracing::info!("Configuration loaded: mock_proofs = {}", config.mock_proofs);

    tracing::info!("Initializing database...");
    let db = Arc::new(db::Database::new("app.db").await?);
    tracing::info!("Database initialized successfully");

    tracing::info!("Initializing content storage...");
    let storage = Arc::new(storage::ContentAddressedStorage::new("content")?);
    tracing::info!("Content storage initialized successfully");

    let pod_config = pod::PodConfig::new(config.mock_proofs);
    let state = Arc::new(AppState {
        db,
        storage,
        config,
        pod_config,
    });

    tracing::info!("Setting up routes...");
    let app = Router::new()
        .route("/", get(handlers::root))
        // Post routes
        .route("/posts", get(handlers::get_posts))
        .route("/posts/:id", get(handlers::get_post_by_id))
        // Document routes
        .route("/documents", get(handlers::get_documents))
        .route("/documents/:id", get(handlers::get_document_by_id))
        .route(
            "/documents/:id/replies",
            get(handlers::get_document_replies),
        )
        // Publishing route
        .route("/publish", post(handlers::publish_document))
        // Identity server routes
        .route(
            "/identity/challenge",
            post(handlers::request_identity_challenge),
        )
        .route(
            "/identity/register",
            post(handlers::register_identity_server),
        )
        // Upvote routes
        .route("/documents/:id/upvote", post(handlers::upvote_document))
        .layer(CorsLayer::permissive())
        .with_state(state);

    tracing::info!("Binding to 0.0.0.0:3000...");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!("Server running on http://localhost:3000");
    tracing::info!("Available endpoints:");
    tracing::info!("  GET  /                       - Root endpoint");
    tracing::info!("  GET  /posts                  - List all posts");
    tracing::info!("  GET  /posts/:id              - Get post with documents");
    tracing::info!("  GET  /documents              - List all documents");
    tracing::info!("  GET  /documents/:id          - Get specific document");
    tracing::info!("  GET  /documents/:id/replies  - Get replies to a document");
    tracing::info!("  POST /publish                - Publish new document");
    tracing::info!("  POST /identity/challenge     - Request challenge for identity server");
    tracing::info!("  POST /identity/register      - Register identity server");
    tracing::info!("  POST /documents/:id/upvote   - Upvote a document");

    axum::serve(listener, app).await?;
    Ok(())
}
