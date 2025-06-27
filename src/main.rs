mod db;
mod handlers;
mod models;
mod pod;
mod storage;

use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

pub struct AppState {
    pub db: Arc<db::Database>,
    pub storage: Arc<storage::ContentAddressedStorage>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    log::info!("Starting PodNet Server...");

    log::info!("Initializing database...");
    let db = Arc::new(db::Database::new("app.db").await?);
    log::info!("Database initialized successfully");

    log::info!("Initializing content storage...");
    let storage = Arc::new(storage::ContentAddressedStorage::new("content")?);
    log::info!("Content storage initialized successfully");

    let state = Arc::new(AppState { db, storage });

    log::info!("Setting up routes...");
    let app = Router::new()
        .route("/", get(handlers::root))
        // Post routes
        .route("/posts", get(handlers::get_posts))
        .route("/posts/:id", get(handlers::get_post_by_id))
        // Document routes
        .route("/documents", get(handlers::get_documents))
        .route("/documents/:id", get(handlers::get_document_by_id))
        .route(
            "/documents/:id/render",
            get(handlers::get_rendered_document_by_id),
        )
        // Publishing route
        .route("/publish", post(handlers::publish_document))
        // User registration
        .route("/register", post(handlers::register_user))
        // Identity server routes
        .route(
            "/identity/register",
            post(handlers::register_identity_server),
        )
        .layer(CorsLayer::permissive())
        .with_state(state);

    log::info!("Binding to 0.0.0.0:3000...");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    log::info!("Server running on http://localhost:3000");
    log::info!("Available endpoints:");
    log::info!("  GET  /                       - Root endpoint");
    log::info!("  GET  /posts                  - List all posts");
    log::info!("  GET  /posts/:id              - Get post with documents");
    log::info!("  GET  /documents              - List all documents");
    log::info!("  GET  /documents/:id          - Get specific document");
    log::info!("  GET  /documents/:id/render   - Get rendered document HTML");
    log::info!("  POST /publish                - Publish new document");
    log::info!("  POST /register               - Register user with public key");
    log::info!("  POST /identity/register      - Register identity server");

    axum::serve(listener, app).await?;
    Ok(())
}
