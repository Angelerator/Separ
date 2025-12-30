//! Separ Authorization Platform - Main Server

use anyhow::{Context, Result};
use axum::Router;
use std::net::SocketAddr;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod config;

use config::Settings;
use separ_api::AppState;
use separ_db::{create_pool, DatabaseConfig};
use separ_oauth::JwtService;
use separ_spicedb::{SpiceDbAuthorizationService, SpiceDbClient, SpiceDbConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    // Initialize tracing
    init_tracing();

    // Load configuration
    let settings = Settings::load().context("Failed to load configuration")?;

    info!(
        "Starting Separ Authorization Platform v{}",
        env!("CARGO_PKG_VERSION")
    );
    info!("Configuration loaded successfully");

    // Initialize services
    let state = initialize_services(&settings).await?;

    // Create API router with state
    let app = create_app(state);

    // Start server
    let addr: SocketAddr = format!("{}:{}", settings.server.host, settings.server.port)
        .parse()
        .context("Invalid server address")?;

    info!("Server listening on http://{}", addr);
    info!("Health check: http://{}/health", addr);
    info!("API docs: http://{}/api/v1", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,separ=debug,tower_http=debug"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_target(true))
        .init();
}

async fn initialize_services(settings: &Settings) -> Result<AppState> {
    // Initialize database connection pool
    info!("Connecting to PostgreSQL...");
    let db_config = DatabaseConfig {
        url: settings.database.url.clone(),
        max_connections: settings.database.max_connections,
        min_connections: 2,
        acquire_timeout_secs: 30,
        idle_timeout_secs: 600,
    };

    let db_pool = match create_pool(&db_config).await {
        Ok(pool) => {
            info!("PostgreSQL connection established");
            pool
        }
        Err(e) => {
            warn!("Failed to connect to PostgreSQL: {}. Using fallback mode.", e);
            // For development, we can continue without a database
            // In production, you'd want to fail here
            return Err(e.into());
        }
    };

    // Initialize SpiceDB client
    info!("Connecting to SpiceDB at {}...", settings.spicedb.endpoint);
    let spicedb_config = SpiceDbConfig {
        endpoint: settings.spicedb.endpoint.clone(),
        token: settings.spicedb.token.clone(),
        use_tls: false,
        connect_timeout_ms: 5000,
        request_timeout_ms: 30000,
    };

    let spicedb_client = match SpiceDbClient::new(spicedb_config).await {
        Ok(client) => {
            info!("SpiceDB connection established");
            client
        }
        Err(e) => {
            error!("Failed to connect to SpiceDB: {}", e);
            return Err(e.into());
        }
    };

    // Create authorization service
    let auth_service = SpiceDbAuthorizationService::new(spicedb_client);

    // Initialize schema in SpiceDB
    match auth_service.initialize_schema().await {
        Ok(()) => info!("SpiceDB schema initialized"),
        Err(e) => {
            warn!("Failed to initialize SpiceDB schema: {}. Schema may already exist.", e);
            // Don't fail - schema might already exist
        }
    }

    // Create JWT service
    let jwt_service = JwtService::new(
        settings.jwt.secret.clone(),
        settings.jwt.issuer.clone(),
        settings.jwt.access_token_expiry_secs,
        settings.jwt.refresh_token_expiry_secs,
    );

    // Create application state
    let state = AppState::new(db_pool, auth_service, jwt_service);

    info!("All services initialized successfully");
    Ok(state)
}

fn create_app(state: AppState) -> Router {
    // Create router with state
    let app = separ_api::create_router_with_state(state);

    // Add middleware
    app.layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
}
