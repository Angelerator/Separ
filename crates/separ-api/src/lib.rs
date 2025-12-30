//! Separ API - HTTP API layer for the authorization platform

pub mod dto;
pub mod handlers;
pub mod middleware;
pub mod routes;
pub mod state;

pub use routes::create_router;
pub use routes::create_router_with_state;
pub use state::AppState;
