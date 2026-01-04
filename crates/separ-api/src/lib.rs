//! Separ API - HTTP API layer for the authorization platform

#![allow(clippy::type_complexity)]
#![allow(unused_variables)]

pub mod dto;
pub mod handlers;
pub mod middleware;
pub mod password;
pub mod routes;
pub mod state;

pub use routes::create_router;
pub use routes::create_router_with_state;
pub use state::AppState;
