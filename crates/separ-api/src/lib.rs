//! Separ API - HTTP API layer for the authorization platform
//!
//! Security features:
//! - Input validation and sanitization
//! - Security headers (HSTS, CSP, X-Frame-Options)
//! - Rate limiting (IP-based and per-API-key)
//! - Request size limits
//! - Audit logging

#![allow(clippy::type_complexity)]
#![allow(unused_variables)]

pub mod dto;
pub mod handlers;
pub mod middleware;
pub mod password;
pub mod routes;
pub mod state;
pub mod validation;

pub use routes::create_router;
pub use routes::create_router_with_state;
pub use state::AppState;
