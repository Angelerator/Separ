//! Separ Proxy - Authentication Proxy for PostgreSQL Wire Protocol
//!
//! This crate provides a transparent proxy that sits in front of PostgreSQL-compatible
//! databases (like Tavana) and handles authentication using multiple identity providers.
//!
//! # Features
//!
//! - PostgreSQL wire protocol handling
//! - Multi-provider JWT token validation
//! - API key authentication
//! - Service account token validation
//! - mTLS certificate validation (optional)
//! - Connection pooling and management
//!
//! # Architecture
//!
//! ```text
//! ┌─────────┐     ┌─────────────┐     ┌─────────┐
//! │ Client  │────▶│ Separ Proxy │────▶│  Tavana │
//! │ (psql)  │◀────│             │◀────│         │
//! └─────────┘     └─────────────┘     └─────────┘
//!                        │
//!                        ▼
//!                 ┌─────────────┐
//!                 │    Separ    │
//!                 │  (AuthZ)    │
//!                 └─────────────┘
//! ```

#![allow(dead_code)]
#![allow(unused_variables)]

pub mod auth;
pub mod config;
pub mod connection;
pub mod protocol;
pub mod proxy;

#[cfg(test)]
mod tests;

pub use config::ProxyConfig;
pub use proxy::SeparProxy;
