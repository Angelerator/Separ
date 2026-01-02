//! Separ Identity - Multi-provider identity sync and authentication
//!
//! This crate provides pluggable identity provider implementations for:
//! - Azure AD / Entra ID
//! - Okta
//! - Google Workspace
//! - Generic OIDC
//! - LDAP (optional)
//!
//! # Architecture
//!
//! The identity system is built around two core traits:
//! - `IdentitySync`: For syncing users, groups, and apps from external providers
//! - `IdentityAuth`: For authenticating tokens from external providers
//!
//! Each provider implements these traits, and the `ProviderRegistry` manages
//! multiple providers per tenant.

pub mod providers;
pub mod registry;
pub mod sync;

#[cfg(test)]
mod tests;

// Re-export provider implementations
#[cfg(feature = "azure")]
pub use providers::azure::AzureAdProvider;

#[cfg(feature = "okta")]
pub use providers::okta::OktaProvider;

#[cfg(feature = "google")]
pub use providers::google::GoogleProvider;

#[cfg(feature = "oidc")]
pub use providers::oidc::GenericOidcProvider;

#[cfg(feature = "ldap")]
pub use providers::ldap::LdapProvider;

// Re-export core types
pub use separ_core::identity::*;

// Re-export registry and sync
pub use registry::ProviderRegistry;
pub use sync::SyncOrchestrator;
