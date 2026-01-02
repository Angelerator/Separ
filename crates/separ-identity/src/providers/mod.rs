//! Identity provider implementations

#[cfg(feature = "azure")]
pub mod azure;

#[cfg(feature = "okta")]
pub mod okta;

#[cfg(feature = "google")]
pub mod google;

#[cfg(feature = "oidc")]
pub mod oidc;

#[cfg(feature = "ldap")]
pub mod ldap;

mod common;

pub use common::*;
