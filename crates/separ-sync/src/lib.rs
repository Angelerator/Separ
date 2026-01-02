//! Separ Sync - Tenant synchronization service (SCIM, Webhooks)

#![allow(dead_code)]
#![allow(unused_variables)]

pub mod scim;
pub mod service;
pub mod webhook;

pub use scim::*;
pub use service::*;
pub use webhook::*;
