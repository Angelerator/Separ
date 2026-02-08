//! Error types for the Separ platform

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SeparError {
    #[error("Entity not found: {entity_type} with id {id}")]
    NotFound { entity_type: String, id: String },

    #[error("Permission denied: {action} on {resource}")]
    PermissionDenied { action: String, resource: String },

    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    #[error("Tenant error: {message}")]
    TenantError { message: String },

    #[error("Authentication error: {message}")]
    AuthError { message: String },

    #[error("OAuth error: {message}")]
    OAuthError { message: String },

    #[error("SpiceDB error: {message}")]
    SpiceDbError { message: String },

    #[error("Database error: {message}")]
    DatabaseError { message: String },

    #[error("Sync error: {message}")]
    SyncError { message: String },

    #[error("Configuration error: {message}")]
    ConfigError { message: String },

    #[error("JWT error: {message}")]
    JwtError { message: String },

    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl SeparError {
    pub fn not_found(entity_type: impl Into<String>, id: impl Into<String>) -> Self {
        Self::NotFound {
            entity_type: entity_type.into(),
            id: id.into(),
        }
    }

    pub fn permission_denied(action: impl Into<String>, resource: impl Into<String>) -> Self {
        Self::PermissionDenied {
            action: action.into(),
            resource: resource.into(),
        }
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }

    pub fn auth_error(message: impl Into<String>) -> Self {
        Self::AuthError {
            message: message.into(),
        }
    }

    pub fn spicedb_error(message: impl Into<String>) -> Self {
        Self::SpiceDbError {
            message: message.into(),
        }
    }

    pub fn database_error(message: impl Into<String>) -> Self {
        Self::DatabaseError {
            message: message.into(),
        }
    }

    pub fn jwt_error(message: impl Into<String>) -> Self {
        Self::JwtError {
            message: message.into(),
        }
    }

    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, SeparError>;
