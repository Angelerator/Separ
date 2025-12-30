//! OAuth handlers (placeholder)

use axum::{extract::Path, http::StatusCode};

pub async fn list_providers() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn create_provider() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn get_provider(Path(_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn update_provider(Path(_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn delete_provider(Path(_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn oauth_authorize(Path(_provider_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn oauth_callback(Path(_provider_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn refresh_token() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

