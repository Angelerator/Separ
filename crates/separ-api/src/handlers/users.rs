//! User management handlers (placeholder)

use axum::{extract::Path, http::StatusCode};

pub async fn create_user() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn get_user(Path(_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn list_users() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn update_user(Path(_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn delete_user(Path(_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn get_current_user() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

