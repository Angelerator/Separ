//! Workspace management handlers (placeholder)

use axum::{extract::Path, http::StatusCode, Json};
use crate::dto::ApiResponse;

pub async fn create_workspace() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn get_workspace(Path(_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn list_workspaces() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn update_workspace(Path(_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn delete_workspace(Path(_id): Path<String>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

