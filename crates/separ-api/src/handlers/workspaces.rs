//! Workspace management handlers
//!
//! Implements workspace-first model:
//! - Users own workspaces directly (not via tenants)
//! - Personal workspaces are created at registration
//! - Team workspaces can be created by any user
//! - Workspace members can be invited

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::state::AppState;

// ============================================================================
// DTOs
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateWorkspaceRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_workspace_type")]
    pub workspace_type: String,
}

fn default_workspace_type() -> String {
    "team".to_string()
}

#[derive(Debug, Deserialize)]
pub struct UpdateWorkspaceRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListWorkspacesQuery {
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    20
}

#[derive(Debug, Serialize)]
pub struct WorkspaceResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub workspace_type: String,
    pub owner_user_id: Option<String>,
    pub tenant_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub total: u64,
    pub items: Vec<T>,
    pub offset: u32,
    pub limit: u32,
    pub has_more: bool,
}

#[derive(Debug, Deserialize)]
pub struct InviteMemberRequest {
    pub user_id: String,
    #[serde(default = "default_member_role")]
    pub role: String,
}

fn default_member_role() -> String {
    "member".to_string()
}

#[derive(Debug, Serialize)]
pub struct WorkspaceMemberResponse {
    pub user_id: String,
    pub role: String,
    pub joined_at: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// Create a new workspace
/// 
/// POST /api/v1/workspaces
/// 
/// Creates a new workspace owned by the authenticated user.
/// Requires: user_id header (from auth middleware)
pub async fn create_workspace(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(request): Json<CreateWorkspaceRequest>,
) -> Result<(StatusCode, Json<ApiResponse<WorkspaceResponse>>), (StatusCode, Json<ApiResponse<()>>)> {
    // Get authenticated user from header
    let user_id = headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "UNAUTHORIZED".to_string(),
                        message: "Authentication required".to_string(),
                    }),
                }),
            )
        })?;

    let workspace_id = uuid::Uuid::new_v4();
    let workspace_id_str = workspace_id.to_string();
    
    // Generate slug from name
    let slug = request.name
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ')
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-");
    
    let slug = format!("{}-{}", slug, &workspace_id_str[..8]);

    info!(
        user_id = %user_id,
        workspace_name = %request.name,
        "Creating new workspace"
    );

    // Validate workspace_type
    let workspace_type = match request.workspace_type.as_str() {
        "personal" | "team" | "organization" => request.workspace_type.clone(),
        _ => "team".to_string(),
    };

    // Insert workspace
    let result = sqlx::query(
        r#"
        INSERT INTO workspaces (id, tenant_id, owner_user_id, name, slug, description, workspace_type, created_at, updated_at)
        VALUES ($1, NULL, $2::uuid, $3, $4, $5, $6, NOW(), NOW())
        "#,
    )
    .bind(workspace_id)
    .bind(uuid::Uuid::parse_str(user_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "INVALID_USER_ID".to_string(),
                    message: "Invalid user ID format".to_string(),
                }),
            }),
        )
    })?)
    .bind(&request.name)
    .bind(&slug)
    .bind(&request.description)
    .bind(&workspace_type)
    .execute(&state.db_pool)
    .await;

    if let Err(e) = result {
        warn!("Failed to create workspace: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "CREATE_FAILED".to_string(),
                    message: format!("Failed to create workspace: {}", e),
                }),
            }),
        ));
    }

    // Add user as owner in workspace_members
    let _ = sqlx::query(
        r#"
        INSERT INTO workspace_members (workspace_id, user_id, role, joined_at)
        VALUES ($1, $2::uuid, 'owner', NOW())
        "#,
    )
    .bind(workspace_id)
    .bind(uuid::Uuid::parse_str(user_id).unwrap())
    .execute(&state.db_pool)
    .await;

    // Create ownership in SpiceDB
    let _ = state
        .auth_service
        .client()
        .write_relationship("workspace", &workspace_id_str, "owner", "user", user_id)
        .await;

    info!(
        workspace_id = %workspace_id_str,
        "Workspace created successfully"
    );

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse {
            success: true,
            data: Some(WorkspaceResponse {
                id: workspace_id_str,
                name: request.name,
                slug,
                description: request.description,
                workspace_type,
                owner_user_id: Some(user_id.to_string()),
                tenant_id: None,
                created_at: chrono::Utc::now().to_rfc3339(),
                updated_at: chrono::Utc::now().to_rfc3339(),
            }),
            error: None,
        }),
    ))
}

/// Get a workspace by ID
/// 
/// GET /api/v1/workspaces/:id
pub async fn get_workspace(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<WorkspaceResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let workspace_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "INVALID_ID".to_string(),
                    message: "Invalid workspace ID format".to_string(),
                }),
            }),
        )
    })?;

    let workspace: Option<(uuid::Uuid, String, String, Option<String>, String, Option<uuid::Uuid>, Option<uuid::Uuid>, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> = 
        sqlx::query_as(
            r#"
            SELECT id, name, slug, description, workspace_type, owner_user_id, tenant_id, created_at, updated_at
            FROM workspaces
            WHERE id = $1
            "#,
        )
        .bind(workspace_id)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "FETCH_FAILED".to_string(),
                        message: e.to_string(),
                    }),
                }),
            )
        })?;

    match workspace {
        Some((id, name, slug, description, workspace_type, owner_user_id, tenant_id, created_at, updated_at)) => {
            Ok(Json(ApiResponse {
                success: true,
                data: Some(WorkspaceResponse {
                    id: id.to_string(),
                    name,
                    slug,
                    description,
                    workspace_type,
                    owner_user_id: owner_user_id.map(|u| u.to_string()),
                    tenant_id: tenant_id.map(|t| t.to_string()),
                    created_at: created_at.to_rfc3339(),
                    updated_at: updated_at.to_rfc3339(),
                }),
                error: None,
            }))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "NOT_FOUND".to_string(),
                    message: "Workspace not found".to_string(),
                }),
            }),
        )),
    }
}

/// List workspaces for authenticated user
/// 
/// GET /api/v1/workspaces
/// 
/// Returns workspaces where user is a member (any role)
pub async fn list_workspaces(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<ListWorkspacesQuery>,
) -> Result<Json<PaginatedResponse<WorkspaceResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let user_id = headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "UNAUTHORIZED".to_string(),
                        message: "Authentication required".to_string(),
                    }),
                }),
            )
        })?;

    let user_uuid = uuid::Uuid::parse_str(user_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "INVALID_USER_ID".to_string(),
                    message: "Invalid user ID format".to_string(),
                }),
            }),
        )
    })?;

    let limit = query.limit.min(100);
    let offset = query.offset;

    let workspaces: Vec<(uuid::Uuid, String, String, Option<String>, String, Option<uuid::Uuid>, Option<uuid::Uuid>, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> = 
        sqlx::query_as(
            r#"
            SELECT w.id, w.name, w.slug, w.description, w.workspace_type, w.owner_user_id, w.tenant_id, w.created_at, w.updated_at
            FROM workspaces w
            INNER JOIN workspace_members wm ON w.id = wm.workspace_id
            WHERE wm.user_id = $1
            ORDER BY w.created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(user_uuid)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&state.db_pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "LIST_FAILED".to_string(),
                        message: e.to_string(),
                    }),
                }),
            )
        })?;

    let items: Vec<WorkspaceResponse> = workspaces
        .into_iter()
        .map(|(id, name, slug, description, workspace_type, owner_user_id, tenant_id, created_at, updated_at)| {
            WorkspaceResponse {
                id: id.to_string(),
                name,
                slug,
                description,
                workspace_type,
                owner_user_id: owner_user_id.map(|u| u.to_string()),
                tenant_id: tenant_id.map(|t| t.to_string()),
                created_at: created_at.to_rfc3339(),
                updated_at: updated_at.to_rfc3339(),
            }
        })
        .collect();

    let has_more = items.len() as u32 == limit;

    Ok(Json(PaginatedResponse {
        total: items.len() as u64,
        items,
        offset,
        limit,
        has_more,
    }))
}

/// Update a workspace
/// 
/// PUT /api/v1/workspaces/:id
pub async fn update_workspace(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<UpdateWorkspaceRequest>,
) -> Result<Json<ApiResponse<WorkspaceResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let workspace_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "INVALID_ID".to_string(),
                    message: "Invalid workspace ID format".to_string(),
                }),
            }),
        )
    })?;

    // Build dynamic update query
    let mut set_clauses = vec!["updated_at = NOW()".to_string()];
    
    if request.name.is_some() {
        set_clauses.push(format!("name = '{}'", request.name.as_ref().unwrap().replace('\'', "''")));
    }
    if request.description.is_some() {
        set_clauses.push(format!("description = '{}'", request.description.as_ref().unwrap().replace('\'', "''")));
    }

    let query = format!(
        "UPDATE workspaces SET {} WHERE id = $1 RETURNING id, name, slug, description, workspace_type, owner_user_id, tenant_id, created_at, updated_at",
        set_clauses.join(", ")
    );

    let result: Option<(uuid::Uuid, String, String, Option<String>, String, Option<uuid::Uuid>, Option<uuid::Uuid>, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> = 
        sqlx::query_as(&query)
            .bind(workspace_id)
            .fetch_optional(&state.db_pool)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse {
                        success: false,
                        data: None,
                        error: Some(ApiError {
                            code: "UPDATE_FAILED".to_string(),
                            message: e.to_string(),
                        }),
                    }),
                )
            })?;

    match result {
        Some((id, name, slug, description, workspace_type, owner_user_id, tenant_id, created_at, updated_at)) => {
            Ok(Json(ApiResponse {
                success: true,
                data: Some(WorkspaceResponse {
                    id: id.to_string(),
                    name,
                    slug,
                    description,
                    workspace_type,
                    owner_user_id: owner_user_id.map(|u| u.to_string()),
                    tenant_id: tenant_id.map(|t| t.to_string()),
                    created_at: created_at.to_rfc3339(),
                    updated_at: updated_at.to_rfc3339(),
                }),
                error: None,
            }))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "NOT_FOUND".to_string(),
                    message: "Workspace not found".to_string(),
                }),
            }),
        )),
    }
}

/// Delete a workspace
/// 
/// DELETE /api/v1/workspaces/:id
pub async fn delete_workspace(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiResponse<()>>)> {
    let workspace_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "INVALID_ID".to_string(),
                    message: "Invalid workspace ID format".to_string(),
                }),
            }),
        )
    })?;

    let result = sqlx::query("DELETE FROM workspaces WHERE id = $1")
        .bind(workspace_id)
        .execute(&state.db_pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "DELETE_FAILED".to_string(),
                        message: e.to_string(),
                    }),
                }),
            )
        })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "NOT_FOUND".to_string(),
                    message: "Workspace not found".to_string(),
                }),
            }),
        ));
    }

    info!(workspace_id = %id, "Workspace deleted");
    Ok(StatusCode::NO_CONTENT)
}

/// Invite a user to a workspace
/// 
/// POST /api/v1/workspaces/:id/members
pub async fn invite_member(
    State(state): State<AppState>,
    Path(workspace_id): Path<String>,
    Json(request): Json<InviteMemberRequest>,
) -> Result<(StatusCode, Json<ApiResponse<WorkspaceMemberResponse>>), (StatusCode, Json<ApiResponse<()>>)> {
    let ws_id = uuid::Uuid::parse_str(&workspace_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "INVALID_ID".to_string(),
                    message: "Invalid workspace ID".to_string(),
                }),
            }),
        )
    })?;

    let user_uuid = uuid::Uuid::parse_str(&request.user_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "INVALID_USER_ID".to_string(),
                    message: "Invalid user ID".to_string(),
                }),
            }),
        )
    })?;

    // Validate role
    let role = match request.role.as_str() {
        "owner" | "admin" | "member" | "viewer" => request.role.clone(),
        _ => "member".to_string(),
    };

    // Insert member
    let result = sqlx::query(
        r#"
        INSERT INTO workspace_members (workspace_id, user_id, role, joined_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (workspace_id, user_id) DO UPDATE SET role = $3
        "#,
    )
    .bind(ws_id)
    .bind(user_uuid)
    .bind(&role)
    .execute(&state.db_pool)
    .await;

    if let Err(e) = result {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "INVITE_FAILED".to_string(),
                    message: e.to_string(),
                }),
            }),
        ));
    }

    // Create relationship in SpiceDB
    let _ = state
        .auth_service
        .client()
        .write_relationship("workspace", &workspace_id, &role, "user", &request.user_id)
        .await;

    info!(
        workspace_id = %workspace_id,
        user_id = %request.user_id,
        role = %role,
        "Member invited to workspace"
    );

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse {
            success: true,
            data: Some(WorkspaceMemberResponse {
                user_id: request.user_id,
                role,
                joined_at: chrono::Utc::now().to_rfc3339(),
            }),
            error: None,
        }),
    ))
}

/// List workspace members
/// 
/// GET /api/v1/workspaces/:id/members
pub async fn list_members(
    State(state): State<AppState>,
    Path(workspace_id): Path<String>,
) -> Result<Json<ApiResponse<Vec<WorkspaceMemberResponse>>>, (StatusCode, Json<ApiResponse<()>>)> {
    let ws_id = uuid::Uuid::parse_str(&workspace_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "INVALID_ID".to_string(),
                    message: "Invalid workspace ID".to_string(),
                }),
            }),
        )
    })?;

    let members: Vec<(uuid::Uuid, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        r#"
        SELECT user_id, role, joined_at
        FROM workspace_members
        WHERE workspace_id = $1
        ORDER BY joined_at
        "#,
    )
    .bind(ws_id)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "LIST_FAILED".to_string(),
                    message: e.to_string(),
                }),
            }),
        )
    })?;

    let items: Vec<WorkspaceMemberResponse> = members
        .into_iter()
        .map(|(user_id, role, joined_at)| WorkspaceMemberResponse {
            user_id: user_id.to_string(),
            role,
            joined_at: joined_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(ApiResponse {
        success: true,
        data: Some(items),
        error: None,
    }))
}
