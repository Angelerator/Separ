//! Workspace management handlers
//!
//! Implements workspace-first model:
//! - Users own workspaces directly (not via tenants)
//! - Personal workspaces are created at registration
//! - Shared workspaces can be created by any user
//! - Workspace members can be invited
//! - Users cannot leave or delete their personal workspace

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
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
    "shared".to_string()
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
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub role: String,
    pub joined_at: String,
}

#[derive(Debug, Deserialize)]
pub struct SwitchWorkspaceRequest {
    pub workspace_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SwitchWorkspaceResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub workspace_id: String,
    pub workspace_name: String,
    pub tenant_id: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMemberRoleRequest {
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct TransferOwnershipRequest {
    pub new_owner_user_id: String,
}

#[derive(Debug, Deserialize)]
pub struct InviteByEmailRequest {
    pub email: String,
    pub role: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InvitationResponse {
    pub id: String,
    pub workspace_id: String,
    pub invitee_email: String,
    pub role: String,
    pub status: String,
    pub expires_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct AcceptInvitationRequest {
    pub token: String,
}

// ============================================================================
// Helper functions
// ============================================================================

fn extract_user_id(headers: &HeaderMap) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "unauthorized",
                    "message": "x-user-id header required"
                })),
            )
        })
}

fn parse_uuid(
    s: &str,
    field: &str,
) -> Result<uuid::Uuid, (StatusCode, Json<serde_json::Value>)> {
    uuid::Uuid::parse_str(s).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_id",
                "message": format!("Invalid {} format", field)
            })),
        )
    })
}

fn forbidden(msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "forbidden",
            "message": msg
        })),
    )
}

fn bad_request(msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "bad_request",
            "message": msg
        })),
    )
}

fn internal_error(msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "error": "internal_error",
            "message": msg
        })),
    )
}

async fn get_member_role(
    state: &AppState,
    ws_uuid: uuid::Uuid,
    user_id: &str,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let result: Option<(String,)> = sqlx::query_as(
        "SELECT role FROM workspace_members WHERE workspace_id = $1 AND user_id = $2::uuid",
    )
    .bind(ws_uuid)
    .bind(uuid::Uuid::parse_str(user_id).unwrap_or_default())
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| internal_error(&format!("Database error: {}", e)))?;

    result.map(|(r,)| r).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "not_found",
                "message": "User is not a member of this workspace"
            })),
        )
    })
}

async fn is_last_owner(
    state: &AppState,
    ws_uuid: uuid::Uuid,
    user_uuid: uuid::Uuid,
) -> Result<bool, (StatusCode, Json<serde_json::Value>)> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM workspace_members WHERE workspace_id = $1 AND role = 'owner'",
    )
    .bind(ws_uuid)
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| internal_error(&format!("Database error: {}", e)))?;

    let is_owner: Option<(String,)> = sqlx::query_as(
        "SELECT role FROM workspace_members WHERE workspace_id = $1 AND user_id = $2 AND role = 'owner'",
    )
    .bind(ws_uuid)
    .bind(user_uuid)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| internal_error(&format!("Database error: {}", e)))?;

    Ok(count.0 <= 1 && is_owner.is_some())
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
) -> Result<(StatusCode, Json<ApiResponse<WorkspaceResponse>>), (StatusCode, Json<ApiResponse<()>>)>
{
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
    let slug = request
        .name
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
    // Only "shared" is valid for user-created workspaces (personal is auto-created at registration).
    // Map legacy "team" / "organization" to "shared" for backward compatibility.
    let workspace_type = match request.workspace_type.as_str() {
        "shared" => "shared".to_string(),
        "team" | "organization" => "shared".to_string(), // backward compat
        _ => "shared".to_string(),
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
            WHERE id = $1 AND deleted_at IS NULL
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
        Some((
            id,
            name,
            slug,
            description,
            workspace_type,
            owner_user_id,
            tenant_id,
            created_at,
            updated_at,
        )) => Ok(Json(ApiResponse {
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
        })),
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
            WHERE wm.user_id = $1 AND w.deleted_at IS NULL
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
        .map(
            |(
                id,
                name,
                slug,
                description,
                workspace_type,
                owner_user_id,
                tenant_id,
                created_at,
                updated_at,
            )| {
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
            },
        )
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

    if let Some(name) = &request.name {
        set_clauses.push(format!("name = '{}'", name.replace('\'', "''")));
    }
    if let Some(description) = &request.description {
        set_clauses.push(format!(
            "description = '{}'",
            description.replace('\'', "''")
        ));
    }

    let query = format!(
        "UPDATE workspaces SET {} WHERE id = $1 AND deleted_at IS NULL RETURNING id, name, slug, description, workspace_type, owner_user_id, tenant_id, created_at, updated_at",
        set_clauses.join(", ")
    );

    let result: Option<(
        uuid::Uuid,
        String,
        String,
        Option<String>,
        String,
        Option<uuid::Uuid>,
        Option<uuid::Uuid>,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(&query)
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
        Some((
            id,
            name,
            slug,
            description,
            workspace_type,
            owner_user_id,
            tenant_id,
            created_at,
            updated_at,
        )) => Ok(Json(ApiResponse {
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
        })),
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

/// List ALL workspaces (admin endpoint — no user scoping)
///
/// GET /api/v1/admin/workspaces
pub async fn admin_list_workspaces(
    State(state): State<AppState>,
    Query(query): Query<ListWorkspacesQuery>,
) -> Result<Json<PaginatedResponse<WorkspaceResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let limit = query.limit.min(100);
    let offset = query.offset;

    let workspaces: Vec<(uuid::Uuid, String, String, Option<String>, String, Option<uuid::Uuid>, Option<uuid::Uuid>, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            r#"
            SELECT id, name, slug, description, workspace_type, owner_user_id, tenant_id, created_at, updated_at
            FROM workspaces
            WHERE deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
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
        .map(
            |(
                id,
                name,
                slug,
                description,
                workspace_type,
                owner_user_id,
                tenant_id,
                created_at,
                updated_at,
            )| {
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
            },
        )
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

/// Delete a workspace (soft delete)
///
/// DELETE /api/v1/workspaces/:id
pub async fn delete_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let user_id = extract_user_id(&headers)?;
    let ws_uuid = parse_uuid(&id, "workspace_id")?;

    // Check if workspace exists
    let ws: Option<(String, Option<uuid::Uuid>)> = sqlx::query_as(
        "SELECT workspace_type, owner_user_id FROM workspaces WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(ws_uuid)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| internal_error(&format!("Database error: {}", e)))?;

    let (ws_type, _) = ws.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "not_found",
                "message": "Workspace not found"
            })),
        )
    })?;

    // Cannot delete personal workspaces
    if ws_type == "personal" {
        return Err(bad_request("Personal workspaces cannot be deleted"));
    }

    // Only owner can delete
    let role = get_member_role(&state, ws_uuid, &user_id).await?;
    if role != "owner" {
        return Err(forbidden(
            "Only the workspace owner can delete a workspace",
        ));
    }

    // Soft delete
    sqlx::query("UPDATE workspaces SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1")
        .bind(ws_uuid)
        .execute(&state.db_pool)
        .await
        .map_err(|e| internal_error(&format!("Failed to delete workspace: {}", e)))?;

    // Revoke all API keys for this workspace
    sqlx::query(
        "UPDATE api_keys SET revoked_at = NOW() WHERE workspace_id = $1 AND revoked_at IS NULL",
    )
    .bind(ws_uuid)
    .execute(&state.db_pool)
    .await
    .ok();

    info!(workspace_id = %id, "Workspace soft-deleted");
    Ok(StatusCode::NO_CONTENT)
}

/// Invite a user to a workspace
///
/// POST /api/v1/workspaces/:id/members
pub async fn invite_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(request): Json<InviteMemberRequest>,
) -> Result<
    (StatusCode, Json<ApiResponse<WorkspaceMemberResponse>>),
    (StatusCode, Json<ApiResponse<()>>),
> {
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

    // Check that the requester is an owner or admin
    let requester_id = extract_user_id(&headers).map_err(|(status, body)| {
        (
            status,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "UNAUTHORIZED".to_string(),
                    message: body.0["message"].as_str().unwrap_or("Unauthorized").to_string(),
                }),
            }),
        )
    })?;

    let requester_role = get_member_role(&state, ws_id, &requester_id).await.map_err(|(status, body)| {
        (
            status,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "FORBIDDEN".to_string(),
                    message: body.0["message"].as_str().unwrap_or("Access denied").to_string(),
                }),
            }),
        )
    })?;

    if !matches!(requester_role.as_str(), "owner" | "admin") {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "FORBIDDEN".to_string(),
                    message: "Only owners and admins can invite members".to_string(),
                }),
            }),
        ));
    }

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
                email: None,
                display_name: None,
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

    let members: Vec<(uuid::Uuid, Option<String>, Option<String>, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        r#"
        SELECT wm.user_id, u.email, u.display_name, wm.role, wm.joined_at
        FROM workspace_members wm
        LEFT JOIN users u ON wm.user_id = u.id
        WHERE wm.workspace_id = $1
        ORDER BY wm.joined_at
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
        .map(|(user_id, email, display_name, role, joined_at)| WorkspaceMemberResponse {
            user_id: user_id.to_string(),
            email,
            display_name,
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

/// Switch workspace - issues new JWT with different workspace_id
///
/// POST /api/v1/workspaces/switch
pub async fn switch_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SwitchWorkspaceRequest>,
) -> Result<Json<SwitchWorkspaceResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Extract user_id from request body, x-user-id header, or JWT Authorization header
    let user_id_str = if let Some(ref uid) = request.user_id {
        uid.clone()
    } else if let Some(h) = headers.get("x-user-id").and_then(|v| v.to_str().ok()) {
        h.to_string()
    } else if let Some(auth) = headers.get("Authorization").and_then(|v| v.to_str().ok()) {
        // Extract from JWT Bearer token
        if let Some(token) = auth.strip_prefix("Bearer ") {
            match state.jwt_service.validate_token(token) {
                Ok(claims) => claims.sub,
                Err(_) => return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                    "error": "invalid_token",
                    "message": "Invalid or expired token"
                })))),
            }
        } else {
            return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                "error": "unauthorized",
                "message": "User identification required (user_id in body, x-user-id header, or Bearer token)"
            }))));
        }
    } else {
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "unauthorized",
            "message": "User identification required (user_id in body, x-user-id header, or Bearer token)"
        }))));
    };

    let workspace_uuid = uuid::Uuid::parse_str(&request.workspace_id).map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "invalid_workspace_id",
            "message": "Invalid workspace ID format"
        })))
    })?;

    // Verify user is a member of the workspace
    let is_member: Option<(String,)> = sqlx::query_as(
        "SELECT role FROM workspace_members WHERE workspace_id = $1 AND user_id = $2::uuid"
    )
    .bind(workspace_uuid)
    .bind(uuid::Uuid::parse_str(&user_id_str).unwrap_or_default())
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "database_error",
            "message": format!("Failed to verify membership: {}", e)
        })))
    })?;

    if is_member.is_none() {
        return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({
            "error": "not_a_member",
            "message": "You are not a member of this workspace"
        }))));
    }

    // Get workspace details
    let workspace: Option<(String, Option<uuid::Uuid>)> = sqlx::query_as(
        "SELECT name, tenant_id FROM workspaces WHERE id = $1"
    )
    .bind(workspace_uuid)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "database_error",
            "message": format!("Failed to get workspace: {}", e)
        })))
    })?;

    let (workspace_name, tenant_uuid) = workspace.ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "workspace_not_found",
            "message": "Workspace not found"
        })))
    })?;

    let tenant_id = tenant_uuid.map(|u| u.to_string()).unwrap_or_default();

    // Get user info for token
    let user_info: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT email, display_name FROM users WHERE id = $1::uuid"
    )
    .bind(uuid::Uuid::parse_str(&user_id_str).unwrap_or_default())
    .fetch_optional(&state.db_pool)
    .await
    .unwrap_or(None);

    let (email, display_name) = user_info.unwrap_or((String::new(), None));

    // Check platform admin status to preserve roles in new JWT
    let has_platform_access = state.auth_service.client()
        .check_permission("platform", "main", "admin", "user", &user_id_str)
        .await.unwrap_or(false);

    let permissions = if has_platform_access {
        vec!["read".to_string(), "write".to_string(), "query".to_string(), "admin".to_string()]
    } else {
        vec!["read".to_string(), "query".to_string()]
    };
    let groups = if has_platform_access { vec!["admins".to_string()] } else { vec![] };

    // Generate new JWT with workspace_id and preserved permissions
    let tokens = state.jwt_service.generate_tokens(
        &user_id_str,
        &tenant_id,
        &request.workspace_id,
        if email.is_empty() { None } else { Some(&email) },
        display_name.as_deref(),
        groups,
        permissions,
    ).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "token_generation_failed",
            "message": format!("Failed to generate tokens: {}", e)
        })))
    })?;

    Ok(Json(SwitchWorkspaceResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: tokens.token_type,
        expires_in: tokens.expires_in,
        workspace_id: request.workspace_id,
        workspace_name,
        tenant_id,
    }))
}

// ============================================================================
// Member management handlers
// ============================================================================

/// Remove a member from a workspace
///
/// DELETE /api/v1/workspaces/:id/members/:user_id
pub async fn remove_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((workspace_id, member_user_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let requester_id = extract_user_id(&headers)?;
    let ws_uuid = parse_uuid(&workspace_id, "workspace_id")?;
    let member_uuid = parse_uuid(&member_user_id, "user_id")?;

    // Check requester has manage_members permission (owner or admin)
    let requester_role = get_member_role(&state, ws_uuid, &requester_id).await?;
    if !matches!(requester_role.as_str(), "owner" | "admin") {
        return Err(forbidden("Only owners and admins can remove members"));
    }

    // Cannot remove the last owner
    if is_last_owner(&state, ws_uuid, member_uuid).await? {
        return Err(bad_request(
            "Cannot remove the last owner. Transfer ownership first.",
        ));
    }

    // Remove from workspace_members
    sqlx::query("DELETE FROM workspace_members WHERE workspace_id = $1 AND user_id = $2")
        .bind(ws_uuid)
        .bind(member_uuid)
        .execute(&state.db_pool)
        .await
        .map_err(|e| internal_error(&format!("Failed to remove member: {}", e)))?;

    // Remove SpiceDB relationships
    let _ = state
        .auth_service
        .client()
        .delete_relationship(
            "workspace",
            &workspace_id,
            &requester_role,
            "user",
            &member_user_id,
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Update a member's role in a workspace
///
/// PUT /api/v1/workspaces/:id/members/:user_id
pub async fn update_member_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((workspace_id, member_user_id)): Path<(String, String)>,
    Json(request): Json<UpdateMemberRoleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let requester_id = extract_user_id(&headers)?;
    let ws_uuid = parse_uuid(&workspace_id, "workspace_id")?;
    let member_uuid = parse_uuid(&member_user_id, "user_id")?;

    // Validate role
    let valid_roles = ["owner", "admin", "member", "viewer"];
    if !valid_roles.contains(&request.role.as_str()) {
        return Err(bad_request(&format!(
            "Invalid role. Must be one of: {}",
            valid_roles.join(", ")
        )));
    }

    // Check requester has manage_members permission
    let requester_role = get_member_role(&state, ws_uuid, &requester_id).await?;
    if !matches!(requester_role.as_str(), "owner" | "admin") {
        return Err(forbidden("Only owners and admins can change roles"));
    }

    // Only owners can promote to owner or demote from owner
    let current_role = get_member_role(&state, ws_uuid, &member_user_id).await?;
    if (current_role == "owner" || request.role == "owner") && requester_role != "owner" {
        return Err(forbidden("Only owners can grant or revoke owner role"));
    }

    // Cannot demote last owner
    if current_role == "owner"
        && request.role != "owner"
        && is_last_owner(&state, ws_uuid, member_uuid).await?
    {
        return Err(bad_request(
            "Cannot demote the last owner. Transfer ownership first.",
        ));
    }

    // Update in DB
    sqlx::query(
        "UPDATE workspace_members SET role = $1 WHERE workspace_id = $2 AND user_id = $3",
    )
    .bind(&request.role)
    .bind(ws_uuid)
    .bind(member_uuid)
    .execute(&state.db_pool)
    .await
    .map_err(|e| internal_error(&format!("Failed to update role: {}", e)))?;

    // Update SpiceDB: delete old relation, create new
    let _ = state
        .auth_service
        .client()
        .delete_relationship(
            "workspace",
            &workspace_id,
            &current_role,
            "user",
            &member_user_id,
        )
        .await;
    let _ = state
        .auth_service
        .client()
        .write_relationship(
            "workspace",
            &workspace_id,
            &request.role,
            "user",
            &member_user_id,
        )
        .await;

    Ok(Json(serde_json::json!({ "role": request.role })))
}

/// Leave a workspace
///
/// POST /api/v1/workspaces/:id/leave
pub async fn leave_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let user_id = extract_user_id(&headers)?;
    let ws_uuid = parse_uuid(&workspace_id, "workspace_id")?;
    let user_uuid = uuid::Uuid::parse_str(&user_id).unwrap_or_default();

    // Cannot leave personal workspace
    let ws_type: Option<(String,)> = sqlx::query_as(
        "SELECT workspace_type FROM workspaces WHERE id = $1",
    )
    .bind(ws_uuid)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| internal_error(&format!("Database error: {}", e)))?;

    if let Some((wtype,)) = &ws_type {
        if wtype == "personal" {
            return Err(bad_request("Cannot leave your personal workspace"));
        }
    }

    // Check membership
    let role = get_member_role(&state, ws_uuid, &user_id).await?;

    // Cannot leave if last owner
    if role == "owner" && is_last_owner(&state, ws_uuid, user_uuid).await? {
        return Err(bad_request(
            "Cannot leave as the last owner. Transfer ownership or delete the workspace.",
        ));
    }

    // Remove membership
    sqlx::query(
        "DELETE FROM workspace_members WHERE workspace_id = $1 AND user_id = $2::uuid",
    )
    .bind(ws_uuid)
    .bind(user_uuid)
    .execute(&state.db_pool)
    .await
    .map_err(|e| internal_error(&format!("Failed to leave workspace: {}", e)))?;

    // Remove SpiceDB
    let _ = state
        .auth_service
        .client()
        .delete_relationship("workspace", &workspace_id, &role, "user", &user_id)
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Transfer workspace ownership
///
/// POST /api/v1/workspaces/:id/transfer-ownership
pub async fn transfer_ownership(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(request): Json<TransferOwnershipRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let requester_id = extract_user_id(&headers)?;
    let ws_uuid = parse_uuid(&workspace_id, "workspace_id")?;
    let new_owner_uuid = parse_uuid(&request.new_owner_user_id, "new_owner_user_id")?;

    // Only current owner can transfer
    let requester_role = get_member_role(&state, ws_uuid, &requester_id).await?;
    if requester_role != "owner" {
        return Err(forbidden("Only owners can transfer ownership"));
    }

    // New owner must be a member
    let _ = get_member_role(&state, ws_uuid, &request.new_owner_user_id).await?;

    // Update roles in DB
    sqlx::query(
        "UPDATE workspace_members SET role = 'admin' WHERE workspace_id = $1 AND user_id = $2::uuid AND role = 'owner'",
    )
    .bind(ws_uuid)
    .bind(uuid::Uuid::parse_str(&requester_id).unwrap_or_default())
    .execute(&state.db_pool)
    .await
    .map_err(|e| internal_error(&format!("Failed to update role: {}", e)))?;

    sqlx::query(
        "UPDATE workspace_members SET role = 'owner' WHERE workspace_id = $1 AND user_id = $2",
    )
    .bind(ws_uuid)
    .bind(new_owner_uuid)
    .execute(&state.db_pool)
    .await
    .map_err(|e| internal_error(&format!("Failed to update role: {}", e)))?;

    // Update workspace owner_user_id
    sqlx::query("UPDATE workspaces SET owner_user_id = $1 WHERE id = $2")
        .bind(new_owner_uuid)
        .bind(ws_uuid)
        .execute(&state.db_pool)
        .await
        .ok();

    // Update SpiceDB
    let _ = state
        .auth_service
        .client()
        .delete_relationship("workspace", &workspace_id, "owner", "user", &requester_id)
        .await;
    let _ = state
        .auth_service
        .client()
        .write_relationship("workspace", &workspace_id, "admin", "user", &requester_id)
        .await;
    let _ = state
        .auth_service
        .client()
        .delete_relationship(
            "workspace",
            &workspace_id,
            "member",
            "user",
            &request.new_owner_user_id,
        )
        .await;
    let _ = state
        .auth_service
        .client()
        .delete_relationship(
            "workspace",
            &workspace_id,
            "admin",
            "user",
            &request.new_owner_user_id,
        )
        .await;
    let _ = state
        .auth_service
        .client()
        .write_relationship(
            "workspace",
            &workspace_id,
            "owner",
            "user",
            &request.new_owner_user_id,
        )
        .await;

    Ok(Json(serde_json::json!({
        "message": "Ownership transferred successfully",
        "new_owner": request.new_owner_user_id,
        "previous_owner_role": "admin"
    })))
}

// ============================================================================
// Invitation handlers
// ============================================================================

/// Invite a user by email to a workspace
///
/// POST /api/v1/workspaces/:id/invitations
pub async fn invite_by_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(request): Json<InviteByEmailRequest>,
) -> Result<(StatusCode, Json<InvitationResponse>), (StatusCode, Json<serde_json::Value>)> {
    let inviter_id = extract_user_id(&headers)?;
    let ws_uuid = parse_uuid(&workspace_id, "workspace_id")?;
    let role = request.role.unwrap_or_else(|| "member".to_string());

    // Validate role
    if !["admin", "member", "viewer"].contains(&role.as_str()) {
        return Err(bad_request(
            "Invalid role. Must be admin, member, or viewer",
        ));
    }

    // Check inviter has invite permission (owner or admin)
    let inviter_role = get_member_role(&state, ws_uuid, &inviter_id).await?;
    if !matches!(inviter_role.as_str(), "owner" | "admin") {
        return Err(forbidden("Only owners and admins can invite members"));
    }

    let email = request.email.trim().to_lowercase();

    // Check if already a member
    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT wm.role FROM workspace_members wm JOIN users u ON wm.user_id = u.id WHERE wm.workspace_id = $1 AND LOWER(u.email) = $2",
    )
    .bind(ws_uuid)
    .bind(&email)
    .fetch_optional(&state.db_pool)
    .await
    .unwrap_or(None);

    if existing.is_some() {
        return Err(bad_request(
            "User is already a member of this workspace",
        ));
    }

    // Check for pending invitation
    let pending: Option<(uuid::Uuid,)> = sqlx::query_as(
        "SELECT id FROM workspace_invitations WHERE workspace_id = $1 AND invitee_email = $2 AND status = 'pending'",
    )
    .bind(ws_uuid)
    .bind(&email)
    .fetch_optional(&state.db_pool)
    .await
    .unwrap_or(None);

    if pending.is_some() {
        return Err(bad_request(
            "An invitation is already pending for this email",
        ));
    }

    // Generate invitation token
    let token = uuid::Uuid::new_v4().to_string();

    // Check if user exists
    let existing_user: Option<(uuid::Uuid,)> =
        sqlx::query_as("SELECT id FROM users WHERE LOWER(email) = $1")
            .bind(&email)
            .fetch_optional(&state.db_pool)
            .await
            .unwrap_or(None);

    let inviter_uuid = uuid::Uuid::parse_str(&inviter_id).unwrap_or_default();

    // Create invitation
    let invitation_id = uuid::Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO workspace_invitations (id, workspace_id, inviter_user_id, invitee_email, invitee_user_id, role, token, status, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', NOW() + INTERVAL '7 days')"#,
    )
    .bind(invitation_id)
    .bind(ws_uuid)
    .bind(inviter_uuid)
    .bind(&email)
    .bind(existing_user.map(|(id,)| id))
    .bind(&role)
    .bind(&token)
    .execute(&state.db_pool)
    .await
    .map_err(|e| internal_error(&format!("Failed to create invitation: {}", e)))?;

    // If user already exists, auto-accept the invitation (add them directly)
    if let Some((user_id,)) = existing_user {
        // Add to workspace_members
        let _ = sqlx::query(
            "INSERT INTO workspace_members (workspace_id, user_id, role, invited_by, joined_at) VALUES ($1, $2, $3, $4, NOW()) ON CONFLICT DO NOTHING",
        )
        .bind(ws_uuid)
        .bind(user_id)
        .bind(&role)
        .bind(inviter_uuid)
        .execute(&state.db_pool)
        .await;

        // Update invitation status
        let _ = sqlx::query(
            "UPDATE workspace_invitations SET status = 'accepted', accepted_at = NOW() WHERE id = $1",
        )
        .bind(invitation_id)
        .execute(&state.db_pool)
        .await;

        // SpiceDB
        let _ = state
            .auth_service
            .client()
            .write_relationship(
                "workspace",
                &workspace_id,
                &role,
                "user",
                &user_id.to_string(),
            )
            .await;

        return Ok((
            StatusCode::CREATED,
            Json(InvitationResponse {
                id: invitation_id.to_string(),
                workspace_id: workspace_id.clone(),
                invitee_email: email,
                role,
                status: "accepted".to_string(),
                expires_at: None,
                created_at: chrono::Utc::now().to_rfc3339(),
            }),
        ));
    }

    Ok((
        StatusCode::CREATED,
        Json(InvitationResponse {
            id: invitation_id.to_string(),
            workspace_id: workspace_id.clone(),
            invitee_email: email,
            role,
            status: "pending".to_string(),
            expires_at: Some(
                (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339(),
            ),
            created_at: chrono::Utc::now().to_rfc3339(),
        }),
    ))
}

/// List pending invitations for a workspace
///
/// GET /api/v1/workspaces/:id/invitations
pub async fn list_invitations(
    State(state): State<AppState>,
    Path(workspace_id): Path<String>,
) -> Result<Json<Vec<InvitationResponse>>, (StatusCode, Json<serde_json::Value>)> {
    let ws_uuid = parse_uuid(&workspace_id, "workspace_id")?;

    let rows: Vec<(
        uuid::Uuid,
        String,
        String,
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "SELECT id, invitee_email, role, status, expires_at, created_at FROM workspace_invitations WHERE workspace_id = $1 ORDER BY created_at DESC",
    )
    .bind(ws_uuid)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| internal_error(&format!("Failed to list invitations: {}", e)))?;

    let invitations = rows
        .into_iter()
        .map(|(id, email, role, status, expires_at, created_at)| InvitationResponse {
            id: id.to_string(),
            workspace_id: workspace_id.clone(),
            invitee_email: email,
            role,
            status,
            expires_at: expires_at.map(|t| t.to_rfc3339()),
            created_at: created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(invitations))
}

/// Accept an invitation by token
///
/// POST /api/v1/workspaces/accept-invitation
pub async fn accept_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AcceptInvitationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let user_id = extract_user_id(&headers)?;

    let invitation: Option<(
        uuid::Uuid,
        uuid::Uuid,
        String,
        String,
        String,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = sqlx::query_as(
        "SELECT id, workspace_id, invitee_email, role, status, expires_at FROM workspace_invitations WHERE token = $1",
    )
    .bind(&request.token)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| internal_error(&format!("Database error: {}", e)))?;

    let (inv_id, ws_uuid, _email, role, status, expires_at) =
        invitation.ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "not_found",
                    "message": "Invitation not found"
                })),
            )
        })?;

    if status != "pending" {
        return Err(bad_request("Invitation is no longer pending"));
    }

    if let Some(exp) = expires_at {
        if exp < chrono::Utc::now() {
            let _ = sqlx::query(
                "UPDATE workspace_invitations SET status = 'expired' WHERE id = $1",
            )
            .bind(inv_id)
            .execute(&state.db_pool)
            .await;
            return Err(bad_request("Invitation has expired"));
        }
    }

    let user_uuid = uuid::Uuid::parse_str(&user_id).unwrap_or_default();

    // Add to workspace
    sqlx::query(
        "INSERT INTO workspace_members (workspace_id, user_id, role, joined_at) VALUES ($1, $2, $3, NOW()) ON CONFLICT DO NOTHING",
    )
    .bind(ws_uuid)
    .bind(user_uuid)
    .bind(&role)
    .execute(&state.db_pool)
    .await
    .map_err(|e| internal_error(&format!("Failed to join workspace: {}", e)))?;

    // Update invitation
    sqlx::query(
        "UPDATE workspace_invitations SET status = 'accepted', accepted_at = NOW(), invitee_user_id = $1 WHERE id = $2",
    )
    .bind(user_uuid)
    .bind(inv_id)
    .execute(&state.db_pool)
    .await
    .ok();

    // SpiceDB
    let _ = state
        .auth_service
        .client()
        .write_relationship(
            "workspace",
            &ws_uuid.to_string(),
            &role,
            "user",
            &user_id,
        )
        .await;

    Ok(Json(serde_json::json!({
        "message": "Successfully joined workspace",
        "workspace_id": ws_uuid.to_string(),
        "role": role
    })))
}
