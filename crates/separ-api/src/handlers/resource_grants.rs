//! Resource grants handlers — fine-grained per-user access control on catalog paths
//!
//! Follows the same patterns as Unity Catalog (GRANT/REVOKE),
//! Apache Polaris (catalog roles), and Lakekeeper (OpenFGA grants).

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::dto::{ApiError, ApiResponse};
use crate::middleware::AuthContext;
use crate::state::AppState;

type ApiResult<T> = Result<(StatusCode, Json<ApiResponse<T>>), (StatusCode, Json<ApiResponse<()>>)>;

fn success<T: Serialize>(data: T) -> (StatusCode, Json<ApiResponse<T>>) {
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: Some(data),
            error: None,
        }),
    )
}

fn bad_request(code: &str, msg: &str) -> (StatusCode, Json<ApiResponse<()>>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse {
            success: false,
            data: None,
            error: Some(ApiError {
                code: code.to_string(),
                message: msg.to_string(),
                details: None,
            }),
        }),
    )
}

fn internal_error(msg: &str) -> (StatusCode, Json<ApiResponse<()>>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiResponse {
            success: false,
            data: None,
            error: Some(ApiError {
                code: "internal_error".to_string(),
                message: msg.to_string(),
                details: None,
            }),
        }),
    )
}

fn forbidden(msg: &str) -> (StatusCode, Json<ApiResponse<()>>) {
    (
        StatusCode::FORBIDDEN,
        Json(ApiResponse {
            success: false,
            data: None,
            error: Some(ApiError {
                code: "forbidden".to_string(),
                message: msg.to_string(),
                details: None,
            }),
        }),
    )
}

// ─── Request/Response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateGrantRequest {
    pub path_prefix: String,
    pub principal_type: String,  // "user" or "group"
    pub principal_id: String,
    pub permission: String,      // "read", "read_write", "admin", "deny"
    #[serde(default = "default_true")]
    pub recursive: bool,
}

fn default_true() -> bool { true }

#[derive(Debug, Serialize)]
pub struct GrantResponse {
    pub id: String,
    pub workspace_id: String,
    pub path_prefix: String,
    pub principal_type: String,
    pub principal_id: String,
    pub permission: String,
    pub recursive: bool,
    pub granted_by: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ListGrantsQuery {
    pub path_prefix: Option<String>,
    pub principal_id: Option<String>,
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// Create a resource grant (GRANT permission ON path TO principal)
pub async fn create_grant(
    State(state): State<AppState>,
    Path(workspace_id): Path<String>,
    auth_ctx: Option<Extension<AuthContext>>,
    Json(request): Json<CreateGrantRequest>,
) -> ApiResult<GrantResponse> {
    let ws_uuid: Uuid = workspace_id
        .parse()
        .map_err(|_| bad_request("invalid_id", "Invalid workspace ID"))?;
    let principal_uuid: Uuid = request.principal_id
        .parse()
        .map_err(|_| bad_request("invalid_id", "Invalid principal ID"))?;

    // Validate permission value
    if !["read", "read_write", "admin", "deny"].contains(&request.permission.as_str()) {
        return Err(bad_request("invalid_permission", "Permission must be one of: read, read_write, admin, deny"));
    }
    if !["user", "group"].contains(&request.principal_type.as_str()) {
        return Err(bad_request("invalid_principal_type", "Principal type must be 'user' or 'group'"));
    }

    // Check caller has manage permission on this workspace
    if let Some(Extension(ctx)) = &auth_ctx {
        let user_id_str = ctx.user_id.to_string();
        let role = get_workspace_role(&state, ws_uuid, &user_id_str).await;
        if !matches!(role.as_deref(), Some("owner") | Some("admin")) {
            return Err(forbidden("Only workspace owners and admins can manage grants"));
        }
    }

    // Normalize path prefix
    let path_prefix = normalize_path(&request.path_prefix);

    let granted_by: Option<String> = auth_ctx
        .as_ref()
        .map(|Extension(ctx)| ctx.user_id.to_string());

    // Insert into database
    let row = sqlx::query_as::<_, (Uuid, String, String, Uuid, String, bool, Option<Uuid>, chrono::DateTime<chrono::Utc>)>(
        r#"INSERT INTO resource_grants (workspace_id, path_prefix, principal_type, principal_id, permission, recursive, granted_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (workspace_id, path_prefix, principal_type, principal_id) 
           DO UPDATE SET permission = $5, recursive = $6, updated_at = NOW()
           RETURNING id, path_prefix, principal_type, principal_id, permission, recursive, granted_by, created_at"#,
    )
    .bind(ws_uuid)
    .bind(&path_prefix)
    .bind(&request.principal_type)
    .bind(principal_uuid)
    .bind(&request.permission)
    .bind(request.recursive)
    .bind(granted_by.as_ref().and_then(|id: &String| id.parse::<Uuid>().ok()))
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| internal_error(&format!("Failed to create grant: {}", e)))?;

    // Sync to SpiceDB: create catalog_path relationship
    let spicedb_relation = match request.permission.as_str() {
        "read" => "reader",
        "read_write" => "writer",
        "admin" => "admin",
        "deny" => "denied",
        _ => "reader",
    };
    let spicedb_subject_type = match request.principal_type.as_str() {
        "group" => "group#member",
        _ => "user",
    };

    // Use path as the catalog_path ID (workspace_id:path_prefix)
    let catalog_path_id = format!("{}:{}", workspace_id, path_prefix);
    
    // Ensure catalog_path has workspace relation
    let _ = state.auth_service.client()
        .write_relationship("catalog_path", &catalog_path_id, "workspace", "workspace", &workspace_id)
        .await;

    // Write the grant relationship
    let _ = state.auth_service.client()
        .write_relationship("catalog_path", &catalog_path_id, spicedb_relation, spicedb_subject_type, &request.principal_id)
        .await;

    info!(
        workspace_id = %workspace_id,
        path = %path_prefix,
        principal = %request.principal_id,
        permission = %request.permission,
        "Resource grant created"
    );

    Ok(success(GrantResponse {
        id: row.0.to_string(),
        workspace_id: workspace_id.clone(),
        path_prefix: row.1,
        principal_type: row.2,
        principal_id: row.3.to_string(),
        permission: row.4,
        recursive: row.5,
        granted_by: row.6.map(|u| u.to_string()),
        created_at: row.7.to_rfc3339(),
    }))
}

/// List resource grants for a workspace
pub async fn list_grants(
    State(state): State<AppState>,
    Path(workspace_id): Path<String>,
    Query(query): Query<ListGrantsQuery>,
) -> ApiResult<Vec<GrantResponse>> {
    let ws_uuid: Uuid = workspace_id
        .parse()
        .map_err(|_| bad_request("invalid_id", "Invalid workspace ID"))?;

    let grants = if let Some(ref path) = query.path_prefix {
        sqlx::query_as::<_, (Uuid, String, String, Uuid, String, bool, Option<Uuid>, chrono::DateTime<chrono::Utc>)>(
            "SELECT id, path_prefix, principal_type, principal_id, permission, recursive, granted_by, created_at FROM resource_grants WHERE workspace_id = $1 AND path_prefix LIKE $2 ORDER BY path_prefix",
        )
        .bind(ws_uuid)
        .bind(format!("{}%", path))
        .fetch_all(&state.db_pool)
        .await
    } else if let Some(ref principal) = query.principal_id {
        let p_uuid: Uuid = principal.parse().map_err(|_| bad_request("invalid_id", "Invalid principal ID"))?;
        sqlx::query_as::<_, (Uuid, String, String, Uuid, String, bool, Option<Uuid>, chrono::DateTime<chrono::Utc>)>(
            "SELECT id, path_prefix, principal_type, principal_id, permission, recursive, granted_by, created_at FROM resource_grants WHERE workspace_id = $1 AND principal_id = $2 ORDER BY path_prefix",
        )
        .bind(ws_uuid)
        .bind(p_uuid)
        .fetch_all(&state.db_pool)
        .await
    } else {
        sqlx::query_as::<_, (Uuid, String, String, Uuid, String, bool, Option<Uuid>, chrono::DateTime<chrono::Utc>)>(
            "SELECT id, path_prefix, principal_type, principal_id, permission, recursive, granted_by, created_at FROM resource_grants WHERE workspace_id = $1 ORDER BY path_prefix",
        )
        .bind(ws_uuid)
        .fetch_all(&state.db_pool)
        .await
    }
    .map_err(|e| internal_error(&format!("Failed to list grants: {}", e)))?;

    let responses: Vec<GrantResponse> = grants
        .into_iter()
        .map(|row| GrantResponse {
            id: row.0.to_string(),
            workspace_id: workspace_id.clone(),
            path_prefix: row.1,
            principal_type: row.2,
            principal_id: row.3.to_string(),
            permission: row.4,
            recursive: row.5,
            granted_by: row.6.map(|u| u.to_string()),
            created_at: row.7.to_rfc3339(),
        })
        .collect();

    Ok(success(responses))
}

/// Delete (revoke) a resource grant
pub async fn delete_grant(
    State(state): State<AppState>,
    Path((workspace_id, grant_id)): Path<(String, String)>,
    auth_ctx: Option<Extension<AuthContext>>,
) -> Result<StatusCode, (StatusCode, Json<ApiResponse<()>>)> {
    let ws_uuid: Uuid = workspace_id
        .parse()
        .map_err(|_| bad_request("invalid_id", "Invalid workspace ID"))?;
    let grant_uuid: Uuid = grant_id
        .parse()
        .map_err(|_| bad_request("invalid_id", "Invalid grant ID"))?;

    // Check caller has manage permission
    if let Some(Extension(ctx)) = &auth_ctx {
        let user_id_str = ctx.user_id.to_string();
        let role = get_workspace_role(&state, ws_uuid, &user_id_str).await;
        if !matches!(role.as_deref(), Some("owner") | Some("admin")) {
            return Err(forbidden("Only workspace owners and admins can revoke grants"));
        }
    }

    // Get grant details before deleting (for SpiceDB cleanup)
    let grant = sqlx::query_as::<_, (String, String, Uuid, String)>(
        "SELECT path_prefix, principal_type, principal_id, permission FROM resource_grants WHERE id = $1 AND workspace_id = $2",
    )
    .bind(grant_uuid)
    .bind(ws_uuid)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| internal_error(&format!("Database error: {}", e)))?;

    if let Some((path_prefix, principal_type, principal_id, permission)) = grant {
        // Delete from database
        sqlx::query("DELETE FROM resource_grants WHERE id = $1")
            .bind(grant_uuid)
            .execute(&state.db_pool)
            .await
            .map_err(|e| internal_error(&format!("Failed to delete grant: {}", e)))?;

        // Clean up SpiceDB relationship
        let spicedb_relation = match permission.as_str() {
            "read" => "reader",
            "read_write" => "writer",
            "admin" => "admin",
            "deny" => "denied",
            _ => "reader",
        };
        let catalog_path_id = format!("{}:{}", workspace_id, path_prefix);
        let spicedb_subject_type = if principal_type == "group" { "group" } else { "user" };

        let _ = state.auth_service.client()
            .delete_relationship("catalog_path", &catalog_path_id, spicedb_relation, spicedb_subject_type, &principal_id.to_string())
            .await;

        info!(
            workspace_id = %workspace_id,
            grant_id = %grant_id,
            path = %path_prefix,
            "Resource grant revoked"
        );
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Resolve the effective permission for a user on a specific resource path.
///
/// Check order (most specific wins):
/// 1. Explicit deny on this path → DENIED
/// 2. Direct grant on this path → use that permission
/// 3. Grant on parent path (with recursive=true) → use that permission
/// 4. Workspace role default → map role to permission
pub async fn resolve_effective_permission(
    state: &AppState,
    workspace_id: &str,
    user_id: &str,
    resource_path: &str,
) -> String {
    let ws_uuid = match workspace_id.parse::<Uuid>() {
        Ok(u) => u,
        Err(_) => return "none".to_string(),
    };
    let user_uuid = match user_id.parse::<Uuid>() {
        Ok(u) => u,
        Err(_) => return "none".to_string(),
    };

    let normalized = normalize_path(resource_path);

    // Check for explicit grants on this path or any parent path
    // Orders by path length descending to get most specific match first
    let grant = sqlx::query_as::<_, (String, bool)>(
        r#"SELECT permission, recursive FROM resource_grants 
           WHERE workspace_id = $1 
             AND principal_type = 'user' 
             AND principal_id = $2
             AND ($3 LIKE path_prefix || '%' OR path_prefix = $3)
           ORDER BY LENGTH(path_prefix) DESC
           LIMIT 1"#,
    )
    .bind(ws_uuid)
    .bind(user_uuid)
    .bind(&normalized)
    .fetch_optional(&state.db_pool)
    .await
    .ok()
    .flatten();

    if let Some((permission, _recursive)) = grant {
        if permission == "deny" {
            return "none".to_string();
        }
        return permission;
    }

    // Also check group-based grants
    let group_grant = sqlx::query_scalar::<_, String>(
        r#"SELECT rg.permission FROM resource_grants rg
           JOIN group_members gm ON gm.group_id = rg.principal_id
           WHERE rg.workspace_id = $1 
             AND rg.principal_type = 'group'
             AND gm.user_id = $2
             AND ($3 LIKE rg.path_prefix || '%' OR rg.path_prefix = $3)
           ORDER BY LENGTH(rg.path_prefix) DESC
           LIMIT 1"#,
    )
    .bind(ws_uuid)
    .bind(user_uuid)
    .bind(&normalized)
    .fetch_optional(&state.db_pool)
    .await
    .ok()
    .flatten();

    if let Some(permission) = group_grant {
        if permission == "deny" {
            return "none".to_string();
        }
        return permission;
    }

    // Fall back to workspace role
    let role = get_workspace_role(state, ws_uuid, user_id).await;
    match role.as_deref() {
        Some("owner") | Some("admin") => "admin".to_string(),
        Some("member") => "read_write".to_string(),
        Some("viewer") => "read".to_string(),
        _ => "none".to_string(),
    }
}

/// Get the effective permission for a user and return the SAS permission string
pub fn permission_to_sas_sp(permission: &str) -> &'static str {
    match permission {
        "admin" => "racwdl",      // read, add, create, write, delete, list
        "read_write" => "racwl",   // read, add, create, write, list
        "read" => "rl",            // read, list
        _ => "",                   // no access
    }
}

/// Map permission to operation string for SAS generation
pub fn permission_to_operation(permission: &str) -> &'static str {
    match permission {
        "admin" | "read_write" => "read_write",
        "read" => "read",
        _ => "read",
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", trimmed)
    }
}

async fn get_workspace_role(state: &AppState, ws_uuid: Uuid, user_id: &str) -> Option<String> {
    let user_uuid = user_id.parse::<Uuid>().ok()?;
    sqlx::query_scalar::<_, String>(
        "SELECT role FROM workspace_members WHERE workspace_id = $1 AND user_id = $2",
    )
    .bind(ws_uuid)
    .bind(user_uuid)
    .fetch_optional(&state.db_pool)
    .await
    .ok()
    .flatten()
}
