//! API Key management handlers
//!
//! Provides CRUD operations for API keys used in service-to-service authentication.

use axum::{
    extract::{Extension, Path, Query, State},
    http::{header, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

use separ_core::{ApiKeyId, CreateApiKeyRequest, TenantId, UserId, WorkspaceId};
use separ_db::repositories::ApiKeyRepository;

use crate::middleware::AuthContext;
use crate::state::AppState;

/// API key response for listing (without sensitive data)
#[derive(Debug, Serialize)]
pub struct ApiKeyDto {
    pub id: String,
    pub key_prefix: String,
    pub name: String,
    pub description: Option<String>,
    pub scopes: Vec<String>,
    pub rate_limit_per_minute: i32,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
    pub created_by: Option<String>,
}

/// API key creation response (includes plaintext key ONCE)
#[derive(Debug, Serialize)]
pub struct CreateApiKeyDto {
    pub id: String,
    /// The full API key - ONLY returned once at creation time!
    pub key: String,
    pub key_prefix: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
}

/// Request body for creating an API key
#[derive(Debug, Deserialize)]
pub struct CreateApiKeyBody {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub expires_in_days: Option<i32>,
    #[serde(default)]
    pub rate_limit_per_minute: Option<i32>,
    /// Tenant ID for the API key (optional)
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Workspace ID for the API key (required)
    pub workspace_id: String,
}

/// Query parameters for listing API keys
#[derive(Debug, Deserialize)]
pub struct ListApiKeysQuery {
    /// Tenant ID (optional fallback)
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Workspace ID (preferred)
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default = "default_offset")]
    pub offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// If true, also show revoked keys
    #[serde(default)]
    pub include_revoked: bool,
}

fn default_offset() -> u32 {
    0
}

fn default_limit() -> u32 {
    100
}

/// Error response structure
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

/// Extract user ID from Authorization header (JWT)
fn extract_user_id_from_token(state: &AppState, auth_header: Option<&str>) -> Option<UserId> {
    let token = auth_header?
        .strip_prefix("Bearer ")?;
    
    let claims = state.jwt_service.validate_token(token).ok()?;
    Uuid::parse_str(&claims.sub).ok().map(UserId::from_uuid)
}

/// List API keys for a tenant
///
/// GET /api/v1/admin/api-keys?tenant_id=xxx
pub async fn list_api_keys(
    State(state): State<AppState>,
    Query(query): Query<ListApiKeysQuery>,
) -> Result<Json<Vec<ApiKeyDto>>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Listing API keys, query: {:?}", query);

    // Prefer workspace_id, fall back to tenant_id
    let keys = if let Some(ref ws_id) = query.workspace_id {
        let workspace_id = WorkspaceId::from_uuid(Uuid::parse_str(ws_id).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_workspace_id".to_string(),
                    message: "Invalid workspace ID format".to_string(),
                }),
            )
        })?);
        state
            .api_key_repo
            .list_by_workspace(workspace_id, query.offset, query.limit)
            .await
    } else if let Some(ref t_id) = query.tenant_id {
        let tenant_id = TenantId::from_uuid(Uuid::parse_str(t_id).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_tenant_id".to_string(),
                    message: "Invalid tenant ID format".to_string(),
                }),
            )
        })?);
        state
            .api_key_repo
            .list_by_tenant(tenant_id, query.offset, query.limit)
            .await
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "missing_scope".to_string(),
                message: "workspace_id or tenant_id is required".to_string(),
            }),
        ));
    };

    let keys = keys.map_err(|e| {
            warn!("Failed to list API keys: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "database_error".to_string(),
                    message: "Failed to list API keys".to_string(),
                }),
            )
        })?;

    // Filter out revoked if not requested
    let keys: Vec<_> = if query.include_revoked {
        keys
    } else {
        keys.into_iter().filter(|k| k.revoked_at.is_none()).collect()
    };

    let dtos: Vec<ApiKeyDto> = keys
        .into_iter()
        .map(|k| ApiKeyDto {
            id: k.id.to_string(),
            key_prefix: k.key_prefix,
            name: k.name,
            description: k.description,
            scopes: k.scopes,
            rate_limit_per_minute: k.rate_limit_per_minute,
            expires_at: k.expires_at.map(|t| t.to_rfc3339()),
            last_used_at: k.last_used_at.map(|t| t.to_rfc3339()),
            revoked_at: k.revoked_at.map(|t| t.to_rfc3339()),
            created_at: k.created_at.to_rfc3339(),
            created_by: k.created_by.map(|id| id.to_string()),
        })
        .collect();

    info!("Listed {} API keys", dtos.len());
    Ok(Json(dtos))
}

/// Create a new API key
///
/// POST /api/v1/admin/api-keys
pub async fn create_api_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateApiKeyBody>,
) -> Result<(StatusCode, Json<CreateApiKeyDto>), (StatusCode, Json<ErrorResponse>)> {
    debug!("Creating API key: {:?}", body.name);

    // Validate name
    if body.name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_name".to_string(),
                message: "API key name is required".to_string(),
            }),
        ));
    }

    // Parse workspace ID (required)
    let workspace_id = WorkspaceId::from_uuid(Uuid::parse_str(&body.workspace_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_workspace_id".to_string(),
                message: "Invalid workspace ID format".to_string(),
            }),
        )
    })?);

    // Parse tenant ID (optional)
    let tenant_id = body
        .tenant_id
        .as_deref()
        .and_then(|t| Uuid::parse_str(t).ok())
        .map(TenantId::from_uuid);

    // Extract user ID from Authorization header (optional, for audit)
    let created_by = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|auth| extract_user_id_from_token(&state, Some(auth)));

    // Default scopes if none provided
    let scopes = if body.scopes.is_empty() {
        vec!["read:*".to_string()]
    } else {
        body.scopes
    };

    let request = CreateApiKeyRequest {
        name: body.name.trim().to_string(),
        description: body.description,
        service_account_id: None,
        scopes,
        expires_in_days: body.expires_in_days,
        rate_limit_per_minute: body.rate_limit_per_minute,
    };

    let response = state
        .api_key_repo
        .create(request, created_by, tenant_id, Some(workspace_id))
        .await
        .map_err(|e| {
            warn!("Failed to create API key: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "database_error".to_string(),
                    message: "Failed to create API key".to_string(),
                }),
            )
        })?;

    info!(
        "Created API key {} for workspace {}",
        response.id, workspace_id
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyDto {
            id: response.id.to_string(),
            key: response.key, // Only returned once!
            key_prefix: response.key_prefix,
            name: response.name,
            scopes: response.scopes,
            expires_at: response.expires_at.map(|t| t.to_rfc3339()),
            created_at: response.created_at.to_rfc3339(),
        }),
    ))
}

/// Get a specific API key by ID
///
/// GET /api/v1/admin/api-keys/{id}
pub async fn get_api_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_ctx: Option<Extension<AuthContext>>,
) -> Result<Json<ApiKeyDto>, (StatusCode, Json<ErrorResponse>)> {
    let key_id = ApiKeyId::from_uuid(Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_id".to_string(),
                message: "Invalid API key ID format".to_string(),
            }),
        )
    })?);

    let key = state
        .api_key_repo
        .get_by_id(key_id)
        .await
        .map_err(|e| {
            warn!("Failed to get API key: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "database_error".to_string(),
                    message: "Failed to get API key".to_string(),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".to_string(),
                    message: "API key not found".to_string(),
                }),
            )
        })?;

    // Workspace isolation (defense in depth): if the auth context and the key
    // both carry a workspace_id, they must match.
    if let Some(Extension(ctx)) = &auth_ctx {
        if let Some(ctx_wid) = ctx.workspace_id {
            if let Some(key_wid) = key.workspace_id {
                if ctx_wid != key_wid {
                    return Err((
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            error: "not_found".to_string(),
                            message: "API key not found".to_string(),
                        }),
                    ));
                }
            }
        }
    }

    Ok(Json(ApiKeyDto {
        id: key.id.to_string(),
        key_prefix: key.key_prefix,
        name: key.name,
        description: key.description,
        scopes: key.scopes,
        rate_limit_per_minute: key.rate_limit_per_minute,
        expires_at: key.expires_at.map(|t| t.to_rfc3339()),
        last_used_at: key.last_used_at.map(|t| t.to_rfc3339()),
        revoked_at: key.revoked_at.map(|t| t.to_rfc3339()),
        created_at: key.created_at.to_rfc3339(),
        created_by: key.created_by.map(|id| id.to_string()),
    }))
}

/// Request body for revoking an API key
#[derive(Debug, Deserialize)]
pub struct RevokeApiKeyBody {
    /// User ID performing the revocation (for audit)
    pub revoked_by: String,
}

/// Revoke an API key
///
/// DELETE /api/v1/admin/api-keys/{id}
pub async fn revoke_api_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    auth_ctx: Option<Extension<AuthContext>>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let key_id = ApiKeyId::from_uuid(Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_id".to_string(),
                message: "Invalid API key ID format".to_string(),
            }),
        )
    })?);

    // Verify the key exists first
    let key = state
        .api_key_repo
        .get_by_id(key_id)
        .await
        .map_err(|e| {
            warn!("Failed to get API key for revocation: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "database_error".to_string(),
                    message: "Failed to get API key".to_string(),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".to_string(),
                    message: "API key not found".to_string(),
                }),
            )
        })?;

    // Workspace isolation (defense in depth): if the auth context and the key
    // both carry a workspace_id, they must match.
    if let Some(Extension(ctx)) = &auth_ctx {
        if let Some(ctx_wid) = ctx.workspace_id {
            if let Some(key_wid) = key.workspace_id {
                if ctx_wid != key_wid {
                    return Err((
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            error: "not_found".to_string(),
                            message: "API key not found".to_string(),
                        }),
                    ));
                }
            }
        }
    }

    // Check if already revoked
    if key.revoked_at.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "already_revoked".to_string(),
                message: "API key is already revoked".to_string(),
            }),
        ));
    }

    // Extract user ID from Authorization header for audit
    let revoked_by = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|auth| extract_user_id_from_token(&state, Some(auth)))
        .unwrap_or_else(UserId::new);

    state
        .api_key_repo
        .revoke(key_id, revoked_by)
        .await
        .map_err(|e| {
            warn!("Failed to revoke API key: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "database_error".to_string(),
                    message: "Failed to revoke API key".to_string(),
                }),
            )
        })?;

    info!(
        "Revoked API key {} by user {:?}",
        key_id, revoked_by
    );

    Ok(StatusCode::NO_CONTENT)
}
