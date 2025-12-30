//! Tenant management handlers

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use tracing::{info, warn};

use separ_core::{
    PlatformId, Tenant, TenantId, TenantRepository, TenantSettings, TenantStatus,
};

use crate::dto::{
    ApiError, ApiResponse, CreateTenantRequest, PaginatedResponse, TenantResponse,
    TenantSettingsDto, UpdateTenantRequest,
};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ListTenantsQuery {
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

/// Create a new tenant
pub async fn create_tenant(
    State(state): State<AppState>,
    Json(request): Json<CreateTenantRequest>,
) -> Result<(StatusCode, Json<ApiResponse<TenantResponse>>), (StatusCode, Json<ApiResponse<()>>)> {
    info!("Creating tenant: {}", request.name);

    let settings = request
        .settings
        .map(|s| TenantSettings {
            max_users: s.max_users,
            max_applications: s.max_applications,
            allow_external_oauth: s.allow_external_oauth.unwrap_or(true),
            scim_enabled: s.scim_enabled.unwrap_or(false),
            custom_domain: s.custom_domain,
            session_timeout_secs: s.session_timeout_secs,
        })
        .unwrap_or_default();

    let tenant = Tenant {
        id: TenantId::new(),
        platform_id: PlatformId::from_uuid(
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        ),
        name: request.name.clone(),
        slug: request.slug,
        status: TenantStatus::Active,
        settings,
        metadata: request.metadata.unwrap_or_default(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    match state.tenant_repo.create(&tenant).await {
        Ok(created) => {
            info!("Created tenant: {} ({})", created.name, created.id);
            
            // Also create the tenant in SpiceDB for authorization
            let _ = state.auth_service.client().write_relationship(
                "tenant",
                &created.id.to_string(),
                "platform",
                "platform",
                "default",
            ).await;

            Ok((
                StatusCode::CREATED,
                Json(ApiResponse {
                    success: true,
                    data: Some(tenant_to_response(&created)),
                    error: None,
                }),
            ))
        }
        Err(e) => {
            warn!("Failed to create tenant: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "CREATE_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    }),
                }),
            ))
        }
    }
}

/// Get a tenant by ID
pub async fn get_tenant(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<TenantResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let tenant_id: TenantId = id.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "INVALID_ID".to_string(),
                    message: "Invalid tenant ID format".to_string(),
                    details: None,
                }),
            }),
        )
    })?;

    match state.tenant_repo.get_by_id(tenant_id).await {
        Ok(Some(tenant)) => Ok(Json(ApiResponse {
            success: true,
            data: Some(tenant_to_response(&tenant)),
            error: None,
        })),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "NOT_FOUND".to_string(),
                    message: "Tenant not found".to_string(),
                    details: None,
                }),
            }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "FETCH_FAILED".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )),
    }
}

/// List all tenants with pagination
pub async fn list_tenants(
    State(state): State<AppState>,
    Query(query): Query<ListTenantsQuery>,
) -> Result<Json<PaginatedResponse<TenantResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(20).min(100);

    match state.tenant_repo.list(offset, limit).await {
        Ok(tenants) => {
            let items: Vec<TenantResponse> = tenants.iter().map(tenant_to_response).collect();
            let has_more = items.len() as u32 == limit;

            Ok(Json(PaginatedResponse {
                total: items.len() as u64,
                items,
                offset,
                limit,
                has_more,
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "LIST_FAILED".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )),
    }
}

/// Update an existing tenant
pub async fn update_tenant(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<UpdateTenantRequest>,
) -> Result<Json<ApiResponse<TenantResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let tenant_id: TenantId = id.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "INVALID_ID".to_string(),
                    message: "Invalid tenant ID format".to_string(),
                    details: None,
                }),
            }),
        )
    })?;

    // First, get the existing tenant
    let existing = match state.tenant_repo.get_by_id(tenant_id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "NOT_FOUND".to_string(),
                        message: "Tenant not found".to_string(),
                        details: None,
                    }),
                }),
            ))
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "FETCH_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    }),
                }),
            ))
        }
    };

    // Apply updates
    let status = request
        .status
        .as_deref()
        .map(|s| match s {
            "active" => TenantStatus::Active,
            "suspended" => TenantStatus::Suspended,
            "pending_setup" => TenantStatus::PendingSetup,
            "deactivated" => TenantStatus::Deactivated,
            _ => existing.status.clone(),
        })
        .unwrap_or(existing.status.clone());

    let settings = request
        .settings
        .map(|s| TenantSettings {
            max_users: s.max_users.or(existing.settings.max_users),
            max_applications: s.max_applications.or(existing.settings.max_applications),
            allow_external_oauth: s
                .allow_external_oauth
                .unwrap_or(existing.settings.allow_external_oauth),
            scim_enabled: s.scim_enabled.unwrap_or(existing.settings.scim_enabled),
            custom_domain: s.custom_domain.or(existing.settings.custom_domain.clone()),
            session_timeout_secs: s
                .session_timeout_secs
                .or(existing.settings.session_timeout_secs),
        })
        .unwrap_or(existing.settings.clone());

    let updated = Tenant {
        id: existing.id,
        platform_id: existing.platform_id,
        name: request.name.unwrap_or(existing.name),
        slug: request.slug.unwrap_or(existing.slug),
        status,
        settings,
        metadata: request.metadata.unwrap_or(existing.metadata),
        created_at: existing.created_at,
        updated_at: chrono::Utc::now(),
    };

    match state.tenant_repo.update(&updated).await {
        Ok(tenant) => {
            info!("Updated tenant: {}", tenant.id);
            Ok(Json(ApiResponse {
                success: true,
                data: Some(tenant_to_response(&tenant)),
                error: None,
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "UPDATE_FAILED".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )),
    }
}

/// Delete a tenant
pub async fn delete_tenant(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiResponse<()>>)> {
    let tenant_id: TenantId = id.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "INVALID_ID".to_string(),
                    message: "Invalid tenant ID format".to_string(),
                    details: None,
                }),
            }),
        )
    })?;

    match state.tenant_repo.delete(tenant_id).await {
        Ok(()) => {
            info!("Deleted tenant: {}", tenant_id);
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "DELETE_FAILED".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )),
    }
}

fn tenant_to_response(tenant: &Tenant) -> TenantResponse {
    TenantResponse {
        id: tenant.id.to_string(),
        name: tenant.name.clone(),
        slug: tenant.slug.clone(),
        status: match tenant.status {
            TenantStatus::Active => "active",
            TenantStatus::Suspended => "suspended",
            TenantStatus::PendingSetup => "pending_setup",
            TenantStatus::Deactivated => "deactivated",
        }
        .to_string(),
        settings: TenantSettingsDto {
            max_users: tenant.settings.max_users,
            max_applications: tenant.settings.max_applications,
            allow_external_oauth: Some(tenant.settings.allow_external_oauth),
            scim_enabled: Some(tenant.settings.scim_enabled),
            custom_domain: tenant.settings.custom_domain.clone(),
            session_timeout_secs: tenant.settings.session_timeout_secs,
        },
        created_at: tenant.created_at.to_rfc3339(),
        updated_at: tenant.updated_at.to_rfc3339(),
    }
}
