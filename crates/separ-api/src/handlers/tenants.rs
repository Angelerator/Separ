//! Tenant management handlers

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use tracing::{info, warn};

use separ_core::{PlatformId, Tenant, TenantId, TenantRepository, TenantSettings, TenantStatus};

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
        zed_token: None, // Will be set when permissions are assigned
    };

    match state.tenant_repo.create(&tenant).await {
        Ok(created) => {
            info!("Created tenant: {} ({})", created.name, created.id);

            // Also create the tenant in SpiceDB for authorization
            let _ = state
                .auth_service
                .client()
                .write_relationship(
                    "tenant",
                    &created.id.to_string(),
                    "platform",
                    "platform",
                    "default",
                )
                .await;

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
            _ => existing.status,
        })
        .unwrap_or(existing.status);

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
        zed_token: existing.zed_token, // Preserve existing token
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

// =============================================================================
// DOMAIN CLAIMING (Workspace-First Model)
// =============================================================================

use serde::Serialize;

#[derive(Debug, Deserialize)]
pub struct ClaimDomainRequest {
    /// The domain to claim (e.g., "acme.com")
    pub domain: String,
    /// The user ID to assign as tenant owner
    pub owner_user_id: String,
    /// Optional tenant name (defaults to domain)
    pub tenant_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ClaimDomainResponse {
    pub success: bool,
    pub tenant_id: String,
    pub domain: String,
    pub owner_user_id: String,
    pub users_linked: u64,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct UnclaimedDomainResponse {
    pub domain: String,
    pub user_count: i64,
}

#[derive(Debug, Serialize)]
pub struct DomainUserResponse {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub created_at: String,
}

/// Claim a domain and assign a tenant owner
/// 
/// POST /api/v1/admin/domains/claim
/// 
/// Platform admin uses this to:
/// 1. Create a tenant for a domain
/// 2. Assign a user as the tenant owner
/// 3. Link all users with matching email domain to the tenant
pub async fn claim_domain(
    State(state): State<AppState>,
    Json(request): Json<ClaimDomainRequest>,
) -> Result<Json<ClaimDomainResponse>, (StatusCode, Json<ApiResponse<()>>)> {
    let domain = request.domain.to_lowercase();
    
    info!(domain = %domain, owner = %request.owner_user_id, "Claiming domain");

    // Check if domain is a public email domain (cannot be claimed)
    let is_public: Option<(String,)> = sqlx::query_as(
        "SELECT domain FROM public_email_domains WHERE domain = $1"
    )
    .bind(&domain)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "DB_ERROR".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )
    })?;

    if is_public.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "PUBLIC_DOMAIN".to_string(),
                    message: format!("Cannot claim public email domain: {}", domain),
                    details: None,
                }),
            }),
        ));
    }

    // Check if domain is already claimed
    let existing_tenant: Option<(uuid::Uuid,)> = sqlx::query_as(
        "SELECT id FROM tenants WHERE domain = $1"
    )
    .bind(&domain)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "DB_ERROR".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )
    })?;

    if existing_tenant.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "DOMAIN_CLAIMED".to_string(),
                    message: format!("Domain {} is already claimed", domain),
                    details: None,
                }),
            }),
        ));
    }

    // Verify owner user exists and has matching email domain
    let owner_uuid = uuid::Uuid::parse_str(&request.owner_user_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "INVALID_USER_ID".to_string(),
                    message: "Invalid owner user ID format".to_string(),
                    details: None,
                }),
            }),
        )
    })?;

    let owner: Option<(String,)> = sqlx::query_as(
        "SELECT email FROM users WHERE id = $1"
    )
    .bind(owner_uuid)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "DB_ERROR".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )
    })?;

    let owner_email = owner.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "USER_NOT_FOUND".to_string(),
                    message: "Owner user not found".to_string(),
                    details: None,
                }),
            }),
        )
    })?.0;

    // Verify owner email matches domain
    let owner_domain = owner_email.split('@').nth(1).unwrap_or("");
    if owner_domain.to_lowercase() != domain {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "DOMAIN_MISMATCH".to_string(),
                    message: format!(
                        "Owner email domain ({}) does not match claim domain ({})",
                        owner_domain, domain
                    ),
                    details: None,
                }),
            }),
        ));
    }

    // Get or create default platform
    let platform_id: uuid::Uuid = sqlx::query_as::<_, (uuid::Uuid,)>(
        "SELECT id FROM platforms WHERE name = 'default' LIMIT 1"
    )
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "DB_ERROR".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )
    })?
    .map(|(id,)| id)
    .unwrap_or_else(uuid::Uuid::new_v4);

    // Create tenant for domain
    let tenant_id = uuid::Uuid::new_v4();
    let tenant_name = request.tenant_name.unwrap_or_else(|| domain.clone());
    
    let create_result = sqlx::query(
        r#"
        INSERT INTO tenants (id, platform_id, name, slug, domain, owner_user_id, status, settings, metadata, claimed_at, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, 'claimed', '{}', '{}', NOW(), NOW(), NOW())
        "#,
    )
    .bind(tenant_id)
    .bind(platform_id)
    .bind(&tenant_name)
    .bind(&domain) // slug = domain
    .bind(&domain)
    .bind(owner_uuid)
    .execute(&state.db_pool)
    .await;

    if let Err(e) = create_result {
        warn!("Failed to create tenant for domain {}: {}", domain, e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "CREATE_FAILED".to_string(),
                    message: format!("Failed to create tenant: {}", e),
                    details: None,
                }),
            }),
        ));
    }

    // Link all users with matching domain to this tenant
    let update_result = sqlx::query(
        r#"
        UPDATE users 
        SET tenant_id = $1, updated_at = NOW()
        WHERE LOWER(SUBSTRING(email FROM POSITION('@' IN email) + 1)) = $2
        "#,
    )
    .bind(tenant_id)
    .bind(&domain)
    .execute(&state.db_pool)
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
                    details: None,
                }),
            }),
        )
    })?;

    let users_linked = update_result.rows_affected();

    // Create SpiceDB relationships
    let tenant_id_str = tenant_id.to_string();
    
    // Owner relationship
    let _ = state
        .auth_service
        .client()
        .write_relationship("tenant", &tenant_id_str, "owner", "user", &request.owner_user_id)
        .await;

    // Link tenant to platform
    let _ = state
        .auth_service
        .client()
        .write_relationship("tenant", &tenant_id_str, "platform", "platform", "default")
        .await;

    info!(
        domain = %domain,
        tenant_id = %tenant_id_str,
        owner = %request.owner_user_id,
        users_linked = users_linked,
        "Domain claimed successfully"
    );

    Ok(Json(ClaimDomainResponse {
        success: true,
        tenant_id: tenant_id_str,
        domain,
        owner_user_id: request.owner_user_id,
        users_linked,
        message: format!("Domain claimed. {} users linked to tenant.", users_linked),
    }))
}

/// List domains with registered users but no tenant
/// 
/// GET /api/v1/admin/domains/unclaimed
pub async fn list_unclaimed_domains(
    State(state): State<AppState>,
) -> Result<Json<Vec<UnclaimedDomainResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let domains: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT 
            LOWER(SUBSTRING(email FROM POSITION('@' IN email) + 1)) as domain,
            COUNT(*) as user_count
        FROM users
        WHERE tenant_id IS NULL
        GROUP BY LOWER(SUBSTRING(email FROM POSITION('@' IN email) + 1))
        HAVING LOWER(SUBSTRING(email FROM POSITION('@' IN email) + 1)) NOT IN (
            SELECT domain FROM public_email_domains
        )
        ORDER BY user_count DESC
        "#,
    )
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "DB_ERROR".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )
    })?;

    let response: Vec<UnclaimedDomainResponse> = domains
        .into_iter()
        .map(|(domain, user_count)| UnclaimedDomainResponse { domain, user_count })
        .collect();

    Ok(Json(response))
}

/// Get users for a specific domain
/// 
/// GET /api/v1/admin/domains/{domain}/users
pub async fn get_domain_users(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Vec<DomainUserResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let domain = domain.to_lowercase();
    
    let users: Vec<(uuid::Uuid, String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        r#"
        SELECT id, email, display_name, created_at
        FROM users
        WHERE LOWER(SUBSTRING(email FROM POSITION('@' IN email) + 1)) = $1
        ORDER BY created_at
        "#,
    )
    .bind(&domain)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "DB_ERROR".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )
    })?;

    let response: Vec<DomainUserResponse> = users
        .into_iter()
        .map(|(id, email, display_name, created_at)| DomainUserResponse {
            id: id.to_string(),
            email,
            display_name,
            created_at: created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(response))
}

// =============================================================================
// Platform Admin Management
// =============================================================================

/// Request to create/promote a platform admin
#[derive(Debug, Deserialize)]
pub struct CreatePlatformAdminRequest {
    /// Email address for the admin
    pub email: String,
    /// Display name
    pub display_name: String,
    /// Password (minimum 12 characters)
    pub password: String,
}

/// Response from platform admin creation
#[derive(Debug, Serialize)]
pub struct CreatePlatformAdminResponse {
    pub success: bool,
    pub user_id: String,
    pub email: String,
    pub message: String,
}

/// Create or promote a user to platform admin (super admin)
/// 
/// POST /api/v1/admin/platform-admins
/// 
/// This endpoint creates a new platform admin or promotes an existing user.
/// Requires admin API key authentication.
pub async fn create_platform_admin(
    State(state): State<AppState>,
    Json(request): Json<CreatePlatformAdminRequest>,
) -> Result<Json<CreatePlatformAdminResponse>, (StatusCode, Json<ApiResponse<()>>)> {
    // Normalize email to lowercase for consistent storage and lookup
    let normalized_email = request.email.trim().to_lowercase();

    // Validate email format
    if !normalized_email.contains('@') || !normalized_email.contains('.') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "INVALID_EMAIL".to_string(),
                    message: "Invalid email format".to_string(),
                    details: None,
                }),
            }),
        ));
    }

    // Validate password strength
    if request.password.len() < 12 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "WEAK_PASSWORD".to_string(),
                    message: "Password must be at least 12 characters".to_string(),
                    details: None,
                }),
            }),
        ));
    }

    // Check if user already exists (case-insensitive via normalized email)
    let existing_user: Option<(uuid::Uuid,)> =
        sqlx::query_as("SELECT id FROM users WHERE LOWER(email) = $1 LIMIT 1")
            .bind(&normalized_email)
            .fetch_optional(&state.db_pool)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse {
                        success: false,
                        data: None,
                        error: Some(ApiError {
                            code: "DB_ERROR".to_string(),
                            message: e.to_string(),
                            details: None,
                        }),
                    }),
                )
            })?;

    let user_id: uuid::Uuid;
    let user_id_str: String;

    if let Some((existing_id,)) = existing_user {
        // User exists - just promote to platform admin
        user_id = existing_id;
        user_id_str = user_id.to_string();
        info!(email = %normalized_email, user_id = %user_id_str, "Promoting existing user to platform admin");

        // Update password if user exists
        let password_hash = crate::password::hash_password(&request.password).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "HASH_ERROR".to_string(),
                        message: format!("Failed to hash password: {}", e),
                        details: None,
                    }),
                }),
            )
        })?;

        // Upsert credentials
        let _ = sqlx::query(
            r#"
            INSERT INTO user_credentials (user_id, password_hash, created_at, updated_at)
            VALUES ($1, $2, NOW(), NOW())
            ON CONFLICT (user_id) DO UPDATE SET password_hash = $2, updated_at = NOW()
            "#,
        )
        .bind(&user_id_str)
        .bind(&password_hash)
        .execute(&state.db_pool)
        .await;
    } else {
        // Create new user
        user_id = uuid::Uuid::new_v4();
        user_id_str = user_id.to_string();

        info!(email = %normalized_email, user_id = %user_id_str, "Creating new platform admin");

        // Hash password
        let password_hash = crate::password::hash_password(&request.password).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "HASH_ERROR".to_string(),
                        message: format!("Failed to hash password: {}", e),
                        details: None,
                    }),
                }),
            )
        })?;

        // Create user (no tenant - platform admin is above tenants)
        // Email is stored in normalized (lowercase) form
        let result = sqlx::query(
            r#"
            INSERT INTO users (id, email, display_name, tenant_id, status, created_at, updated_at)
            VALUES ($1, $2, $3, NULL, 'active', NOW(), NOW())
            "#,
        )
        .bind(user_id)
        .bind(&normalized_email)
        .bind(&request.display_name)
        .execute(&state.db_pool)
        .await;

        if let Err(e) = result {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "CREATE_FAILED".to_string(),
                        message: format!("Failed to create user: {}", e),
                        details: None,
                    }),
                }),
            ));
        }

        // Store password
        let cred_result = sqlx::query(
            r#"
            INSERT INTO user_credentials (user_id, password_hash, created_at, updated_at)
            VALUES ($1, $2, NOW(), NOW())
            "#,
        )
        .bind(&user_id_str)
        .bind(&password_hash)
        .execute(&state.db_pool)
        .await;

        if let Err(e) = cred_result {
            // Rollback user creation
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(user_id)
                .execute(&state.db_pool)
                .await;
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "CRED_FAILED".to_string(),
                        message: format!("Failed to store credentials: {}", e),
                        details: None,
                    }),
                }),
            ));
        }
    }

    // Ensure default platform exists
    let platform_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let _ = sqlx::query(
        r#"
        INSERT INTO platforms (id, name, description, status, settings, created_at, updated_at)
        VALUES ($1, 'default', 'Default Platform', 'active', '{}', NOW(), NOW())
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(platform_id)
    .execute(&state.db_pool)
    .await;

    // Grant platform admin role in SpiceDB
    let write_result = state
        .auth_service
        .client()
        .write_relationship("platform", "default", "admin", "user", &user_id_str)
        .await;

    if let Err(e) = write_result {
        warn!("Failed to write SpiceDB relationship: {}", e);
        // Continue - user is created, SpiceDB might just need retry
    }

    info!(
        email = %request.email,
        user_id = %user_id_str,
        "Platform admin created/promoted successfully"
    );

    Ok(Json(CreatePlatformAdminResponse {
        success: true,
        user_id: user_id_str,
        email: request.email,
        message: "Platform admin created successfully".to_string(),
    }))
}

/// List all platform admins
/// 
/// GET /api/v1/admin/platform-admins
pub async fn list_platform_admins(
    State(state): State<AppState>,
) -> Result<Json<Vec<DomainUserResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    // Get all users who have platform admin role
    // For now, check all users and filter by SpiceDB permission
    let users: Vec<(uuid::Uuid, String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        r#"
        SELECT id, email, display_name, created_at
        FROM users
        WHERE status = 'active'
        ORDER BY created_at DESC
        LIMIT 100
        "#,
    )
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "DB_ERROR".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )
    })?;

    // Filter by platform admin permission in SpiceDB
    let mut admins = Vec::new();
    for (id, email, display_name, created_at) in users {
        let is_admin = state
            .auth_service
            .client()
            .check_permission("platform", "default", "admin", "user", &id.to_string())
            .await
            .unwrap_or(false);

        if is_admin {
            admins.push(DomainUserResponse {
                id: id.to_string(),
                email,
                display_name,
                created_at: created_at.to_rfc3339(),
            });
        }
    }

    Ok(Json(admins))
}
