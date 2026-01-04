//! User management handlers

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::dto::{ApiError, ApiResponse};
use crate::state::AppState;
use separ_core::UserId;

// =============================================================================
// DTOs
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub external_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub tenant_id: Uuid,
    /// Initial password (optional - will be generated if not provided)
    pub password: Option<String>,
    /// Roles to assign: "platform_admin", "tenant_owner", "tenant_admin", "tenant_member"
    pub roles: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct SetPasswordRequest {
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct SetPasswordResponse {
    pub success: bool,
    pub message: String,
    /// Only returned if password was auto-generated
    pub generated_password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AssignRoleRequest {
    pub role: String,
    pub resource_type: String,
    pub resource_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub tenant_id: Option<Uuid>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UserDto {
    pub id: String,
    pub external_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub tenant_id: String,
    pub roles: Vec<UserRoleDto>,
    pub active: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserRoleDto {
    pub role: String,
    pub resource_type: String,
    pub resource_id: String,
}

#[derive(Debug, Serialize)]
pub struct UsersListResponse {
    pub total: i64,
    pub items: Vec<UserDto>,
    pub offset: i64,
    pub limit: i64,
}

// =============================================================================
// Handlers
// =============================================================================

/// Create a new user and optionally assign roles
pub async fn create_user(
    State(state): State<AppState>,
    Json(request): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<ApiResponse<UserDto>>), (StatusCode, Json<ApiResponse<()>>)> {
    let user_id = UserId::new();
    info!(
        "Creating user: {} for tenant {}",
        request.email, request.tenant_id
    );

    // Write the user-tenant relationship using the client directly
    state
        .auth_service
        .client()
        .write_relationship(
            "user",
            &user_id.to_string(),
            "tenant",
            "tenant",
            &request.tenant_id.to_string(),
        )
        .await
        .map_err(|e| {
            warn!("Failed to create user relationship: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "USER_CREATE_FAILED".to_string(),
                        message: format!("Failed to create user: {}", e),
                        details: None,
                    }),
                }),
            )
        })?;

    // Assign roles if provided
    let mut assigned_roles = Vec::new();
    if let Some(roles) = &request.roles {
        for role in roles {
            let (resource_type, relation, resource_id) = match role.as_str() {
                "platform_admin" => ("platform", "admin", "main".to_string()),
                "platform_member" => ("platform", "member", "main".to_string()),
                "tenant_owner" => ("tenant", "owner", request.tenant_id.to_string()),
                "tenant_admin" => ("tenant", "admin", request.tenant_id.to_string()),
                "tenant_member" => ("tenant", "member", request.tenant_id.to_string()),
                _ => {
                    warn!("Unknown role: {}", role);
                    continue;
                }
            };

            state
                .auth_service
                .client()
                .write_relationship(
                    resource_type,
                    &resource_id,
                    relation,
                    "user",
                    &user_id.to_string(),
                )
                .await
                .map_err(|e| {
                    warn!("Failed to assign role {}: {}", role, e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ApiResponse {
                            success: false,
                            data: None,
                            error: Some(ApiError {
                                code: "ROLE_ASSIGN_FAILED".to_string(),
                                message: format!("Failed to assign role: {}", e),
                                details: None,
                            }),
                        }),
                    )
                })?;

            assigned_roles.push(UserRoleDto {
                role: relation.to_string(),
                resource_type: resource_type.to_string(),
                resource_id,
            });
        }
    }

    info!(
        "Created user: {} with {} roles",
        user_id,
        assigned_roles.len()
    );

    let user = UserDto {
        id: user_id.to_string(),
        external_id: request.external_id,
        email: request.email,
        display_name: request.display_name,
        tenant_id: request.tenant_id.to_string(),
        roles: assigned_roles,
        active: true,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse {
            success: true,
            data: Some(user),
            error: None,
        }),
    ))
}

/// Get a user by ID
pub async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<UserDto>>, (StatusCode, Json<ApiResponse<()>>)> {
    // Look up user relationships from SpiceDB
    let relationships = state
        .auth_service
        .client()
        .read_relationships(Some("user"), Some(&id), None, None, None)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "USER_READ_FAILED".to_string(),
                        message: format!("Failed to read user: {}", e),
                        details: None,
                    }),
                }),
            )
        })?;

    if relationships.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "USER_NOT_FOUND".to_string(),
                    message: "User not found".to_string(),
                    details: None,
                }),
            }),
        ));
    }

    // Find tenant relationship
    let tenant_id = relationships
        .iter()
        .find(|(_, _, rel, _, _, _)| rel == "tenant")
        .map(|(_, _, _, _, subj_id, _)| subj_id.clone())
        .unwrap_or_default();

    // Get user's roles by looking up what they're related to
    let roles = get_user_roles(&state, &id).await.unwrap_or_default();

    let user = UserDto {
        id: id.clone(),
        external_id: id.clone(),
        email: "".to_string(),
        display_name: None,
        tenant_id,
        roles,
        active: true,
        created_at: "".to_string(),
    };

    Ok(Json(ApiResponse {
        success: true,
        data: Some(user),
        error: None,
    }))
}

/// List users (optionally filtered by tenant)
pub async fn list_users(
    State(state): State<AppState>,
    Query(query): Query<ListUsersQuery>,
) -> Result<Json<ApiResponse<UsersListResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let tenant_filter = query.tenant_id.map(|t| t.to_string());

    let relationships = state
        .auth_service
        .client()
        .read_relationships(
            Some("user"),
            None,
            Some("tenant"),
            None,
            tenant_filter.as_deref(),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "USERS_LIST_FAILED".to_string(),
                        message: format!("Failed to list users: {}", e),
                        details: None,
                    }),
                }),
            )
        })?;

    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(20);

    let users: Vec<UserDto> = relationships
        .iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(|(_, res_id, _, _, subj_id, _)| UserDto {
            id: res_id.clone(),
            external_id: res_id.clone(),
            email: "".to_string(),
            display_name: None,
            tenant_id: subj_id.clone(),
            roles: vec![],
            active: true,
            created_at: "".to_string(),
        })
        .collect();

    let response = UsersListResponse {
        total: relationships.len() as i64,
        items: users,
        offset,
        limit,
    };

    Ok(Json(ApiResponse {
        success: true,
        data: Some(response),
        error: None,
    }))
}

/// Delete a user
pub async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiResponse<()>>)> {
    info!("Deleting user: {}", id);

    // Delete the user-tenant relationship
    // Note: In a full implementation, we'd also need to delete all roles
    // For now, we use the tenant relation to mark the user as deleted
    state
        .auth_service
        .client()
        .delete_relationship("user", &id, "tenant", "tenant", &id)
        .await
        .map_err(|e| {
            warn!("Failed to delete user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "USER_DELETE_FAILED".to_string(),
                        message: format!("Failed to delete user: {}", e),
                        details: None,
                    }),
                }),
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Assign a role to a user
pub async fn assign_role(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<AssignRoleRequest>,
) -> Result<StatusCode, (StatusCode, Json<ApiResponse<()>>)> {
    info!(
        "Assigning role {} on {}:{} to user {}",
        request.role, request.resource_type, request.resource_id, id
    );

    state
        .auth_service
        .client()
        .write_relationship(
            &request.resource_type,
            &request.resource_id,
            &request.role,
            "user",
            &id,
        )
        .await
        .map_err(|e| {
            warn!("Failed to assign role: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "ROLE_ASSIGN_FAILED".to_string(),
                        message: format!("Failed to assign role: {}", e),
                        details: None,
                    }),
                }),
            )
        })?;

    Ok(StatusCode::OK)
}

/// Remove a role from a user
pub async fn remove_role(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<AssignRoleRequest>,
) -> Result<StatusCode, (StatusCode, Json<ApiResponse<()>>)> {
    info!(
        "Removing role {} on {}:{} from user {}",
        request.role, request.resource_type, request.resource_id, id
    );

    state
        .auth_service
        .client()
        .delete_relationship(
            &request.resource_type,
            &request.resource_id,
            &request.role,
            "user",
            &id,
        )
        .await
        .map_err(|e| {
            warn!("Failed to remove role: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "ROLE_REMOVE_FAILED".to_string(),
                        message: format!("Failed to remove role: {}", e),
                        details: None,
                    }),
                }),
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get user roles
pub async fn get_roles(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Vec<UserRoleDto>>>, (StatusCode, Json<ApiResponse<()>>)> {
    let roles = get_user_roles(&state, &id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "ROLES_READ_FAILED".to_string(),
                    message: format!("Failed to get roles: {}", e),
                    details: None,
                }),
            }),
        )
    })?;

    Ok(Json(ApiResponse {
        success: true,
        data: Some(roles),
        error: None,
    }))
}

/// Set or reset a user's password
pub async fn set_password(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<SetPasswordRequest>,
) -> Result<Json<ApiResponse<SetPasswordResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    info!("Setting password for user: {}", id);

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

    // Hash the password
    let password_hash = crate::password::hash_password(&request.password).map_err(|e| {
        warn!("Failed to hash password: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "PASSWORD_HASH_FAILED".to_string(),
                    message: "Failed to hash password".to_string(),
                    details: None,
                }),
            }),
        )
    })?;

    // Store the password hash in the database
    // For now, store it as a relationship attribute (in production, use a proper user table)
    let result = sqlx::query(
        r#"
        INSERT INTO user_credentials (user_id, password_hash, created_at, updated_at)
        VALUES ($1, $2, NOW(), NOW())
        ON CONFLICT (user_id) DO UPDATE SET password_hash = $2, updated_at = NOW()
        "#,
    )
    .bind(&id)
    .bind(&password_hash)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => {
            info!("Password set successfully for user: {}", id);
            Ok(Json(ApiResponse {
                success: true,
                data: Some(SetPasswordResponse {
                    success: true,
                    message: "Password set successfully".to_string(),
                    generated_password: None,
                }),
                error: None,
            }))
        }
        Err(e) => {
            warn!("Failed to store password: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "PASSWORD_STORE_FAILED".to_string(),
                        message: format!("Failed to store password: {}", e),
                        details: None,
                    }),
                }),
            ))
        }
    }
}

/// Generate a new password for a user
pub async fn generate_password(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<SetPasswordResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    info!("Generating password for user: {}", id);

    // Generate a secure random password
    let new_password = crate::password::generate_password(24);

    // Hash and store it
    let password_hash = crate::password::hash_password(&new_password).map_err(|e| {
        warn!("Failed to hash password: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "PASSWORD_HASH_FAILED".to_string(),
                    message: "Failed to hash password".to_string(),
                    details: None,
                }),
            }),
        )
    })?;

    // Store the password hash
    let result = sqlx::query(
        r#"
        INSERT INTO user_credentials (user_id, password_hash, created_at, updated_at)
        VALUES ($1, $2, NOW(), NOW())
        ON CONFLICT (user_id) DO UPDATE SET password_hash = $2, updated_at = NOW()
        "#,
    )
    .bind(&id)
    .bind(&password_hash)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => {
            info!("Password generated successfully for user: {}", id);
            Ok(Json(ApiResponse {
                success: true,
                data: Some(SetPasswordResponse {
                    success: true,
                    message: "Password generated successfully. Store it securely - it won't be shown again.".to_string(),
                    generated_password: Some(new_password),
                }),
                error: None,
            }))
        }
        Err(e) => {
            warn!("Failed to store password: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(ApiError {
                        code: "PASSWORD_STORE_FAILED".to_string(),
                        message: format!("Failed to store password: {}", e),
                        details: None,
                    }),
                }),
            ))
        }
    }
}

// =============================================================================
// Helpers
// =============================================================================

async fn get_user_roles(state: &AppState, user_id: &str) -> Result<Vec<UserRoleDto>, String> {
    let mut roles = Vec::new();

    // Check platform roles
    for relation in ["admin", "member"] {
        let result = state
            .auth_service
            .client()
            .check_permission("platform", "main", relation, "user", user_id)
            .await;

        if let Ok(has_permission) = result {
            if has_permission {
                roles.push(UserRoleDto {
                    role: relation.to_string(),
                    resource_type: "platform".to_string(),
                    resource_id: "main".to_string(),
                });
            }
        }
    }

    Ok(roles)
}
