//! Storage connection handlers

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;

use separ_core::{
    AuthorizationService, CreateStorageConnectionRequest, Relationship, Resource, 
    StorageConnection, StorageConnectionId, StorageConnectionRepository,
    StorageConnectionStatus, Subject, SubjectType, TenantId, 
    UpdateStorageConnectionRequest, UserId, WorkspaceId,
};

use crate::dto::{ApiError, ApiResponse};
use crate::middleware::AuthContext;
use crate::state::AppState;

/// List query parameters
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub tenant_id: Option<String>,
    pub workspace_id: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

/// Storage connection response (without secrets)
#[derive(Debug, Serialize)]
pub struct StorageConnectionResponse {
    pub id: String,
    pub tenant_id: String,
    pub workspace_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub storage_type: String,
    pub azure_account_name: Option<String>,
    pub azure_container: Option<String>,
    pub azure_tenant_id: Option<String>,
    pub azure_client_id: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
    pub s3_access_key_id: Option<String>,
    pub s3_endpoint_url: Option<String>,
    pub gcs_bucket: Option<String>,
    pub gcs_project_id: Option<String>,
    pub key_prefix: Option<String>,
    pub status: String,
    pub last_tested_at: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<StorageConnection> for StorageConnectionResponse {
    fn from(c: StorageConnection) -> Self {
        Self {
            id: c.id.to_string(),
            tenant_id: c.tenant_id.map(|t| t.to_string()).unwrap_or_default(),
            workspace_id: c.workspace_id.map(|w| w.to_string()),
            name: c.name,
            description: c.description,
            storage_type: c.storage_type.to_string(),
            azure_account_name: c.azure_account_name,
            azure_container: c.azure_container,
            azure_tenant_id: c.azure_tenant_id,
            azure_client_id: c.azure_client_id,
            s3_bucket: c.s3_bucket,
            s3_region: c.s3_region,
            s3_access_key_id: c.s3_access_key_id,
            s3_endpoint_url: c.s3_endpoint_url,
            gcs_bucket: c.gcs_bucket,
            gcs_project_id: c.gcs_project_id,
            key_prefix: c.key_prefix,
            status: c.status.to_string(),
            last_tested_at: c.last_tested_at.map(|t| t.to_rfc3339()),
            last_error: c.last_error,
            created_at: c.created_at.to_rfc3339(),
            updated_at: c.updated_at.to_rfc3339(),
        }
    }
}

/// Storage connection with credentials response
#[derive(Debug, Serialize)]
pub struct StorageConnectionWithCredentialsResponse {
    #[serde(flatten)]
    pub connection: StorageConnectionResponse,
    pub azure_client_secret: Option<String>,
    pub s3_secret_access_key: Option<String>,
    pub gcs_service_account_key: Option<String>,
}

/// Test connection response
#[derive(Debug, Serialize)]
pub struct TestConnectionResponse {
    pub success: bool,
    pub message: String,
}

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

fn created<T: Serialize>(data: T) -> (StatusCode, Json<ApiResponse<T>>) {
    (
        StatusCode::CREATED,
        Json(ApiResponse {
            success: true,
            data: Some(data),
            error: None,
        }),
    )
}

fn error_response(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<ApiResponse<()>>) {
    (
        status,
        Json(ApiResponse {
            success: false,
            data: None,
            error: Some(ApiError {
                code: code.to_string(),
                message: message.to_string(),
                details: None,
            }),
        }),
    )
}

fn bad_request(code: &str, message: &str) -> (StatusCode, Json<ApiResponse<()>>) {
    error_response(StatusCode::BAD_REQUEST, code, message)
}

fn not_found(message: &str) -> (StatusCode, Json<ApiResponse<()>>) {
    error_response(StatusCode::NOT_FOUND, "not_found", message)
}

fn internal_error(message: &str) -> (StatusCode, Json<ApiResponse<()>>) {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
}

/// Workspace isolation check (defense in depth).
///
/// If the auth context carries a `workspace_id` **and** the resource also has
/// a `workspace_id`, the two must match.  A mismatch is surfaced as "not found"
/// so we don't leak the existence of cross-workspace resources.
fn validate_workspace_isolation(
    auth_ctx: &Option<Extension<AuthContext>>,
    resource_workspace_id: Option<WorkspaceId>,
) -> Result<(), (StatusCode, Json<ApiResponse<()>>)> {
    if let Some(Extension(ctx)) = auth_ctx {
        if let Some(ctx_wid) = ctx.workspace_id {
            if let Some(res_wid) = resource_workspace_id {
                if ctx_wid != res_wid {
                    return Err(not_found("Storage connection not found"));
                }
            }
        }
    }
    Ok(())
}

/// Create request with tenant and user context
#[derive(Debug, Deserialize)]
pub struct CreateStorageConnectionBody {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub workspace_id: Option<String>,
    pub user_id: String,
    #[serde(flatten)]
    pub request: CreateStorageConnectionRequest,
}

/// Create a new storage connection
pub async fn create_storage_connection(
    State(state): State<AppState>,
    Json(body): Json<CreateStorageConnectionBody>,
) -> ApiResult<StorageConnectionResponse> {
    let tenant_id: Option<TenantId> = body.tenant_id
        .as_ref()
        .filter(|t| !t.is_empty())
        .map(|t| t.parse::<TenantId>())
        .transpose()
        .map_err(|_| bad_request("invalid_tenant_id", "Invalid tenant ID format"))?;

    let workspace_id: Option<WorkspaceId> = body.workspace_id
        .as_ref()
        .map(|wid| wid.parse::<WorkspaceId>())
        .transpose()
        .map_err(|_| bad_request("invalid_workspace_id", "Invalid workspace ID format"))?;
    
    let user_id: UserId = body.user_id
        .parse()
        .map_err(|_| bad_request("invalid_user_id", "Invalid user ID format"))?;

    // Inject workspace_id into the request
    let mut request = body.request;
    request.workspace_id = workspace_id;

    info!(
        tenant = ?tenant_id,
        workspace = ?workspace_id,
        user = %user_id,
        name = %request.name,
        storage_type = ?request.storage_type,
        "Creating storage connection"
    );

    let connection = state
        .storage_connection_repo
        .create(tenant_id, user_id, &request)
        .await
        .map_err(|e| internal_error(&e.to_string()))?;

    // Grant owner permission in SpiceDB
    let _ = state.auth_service.write_relationship(&Relationship {
        resource: Resource {
            resource_type: "storage_connection".to_string(),
            id: connection.id.to_string(),
        },
        relation: "owner".to_string(),
        subject: Subject {
            subject_type: SubjectType::User,
            id: user_id.to_string(),
            relation: None,
        },
        caveat: None,
    }).await;

    // Link to tenant (only if tenant is provided)
    if let Some(tid) = tenant_id {
        let _ = state.auth_service.write_relationship(&Relationship {
            resource: Resource {
                resource_type: "storage_connection".to_string(),
                id: connection.id.to_string(),
            },
            relation: "tenant".to_string(),
            subject: Subject {
                subject_type: SubjectType::Tenant,
                id: tid.to_string(),
                relation: None,
            },
            caveat: None,
        }).await;
    }

    // Link to workspace
    if let Some(wid) = workspace_id {
        let _ = state.auth_service.write_relationship(&Relationship {
            resource: Resource {
                resource_type: "storage_connection".to_string(),
                id: connection.id.to_string(),
            },
            relation: "workspace".to_string(),
            subject: Subject {
                subject_type: SubjectType::Workspace,
                id: wid.to_string(),
                relation: None,
            },
            caveat: None,
        }).await;
    }

    Ok(created(StorageConnectionResponse::from(connection)))
}

/// List storage connections for a tenant or workspace
pub async fn list_storage_connections(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Vec<StorageConnectionResponse>> {
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).min(1000);

    // Prefer workspace_id filtering; fall back to tenant_id
    let connections = if let Some(ref wid) = query.workspace_id {
        let workspace_id = wid.parse::<WorkspaceId>()
            .map_err(|_| bad_request("invalid_workspace_id", "Invalid workspace ID format"))?;
        state
            .storage_connection_repo
            .list_by_workspace(workspace_id, offset, limit)
            .await
            .map_err(|e| internal_error(&e.to_string()))?
    } else if let Some(ref tid) = query.tenant_id {
        let tenant_id = tid.parse::<TenantId>()
            .map_err(|_| bad_request("invalid_tenant_id", "Invalid tenant ID format"))?;
        state
            .storage_connection_repo
            .list_by_tenant(tenant_id, offset, limit)
            .await
            .map_err(|e| internal_error(&e.to_string()))?
    } else {
        return Err(bad_request("missing_filter", "Either workspace_id or tenant_id is required"));
    };

    Ok(success(connections.into_iter().map(StorageConnectionResponse::from).collect()))
}

/// Query parameters for getting a single storage connection
#[derive(Debug, Deserialize)]
pub struct GetStorageConnectionQuery {
    pub workspace_id: Option<String>,
}

/// Get a specific storage connection
pub async fn get_storage_connection(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<GetStorageConnectionQuery>,
) -> ApiResult<StorageConnectionResponse> {
    let id: StorageConnectionId = id
        .parse()
        .map_err(|_| bad_request("invalid_id", "Invalid storage connection ID"))?;

    let connection = state
        .storage_connection_repo
        .get_by_id(id)
        .await
        .map_err(|e| internal_error(&e.to_string()))?
        .ok_or_else(|| not_found("Storage connection not found"))?;

    // Workspace isolation: if both the request and the connection carry a
    // workspace_id, they must match.  A mismatch is surfaced as "not found"
    // so we don't leak the existence of cross-workspace resources.
    if let Some(ref req_wid) = query.workspace_id {
        let req_workspace_id: WorkspaceId = req_wid
            .parse()
            .map_err(|_| bad_request("invalid_workspace_id", "Invalid workspace ID format"))?;
        if let Some(conn_workspace_id) = connection.workspace_id {
            if conn_workspace_id != req_workspace_id {
                return Err(not_found("Storage connection not found"));
            }
        }
    }

    Ok(success(StorageConnectionResponse::from(connection)))
}

/// Get storage connection with credentials (for authorized services)
pub async fn get_storage_connection_credentials(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_ctx: Option<Extension<AuthContext>>,
) -> ApiResult<StorageConnectionWithCredentialsResponse> {
    let id: StorageConnectionId = id
        .parse()
        .map_err(|_| bad_request("invalid_id", "Invalid storage connection ID"))?;

    let with_creds = state
        .storage_connection_repo
        .get_with_credentials(id)
        .await
        .map_err(|e| internal_error(&e.to_string()))?
        .ok_or_else(|| not_found("Storage connection not found"))?;

    // Workspace isolation (defense in depth)
    validate_workspace_isolation(&auth_ctx, with_creds.connection.workspace_id)?;

    Ok(success(StorageConnectionWithCredentialsResponse {
        connection: StorageConnectionResponse::from(with_creds.connection),
        azure_client_secret: with_creds.azure_client_secret,
        s3_secret_access_key: with_creds.s3_secret_access_key,
        gcs_service_account_key: with_creds.gcs_service_account_key,
    }))
}

/// Update a storage connection
pub async fn update_storage_connection(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_ctx: Option<Extension<AuthContext>>,
    Json(request): Json<UpdateStorageConnectionRequest>,
) -> ApiResult<StorageConnectionResponse> {
    let id: StorageConnectionId = id
        .parse()
        .map_err(|_| bad_request("invalid_id", "Invalid storage connection ID"))?;

    // Fetch connection first for workspace isolation check
    let existing = state
        .storage_connection_repo
        .get_by_id(id)
        .await
        .map_err(|e| internal_error(&e.to_string()))?
        .ok_or_else(|| not_found("Storage connection not found"))?;

    // Workspace isolation (defense in depth)
    validate_workspace_isolation(&auth_ctx, existing.workspace_id)?;

    let connection = state
        .storage_connection_repo
        .update(id, &request)
        .await
        .map_err(|e| internal_error(&e.to_string()))?;

    Ok(success(StorageConnectionResponse::from(connection)))
}

/// Delete a storage connection
pub async fn delete_storage_connection(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_ctx: Option<Extension<AuthContext>>,
) -> Result<StatusCode, (StatusCode, Json<ApiResponse<()>>)> {
    let id: StorageConnectionId = id
        .parse()
        .map_err(|_| bad_request("invalid_id", "Invalid storage connection ID"))?;

    // Fetch connection first for workspace isolation check
    let existing = state
        .storage_connection_repo
        .get_by_id(id)
        .await
        .map_err(|e| internal_error(&e.to_string()))?
        .ok_or_else(|| not_found("Storage connection not found"))?;

    // Workspace isolation (defense in depth)
    validate_workspace_isolation(&auth_ctx, existing.workspace_id)?;

    state
        .storage_connection_repo
        .delete(id)
        .await
        .map_err(|e| internal_error(&e.to_string()))?;

    // Clean up SpiceDB relationships
    use separ_core::RelationshipFilter;
    let _ = state.auth_service.delete_relationships(&RelationshipFilter {
        resource_type: Some("storage_connection".to_string()),
        resource_id: Some(id.to_string()),
        ..Default::default()
    }).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Vend temporary credentials (SAS token) for a storage connection.
///
/// Pure SAS generation — no authorization logic here.
/// Authorization (catalog-level permission checks) is handled by Yekta,
/// which calls this endpoint with the already-resolved operation level.
///
/// This follows the correct separation of concerns:
/// - Yekta owns the catalog (grants, catalog paths, permission checks)
/// - Separ owns the credentials (encrypted secrets, SAS token generation)
pub async fn vend_credentials(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_ctx: Option<Extension<AuthContext>>,
    Json(request): Json<super::azure_sas::VendCredentialsRequest>,
) -> ApiResult<super::azure_sas::VendCredentialsResponse> {
    let id: StorageConnectionId = id
        .parse()
        .map_err(|_| bad_request("invalid_id", "Invalid storage connection ID"))?;

    let with_creds = state
        .storage_connection_repo
        .get_with_credentials(id)
        .await
        .map_err(|e| internal_error(&e.to_string()))?
        .ok_or_else(|| not_found("Storage connection not found"))?;

    // Workspace isolation
    validate_workspace_isolation(&auth_ctx, with_creds.connection.workspace_id)?;

    // Only Azure ADLS is supported for SAS vending right now
    if with_creds.connection.storage_type != separ_core::StorageType::Adls {
        return Err(bad_request(
            "unsupported_storage_type",
            "SAS credential vending is only supported for Azure ADLS connections",
        ));
    }

    let account_name = with_creds
        .connection
        .azure_account_name
        .ok_or_else(|| bad_request("missing_config", "Azure account name is required"))?;
    let container = with_creds
        .connection
        .azure_container
        .ok_or_else(|| bad_request("missing_config", "Azure container is required"))?;

    let ttl = request.ttl_seconds.unwrap_or(super::azure_sas::DEFAULT_TTL_SECONDS);

    let params = super::azure_sas::AzureSasParams {
        account_name,
        container,
        resource_path: request.resource_path,
        operation: request.operation,
        ttl_seconds: ttl,
        scope: request.scope,
        tenant_id: with_creds.connection.azure_tenant_id,
        client_id: with_creds.connection.azure_client_id,
        client_secret: with_creds.azure_client_secret,
        access_key: None,
    };

    let response = super::azure_sas::generate_sas_token(params)
        .await
        .map_err(|e| {
            info!("SAS token generation failed: {}", e);
            internal_error(&format!("Failed to generate SAS token: {}", e))
        })?;

    Ok(success(response))
}

/// Test a storage connection
pub async fn test_storage_connection(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth_ctx: Option<Extension<AuthContext>>,
) -> ApiResult<TestConnectionResponse> {
    let id: StorageConnectionId = id
        .parse()
        .map_err(|_| bad_request("invalid_id", "Invalid storage connection ID"))?;

    let with_creds = state
        .storage_connection_repo
        .get_with_credentials(id)
        .await
        .map_err(|e| internal_error(&e.to_string()))?
        .ok_or_else(|| not_found("Storage connection not found"))?;

    // Workspace isolation (defense in depth)
    validate_workspace_isolation(&auth_ctx, with_creds.connection.workspace_id)?;

    // Perform connection test based on storage type
    let (success_result, message) = match with_creds.connection.storage_type {
        separ_core::StorageType::Adls => {
            if with_creds.connection.azure_account_name.is_none() {
                (false, "Azure account name is required".to_string())
            } else if with_creds.azure_client_secret.is_none() {
                (false, "Azure client secret is required".to_string())
            } else {
                // TODO: Actually test connection to Azure
                (true, "Connection parameters valid".to_string())
            }
        }
        separ_core::StorageType::S3 => {
            if with_creds.connection.s3_bucket.is_none() {
                (false, "S3 bucket is required".to_string())
            } else if with_creds.s3_secret_access_key.is_none() {
                (false, "S3 secret access key is required".to_string())
            } else {
                // TODO: Actually test connection to S3
                (true, "Connection parameters valid".to_string())
            }
        }
        separ_core::StorageType::Gcs => {
            if with_creds.connection.gcs_bucket.is_none() {
                (false, "GCS bucket is required".to_string())
            } else if with_creds.gcs_service_account_key.is_none() {
                (false, "GCS service account key is required".to_string())
            } else {
                // TODO: Actually test connection to GCS
                (true, "Connection parameters valid".to_string())
            }
        }
    };

    // Update status based on test result
    let status = if success_result {
        StorageConnectionStatus::Active
    } else {
        StorageConnectionStatus::Error
    };
    let error = if success_result { None } else { Some(message.as_str()) };

    state
        .storage_connection_repo
        .update_status(id, status, error)
        .await
        .map_err(|e| internal_error(&e.to_string()))?;

    Ok(success(TestConnectionResponse { success: success_result, message }))
}
