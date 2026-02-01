//! Audit log query handlers

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use separ_core::{AuditEvent, AuditFilter, AuditRepository, TenantId};

use crate::dto::{ApiError, ApiResponse, PaginatedResponse};
use crate::state::AppState;

/// Audit query parameters
#[derive(Debug, Deserialize)]
pub struct AuditQueryParams {
    pub tenant_id: Option<String>,
    pub actor_id: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub event_type: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

/// Audit event response
#[derive(Debug, Serialize)]
pub struct AuditEventResponse {
    pub id: String,
    pub tenant_id: String,
    pub event_type: String,
    pub actor_type: String,
    pub actor_id: String,
    pub actor_name: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub action: String,
    pub result: String,
    pub ip_address: Option<String>,
    pub timestamp: String,
}

impl From<AuditEvent> for AuditEventResponse {
    fn from(e: AuditEvent) -> Self {
        Self {
            id: e.id.to_string(),
            tenant_id: e.tenant_id.to_string(),
            event_type: format!("{:?}", e.event_type).to_lowercase(),
            actor_type: format!("{:?}", e.actor.actor_type).to_lowercase(),
            actor_id: e.actor.id,
            actor_name: e.actor.display_name,
            resource_type: e.resource.as_ref().map(|r| r.resource_type.clone()),
            resource_id: e.resource.as_ref().map(|r| r.id.clone()),
            action: e.action,
            result: format!("{:?}", e.result).to_lowercase(),
            ip_address: e.ip_address,
            timestamp: e.timestamp.to_rfc3339(),
        }
    }
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

fn error_response(code: &str, message: &str) -> (StatusCode, Json<ApiResponse<()>>) {
    (
        StatusCode::BAD_REQUEST,
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

/// Query audit logs
/// 
/// Requires: Platform admin OR tenant admin
pub async fn query_audit_logs(
    State(state): State<AppState>,
    Query(params): Query<AuditQueryParams>,
) -> ApiResult<PaginatedResponse<AuditEventResponse>> {
    let tenant_id = match params.tenant_id.as_ref() {
        Some(tid) => match tid.parse::<TenantId>() {
            Ok(id) => id,
            Err(_) => return Err(error_response("invalid_tenant_id", "Invalid tenant ID format")),
        },
        None => return Err(error_response("missing_tenant_id", "Tenant ID is required")),
    };

    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(50).min(500);

    let filter = AuditFilter {
        event_types: None, // TODO: parse from params.event_type
        actor_id: params.actor_id,
        resource_type: params.resource_type,
        resource_id: params.resource_id,
        from_timestamp: params.from,
        to_timestamp: params.to,
    };

    let events = state
        .audit_repo
        .query(tenant_id, &filter, offset, limit)
        .await
        .map_err(|e| error_response("query_failed", &e.to_string()))?;

    let items: Vec<AuditEventResponse> = events.into_iter().map(Into::into).collect();
    let total = items.len() as u64;

    Ok(success(PaginatedResponse {
        total,
        items,
        offset,
        limit,
        has_more: false, // Would need separate count query
    }))
}

/// Get audit log for specific resource
pub async fn get_resource_audit_log(
    State(state): State<AppState>,
    Path((resource_type, resource_id)): Path<(String, String)>,
    Query(params): Query<AuditQueryParams>,
) -> ApiResult<Vec<AuditEventResponse>> {
    let tenant_id = match params.tenant_id.as_ref() {
        Some(tid) => match tid.parse::<TenantId>() {
            Ok(id) => id,
            Err(_) => return Err(error_response("invalid_tenant_id", "Invalid tenant ID format")),
        },
        None => return Err(error_response("missing_tenant_id", "Tenant ID is required")),
    };

    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(50).min(500);

    let filter = AuditFilter {
        resource_type: Some(resource_type),
        resource_id: Some(resource_id),
        from_timestamp: params.from,
        to_timestamp: params.to,
        ..Default::default()
    };

    let events = state
        .audit_repo
        .query(tenant_id, &filter, offset, limit)
        .await
        .map_err(|e| error_response("query_failed", &e.to_string()))?;

    Ok(success(events.into_iter().map(Into::into).collect()))
}
