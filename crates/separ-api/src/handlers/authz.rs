//! Authorization handlers

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use tracing::{debug, info};

use separ_core::{AuthorizationService, Relationship, RelationshipFilter, Resource, Subject, SubjectType};

use crate::dto::{
    ApiError, ApiResponse, CheckPermissionRequest, CheckPermissionResponse,
    DeleteRelationshipRequest, LookupResourcesRequest, LookupResourcesResponse,
    LookupSubjectsRequest, LookupSubjectsResponse, ReadRelationshipsQuery,
    ReadRelationshipsResponse, RelationshipDto, ResourceDto, SubjectDto,
    WriteRelationshipRequest, WriteRelationshipResponse,
};
use crate::state::AppState;

/// Check if a subject has a permission on a resource
pub async fn check_permission(
    State(state): State<AppState>,
    Json(request): Json<CheckPermissionRequest>,
) -> Result<Json<CheckPermissionResponse>, (StatusCode, Json<ApiResponse<()>>)> {
    debug!(
        "Permission check: {}:{} -> {} on {}:{}",
        request.subject_type,
        request.subject_id,
        request.permission,
        request.resource_type,
        request.resource_id
    );

    let subject_type = parse_subject_type(&request.subject_type).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            }),
        )
    })?;

    let subject = Subject {
        subject_type,
        id: request.subject_id,
        relation: request.subject_relation,
    };

    let resource = Resource {
        resource_type: request.resource_type,
        id: request.resource_id,
    };

    match state
        .auth_service
        .check_permission(&subject, &resource, &request.permission)
        .await
    {
        Ok(result) => {
            info!("Permission check result: allowed={}", result.allowed);
            Ok(Json(CheckPermissionResponse {
                allowed: result.allowed,
                checked_at: result.checked_at.to_rfc3339(),
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "CHECK_FAILED".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )),
    }
}

/// Write a relationship (grant permission)
pub async fn write_relationship(
    State(state): State<AppState>,
    Json(request): Json<WriteRelationshipRequest>,
) -> Result<Json<WriteRelationshipResponse>, (StatusCode, Json<ApiResponse<()>>)> {
    info!(
        "Writing relationship: {}:{}#{}@{}:{}",
        request.resource_type,
        request.resource_id,
        request.relation,
        request.subject_type,
        request.subject_id
    );

    let subject_type = parse_subject_type(&request.subject_type).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            }),
        )
    })?;

    let relationship = Relationship {
        resource: Resource {
            resource_type: request.resource_type,
            id: request.resource_id,
        },
        relation: request.relation,
        subject: Subject {
            subject_type,
            id: request.subject_id,
            relation: request.subject_relation,
        },
        caveat: None,
    };

    match state.auth_service.write_relationship(&relationship).await {
        Ok(token) => Ok(Json(WriteRelationshipResponse {
            written_at: chrono::Utc::now().to_rfc3339(),
            token,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "WRITE_FAILED".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )),
    }
}

/// Delete a relationship (revoke permission)
pub async fn delete_relationship(
    State(state): State<AppState>,
    Json(request): Json<DeleteRelationshipRequest>,
) -> Result<Json<WriteRelationshipResponse>, (StatusCode, Json<ApiResponse<()>>)> {
    info!(
        "Deleting relationship: {}:{}#{}@{}:{}",
        request.resource_type,
        request.resource_id,
        request.relation,
        request.subject_type,
        request.subject_id
    );

    let subject_type = parse_subject_type(&request.subject_type).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            }),
        )
    })?;

    let relationship = Relationship {
        resource: Resource {
            resource_type: request.resource_type,
            id: request.resource_id,
        },
        relation: request.relation,
        subject: Subject {
            subject_type,
            id: request.subject_id,
            relation: request.subject_relation,
        },
        caveat: None,
    };

    match state.auth_service.delete_relationship(&relationship).await {
        Ok(token) => Ok(Json(WriteRelationshipResponse {
            written_at: chrono::Utc::now().to_rfc3339(),
            token,
        })),
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

/// Lookup resources a subject has permission on
pub async fn lookup_resources(
    State(state): State<AppState>,
    Json(request): Json<LookupResourcesRequest>,
) -> Result<Json<LookupResourcesResponse>, (StatusCode, Json<ApiResponse<()>>)> {
    debug!(
        "Looking up resources: {}:{} with {} on {}",
        request.subject_type, request.subject_id, request.permission, request.resource_type
    );

    let subject_type = parse_subject_type(&request.subject_type).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            }),
        )
    })?;

    let subject = Subject {
        subject_type,
        id: request.subject_id,
        relation: request.subject_relation,
    };

    match state
        .auth_service
        .lookup_resources(&subject, &request.permission, &request.resource_type)
        .await
    {
        Ok(resources) => Ok(Json(LookupResourcesResponse {
            resources: resources
                .into_iter()
                .map(|r| ResourceDto {
                    resource_type: r.resource_type,
                    id: r.id,
                })
                .collect(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "LOOKUP_FAILED".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )),
    }
}

/// Lookup subjects that have permission on a resource
pub async fn lookup_subjects(
    State(state): State<AppState>,
    Json(request): Json<LookupSubjectsRequest>,
) -> Result<Json<LookupSubjectsResponse>, (StatusCode, Json<ApiResponse<()>>)> {
    debug!(
        "Looking up subjects: {} with {} on {}:{}",
        request.subject_type, request.permission, request.resource_type, request.resource_id
    );

    let resource = Resource {
        resource_type: request.resource_type,
        id: request.resource_id,
    };

    match state
        .auth_service
        .lookup_subjects(&resource, &request.permission, &request.subject_type)
        .await
    {
        Ok(subjects) => Ok(Json(LookupSubjectsResponse {
            subjects: subjects
                .into_iter()
                .map(|s| SubjectDto {
                    subject_type: subject_type_to_string(&s.subject_type),
                    id: s.id,
                    relation: s.relation,
                })
                .collect(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "LOOKUP_FAILED".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )),
    }
}

/// Read relationships (browse permissions)
pub async fn read_relationships(
    State(state): State<AppState>,
    Query(query): Query<ReadRelationshipsQuery>,
) -> Result<Json<ReadRelationshipsResponse>, (StatusCode, Json<ApiResponse<()>>)> {
    info!(
        "Reading relationships with filter: resource_type={:?}, resource_id={:?}, relation={:?}",
        query.resource_type, query.resource_id, query.relation
    );

    let filter = RelationshipFilter {
        resource_type: query.resource_type,
        resource_id: query.resource_id,
        relation: query.relation,
        subject_type: query.subject_type,
        subject_id: query.subject_id,
        subject_relation: None,
    };

    match state.auth_service.read_relationships(&filter).await {
        Ok(relationships) => {
            let dtos: Vec<RelationshipDto> = relationships
                .into_iter()
                .map(|r| RelationshipDto {
                    resource_type: r.resource.resource_type,
                    resource_id: r.resource.id,
                    relation: r.relation,
                    subject_type: subject_type_to_string(&r.subject.subject_type),
                    subject_id: r.subject.id,
                    subject_relation: r.subject.relation,
                })
                .collect();
            let count = dtos.len();
            Ok(Json(ReadRelationshipsResponse {
                relationships: dtos,
                count,
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: "READ_FAILED".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            }),
        )),
    }
}

fn parse_subject_type(s: &str) -> Result<SubjectType, ApiError> {
    match s {
        "user" => Ok(SubjectType::User),
        "service_account" => Ok(SubjectType::ServiceAccount),
        "group" => Ok(SubjectType::Group),
        "*" => Ok(SubjectType::Wildcard),
        _ => Err(ApiError {
            code: "INVALID_SUBJECT_TYPE".to_string(),
            message: format!("Invalid subject type: {}", s),
            details: None,
        }),
    }
}

fn subject_type_to_string(t: &SubjectType) -> String {
    match t {
        SubjectType::User => "user".to_string(),
        SubjectType::ServiceAccount => "service_account".to_string(),
        SubjectType::Group => "group".to_string(),
        SubjectType::Wildcard => "*".to_string(),
    }
}
