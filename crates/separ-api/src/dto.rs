//! Data Transfer Objects for API requests and responses

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Generic Response Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub total: u64,
    pub items: Vec<T>,
    pub offset: u32,
    pub limit: u32,
    pub has_more: bool,
}

/// Pagination query parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationParams {
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    20
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 20,
        }
    }
}

// ============================================================================
// Tenant DTOs
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTenantRequest {
    pub name: String,
    pub slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<TenantSettingsDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateTenantRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<TenantSettingsDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TenantResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub status: String,
    pub settings: TenantSettingsDto,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSettingsDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_users: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_applications: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_external_oauth: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_timeout_secs: Option<u32>,
}

// ============================================================================
// Authorization DTOs
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckPermissionRequest {
    pub resource_type: String,
    pub resource_id: String,
    pub permission: String,
    pub subject_type: String,
    pub subject_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_relation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckPermissionResponse {
    pub allowed: bool,
    pub checked_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WriteRelationshipRequest {
    pub resource_type: String,
    pub resource_id: String,
    pub relation: String,
    pub subject_type: String,
    pub subject_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_relation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRelationshipRequest {
    pub resource_type: String,
    pub resource_id: String,
    pub relation: String,
    pub subject_type: String,
    pub subject_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_relation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WriteRelationshipResponse {
    pub written_at: String,
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LookupResourcesRequest {
    pub resource_type: String,
    pub permission: String,
    pub subject_type: String,
    pub subject_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_relation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LookupResourcesResponse {
    pub resources: Vec<ResourceDto>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LookupSubjectsRequest {
    pub resource_type: String,
    pub resource_id: String,
    pub permission: String,
    pub subject_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LookupSubjectsResponse {
    pub subjects: Vec<SubjectDto>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceDto {
    pub resource_type: String,
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubjectDto {
    pub subject_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ReadRelationshipsQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RelationshipDto {
    pub resource_type: String,
    pub resource_id: String,
    pub relation: String,
    pub subject_type: String,
    pub subject_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_relation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadRelationshipsResponse {
    pub relationships: Vec<RelationshipDto>,
    pub count: usize,
}
