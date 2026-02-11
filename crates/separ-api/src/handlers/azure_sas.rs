//! Azure SAS token generation for credential vending
//!
//! Generates short-lived, path-scoped SAS tokens for Azure ADLS Gen2.
//! Follows the same patterns as Unity Catalog, Apache Polaris, and Lakekeeper:
//!
//! - **User Delegation SAS** (for Service Principal auth): Acquires an Azure AD
//!   token, requests a User Delegation Key, then signs a SAS token with it.
//! - **Service SAS** (for Access Key auth): Signs a SAS token directly with
//!   the storage account key.
//!
//! Both produce path-scoped, time-limited SAS tokens that grant only the
//! permissions needed for the requested operation.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{debug, info};

type HmacSha256 = Hmac<Sha256>;

/// The SAS API version to use in signed tokens
const SAS_VERSION: &str = "2022-11-02";

/// Default SAS token validity in seconds (1 hour, same as UC/Polaris/Lakekeeper)
pub const DEFAULT_TTL_SECONDS: u64 = 3600;

/// Maximum SAS token validity in seconds (7 days, Azure limit)
const MAX_TTL_SECONDS: u64 = 604800;

// ─── Request / Response types ────────────────────────────────────────────────

/// Request to vend a temporary SAS credential for a specific resource path.
#[derive(Debug, Deserialize)]
pub struct VendCredentialsRequest {
    /// The path within the container to scope the SAS token to.
    /// e.g. "dev/bronze/memotech/patents"
    pub resource_path: String,

    /// The operation type: "read" or "read_write"
    #[serde(default = "default_operation")]
    pub operation: String,

    /// SAS token validity in seconds (default: 3600, max: 604800)
    pub ttl_seconds: Option<u64>,

    /// User ID requesting the credentials (for per-user permission checks)
    pub user_id: Option<String>,

    /// SAS scope: "directory" (default, sr=d, path-scoped) or "container" (sr=c, for DuckDB)
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_scope() -> String {
    "directory".to_string()
}

fn default_operation() -> String {
    "read".to_string()
}

/// Response containing the vended temporary SAS credential.
#[derive(Debug, Serialize)]
pub struct VendCredentialsResponse {
    /// The SAS token string (without leading '?')
    pub sas_token: String,

    /// The full URI with SAS token appended
    pub signed_uri: String,

    /// Token expiration as ISO 8601 UTC timestamp
    pub expires_at: String,

    /// Token expiration as Unix epoch milliseconds
    pub expires_at_ms: i64,

    /// The storage account name
    pub account_name: String,

    /// The container/filesystem name
    pub container: String,

    /// The scoped path
    pub resource_path: String,

    /// The effective permission resolved for the user (read, read_write, admin)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_permission: Option<String>,
}

// ─── Azure AD token acquisition ──────────────────────────────────────────────

/// Azure AD token response
#[derive(Debug, Deserialize)]
struct AzureAdTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

/// Acquire an Azure AD OAuth2 token using Service Principal credentials.
async fn get_azure_ad_token(
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String, String> {
    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );

    let client = Client::new();
    let response = client
        .post(&url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", "https://storage.azure.com/.default"),
        ])
        .send()
        .await
        .map_err(|e| format!("Failed to request Azure AD token: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "no body".to_string());
        return Err(format!(
            "Azure AD token request failed ({}): {}",
            status, body
        ));
    }

    let token_response: AzureAdTokenResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Azure AD token response: {}", e))?;

    Ok(token_response.access_token)
}

// ─── User Delegation Key ─────────────────────────────────────────────────────

/// Azure User Delegation Key (returned by the Get User Delegation Key REST API)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UserDelegationKey {
    signed_oid: String,
    signed_tid: String,
    signed_start: String,
    signed_expiry: String,
    signed_service: String,
    signed_version: String,
    value: String,
}

/// Request a User Delegation Key from Azure Storage REST API.
async fn get_user_delegation_key(
    account_name: &str,
    access_token: &str,
    start: &str,
    expiry: &str,
) -> Result<UserDelegationKey, String> {
    let url = format!(
        "https://{}.blob.core.windows.net/?restype=service&comp=userdelegationkey",
        account_name
    );

    let body = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<KeyInfo>
    <Start>{}</Start>
    <Expiry>{}</Expiry>
</KeyInfo>"#,
        start, expiry
    );

    let client = Client::new();
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", access_token))
        .header("x-ms-version", SAS_VERSION)
        .header("Content-Type", "application/xml")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("Failed to request User Delegation Key: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "no body".to_string());
        return Err(format!(
            "Get User Delegation Key failed ({}): {}",
            status, body
        ));
    }

    let xml_body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read delegation key response: {}", e))?;

    debug!("User Delegation Key response: {}", xml_body);

    // Parse XML response manually (avoid adding xml crate dependency)
    let key = parse_user_delegation_key(&xml_body)?;
    Ok(key)
}

/// Parse the User Delegation Key XML response.
fn parse_user_delegation_key(xml: &str) -> Result<UserDelegationKey, String> {
    fn extract_xml_value(xml: &str, tag: &str) -> Result<String, String> {
        let open = format!("<{}>", tag);
        let close = format!("</{}>", tag);
        let start = xml
            .find(&open)
            .ok_or_else(|| format!("Missing <{}> in XML", tag))?
            + open.len();
        let end = xml
            .find(&close)
            .ok_or_else(|| format!("Missing </{}> in XML", tag))?;
        Ok(xml[start..end].trim().to_string())
    }

    Ok(UserDelegationKey {
        signed_oid: extract_xml_value(xml, "SignedOid")?,
        signed_tid: extract_xml_value(xml, "SignedTid")?,
        signed_start: extract_xml_value(xml, "SignedStart")?,
        signed_expiry: extract_xml_value(xml, "SignedExpiry")?,
        signed_service: extract_xml_value(xml, "SignedService")?,
        signed_version: extract_xml_value(xml, "SignedVersion")?,
        value: extract_xml_value(xml, "Value")?,
    })
}

// ─── SAS Token Construction ──────────────────────────────────────────────────

/// SAS permission strings matching Azure's spec
fn permissions_for_operation(operation: &str) -> &'static str {
    match operation {
        "read_write" => "racwdl",   // read, add, create, write, delete, list
        "write" => "acwd",          // add, create, write, delete
        _ => "rl",                  // read, list (default)
    }
}

/// Generate a **User Delegation SAS** token for Azure ADLS Gen2.
///
/// This follows the Azure REST API spec for creating a User Delegation SAS:
/// https://learn.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas
fn generate_user_delegation_sas(
    account_name: &str,
    container: &str,
    resource_path: &str,
    permissions: &str,
    start: &str,
    expiry: &str,
    delegation_key: &UserDelegationKey,
    scope: &str,
) -> Result<String, String> {
    // For container scope, canonicalized resource is just /blob/account/container
    // For directory scope, it includes the path
    let (canonicalized_resource, sr, depth) = if scope == "container" {
        (
            format!("/blob/{}/{}", account_name, container),
            "c",
            0,
        )
    } else {
        let path_trimmed = resource_path.trim_matches('/');
        let d = if path_trimmed.is_empty() { 0 } else { path_trimmed.split('/').count() };
        (
            format!("/blob/{}/{}/{}", account_name, container, path_trimmed),
            "d",
            d,
        )
    };

    // String-to-sign for User Delegation SAS (version 2020-12-06 and later)
    // https://learn.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas#version-2020-12-06-and-later
    //
    // IMPORTANT: sdd (signed directory depth) is a query parameter ONLY,
    // it does NOT appear in the string-to-sign.
    // The response headers (rscc, rscd, rsce, rscl, rsct) are each separate fields.
    let string_to_sign = [
        permissions,                         // 1.  signedPermissions (sp)
        start,                               // 2.  signedStart (st)
        expiry,                              // 3.  signedExpiry (se)
        &canonicalized_resource,             // 4.  canonicalizedResource
        &delegation_key.signed_oid,          // 5.  signedKeyObjectId (skoid)
        &delegation_key.signed_tid,          // 6.  signedKeyTenantId (sktid)
        &delegation_key.signed_start,        // 7.  signedKeyStart (skt)
        &delegation_key.signed_expiry,       // 8.  signedKeyExpiry (ske)
        &delegation_key.signed_service,      // 9.  signedKeyService (sks)
        &delegation_key.signed_version,      // 10. signedKeyVersion (skv)
        "",                                  // 11. signedAuthorizedUserObjectId (saoid)
        "",                                  // 12. signedUnauthorizedUserObjectId (suoid)
        "",                                  // 13. signedCorrelationId (scid)
        "",                                  // 14. signedIP (sip)
        "https",                             // 15. signedProtocol (spr)
        SAS_VERSION,                         // 16. signedVersion (sv)
        sr,                                  // 17. signedResource (sr)
        "",                                  // 18. signedSnapshotTime
        "",                                  // 19. signedEncryptionScope (ses)
        "",                                  // 20. rscc (Cache-Control)
        "",                                  // 21. rscd (Content-Disposition)
        "",                                  // 22. rsce (Content-Encoding)
        "",                                  // 23. rscl (Content-Language)
        "",                                  // 24. rsct (Content-Type)
    ].join("\n");

    debug!(
        "User Delegation SAS string-to-sign:\n{}",
        string_to_sign
    );

    // Sign with the delegation key
    let key_bytes = BASE64
        .decode(&delegation_key.value)
        .map_err(|e| format!("Failed to decode delegation key: {}", e))?;

    let mut mac = HmacSha256::new_from_slice(&key_bytes)
        .map_err(|e| format!("Failed to create HMAC: {}", e))?;
    mac.update(string_to_sign.as_bytes());
    let signature = BASE64.encode(mac.finalize().into_bytes());

    // Build SAS query string
    let sdd_part = if sr == "d" { format!("&sdd={}", depth) } else { String::new() };
    let sas_token = format!(
        "sv={}&sr={}&sp={}&st={}&se={}{}&spr=https&skoid={}&sktid={}&skt={}&ske={}&sks={}&skv={}&sig={}",
        urlencoding::encode(SAS_VERSION),
        sr,
        urlencoding::encode(permissions),
        urlencoding::encode(start),
        urlencoding::encode(expiry),
        sdd_part,
        urlencoding::encode(&delegation_key.signed_oid),
        urlencoding::encode(&delegation_key.signed_tid),
        urlencoding::encode(&delegation_key.signed_start),
        urlencoding::encode(&delegation_key.signed_expiry),
        urlencoding::encode(&delegation_key.signed_service),
        urlencoding::encode(&delegation_key.signed_version),
        urlencoding::encode(&signature),
    );

    Ok(sas_token)
}

/// Generate a **Service SAS** token using a storage account access key.
///
/// This is simpler than User Delegation SAS but requires the account key.
/// https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas
fn generate_service_sas(
    account_name: &str,
    container: &str,
    resource_path: &str,
    permissions: &str,
    start: &str,
    expiry: &str,
    account_key: &str,
) -> Result<String, String> {
    let canonicalized_resource = format!(
        "/blob/{}/{}/{}",
        account_name,
        container,
        resource_path.trim_start_matches('/').trim_end_matches('/')
    );

    let path_trimmed = resource_path.trim_matches('/');
    let depth = if path_trimmed.is_empty() {
        0
    } else {
        path_trimmed.split('/').count()
    };

    // String-to-sign for Service SAS (directory scope, sr=d)
    let string_to_sign = format!(
        "{}\n{}\n{}\n{}\n\n\n{}\nhttps\n{}\n{}\n{}\n\n\n\n\n",
        permissions,                         // sp
        start,                               // st
        expiry,                              // se
        canonicalized_resource,              // canonicalizedResource
        depth,                               // sdd
        SAS_VERSION,                         // sv
        "d",                                 // sr (directory)
        depth,                               // sdd (again for newer versions)
    );

    debug!("Service SAS string-to-sign:\n{}", string_to_sign);

    // Sign with the account key
    let key_bytes = BASE64
        .decode(account_key)
        .map_err(|e| format!("Failed to decode account key: {}", e))?;

    let mut mac = HmacSha256::new_from_slice(&key_bytes)
        .map_err(|e| format!("Failed to create HMAC: {}", e))?;
    mac.update(string_to_sign.as_bytes());
    let signature = BASE64.encode(mac.finalize().into_bytes());

    let sas_token = format!(
        "sv={}&sr=d&sp={}&st={}&se={}&sdd={}&spr=https&sig={}",
        urlencoding::encode(SAS_VERSION),
        urlencoding::encode(permissions),
        urlencoding::encode(start),
        urlencoding::encode(expiry),
        depth,
        urlencoding::encode(&signature),
    );

    Ok(sas_token)
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Parameters needed to generate a SAS token for Azure ADLS.
pub struct AzureSasParams {
    pub account_name: String,
    pub container: String,
    pub resource_path: String,
    pub operation: String,
    pub ttl_seconds: u64,
    /// SAS scope: "directory" (sr=d) or "container" (sr=c)
    pub scope: String,
    /// Service Principal credentials (for User Delegation SAS)
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    /// Storage Account access key (for Service SAS)
    pub access_key: Option<String>,
}

/// Generate a scoped SAS token for Azure ADLS Gen2.
///
/// Chooses the best method based on available credentials:
/// 1. User Delegation SAS (if Service Principal credentials are available) — most secure
/// 2. Service SAS (if access key is available) — simpler, no Azure AD calls
pub async fn generate_sas_token(params: AzureSasParams) -> Result<VendCredentialsResponse, String> {
    let ttl = params.ttl_seconds.min(MAX_TTL_SECONDS).max(60);
    let now = Utc::now();
    // Start 5 minutes ago to account for clock skew (same as Polaris)
    let start = now - Duration::minutes(5);
    let expiry = now + Duration::seconds(ttl as i64);

    let start_str = start.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let expiry_str = expiry.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let permissions = permissions_for_operation(&params.operation);

    let sas_token = if let (Some(tenant_id), Some(client_id), Some(client_secret)) =
        (&params.tenant_id, &params.client_id, &params.client_secret)
    {
        // Path 1: User Delegation SAS (preferred, most secure)
        info!(
            account = %params.account_name,
            container = %params.container,
            path = %params.resource_path,
            operation = %params.operation,
            ttl_seconds = ttl,
            "Generating User Delegation SAS token"
        );

        let access_token = get_azure_ad_token(tenant_id, client_id, client_secret).await?;
        debug!("Acquired Azure AD token for SAS generation");

        let delegation_key = get_user_delegation_key(
            &params.account_name,
            &access_token,
            &start_str,
            &expiry_str,
        )
        .await?;
        debug!("Acquired User Delegation Key");

        generate_user_delegation_sas(
            &params.account_name,
            &params.container,
            &params.resource_path,
            permissions,
            &start_str,
            &expiry_str,
            &delegation_key,
            &params.scope,
        )?
    } else if let Some(access_key) = &params.access_key {
        // Path 2: Service SAS (fallback)
        info!(
            account = %params.account_name,
            container = %params.container,
            path = %params.resource_path,
            operation = %params.operation,
            ttl_seconds = ttl,
            "Generating Service SAS token (using account key)"
        );

        generate_service_sas(
            &params.account_name,
            &params.container,
            &params.resource_path,
            permissions,
            &start_str,
            &expiry_str,
            access_key,
        )?
    } else {
        return Err("No credentials available for SAS generation. Need either Service Principal (tenant_id, client_id, client_secret) or storage account access key.".to_string());
    };

    let signed_uri = format!(
        "abfss://{}@{}.dfs.core.windows.net/{}?{}",
        params.container,
        params.account_name,
        params.resource_path.trim_start_matches('/'),
        sas_token
    );

    Ok(VendCredentialsResponse {
        sas_token,
        signed_uri,
        expires_at: expiry_str,
        expires_at_ms: expiry.timestamp_millis(),
        account_name: params.account_name,
        container: params.container,
        resource_path: params.resource_path,
        effective_permission: None, // Set by the handler after permission check
    })
}
