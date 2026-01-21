//! Audit repository implementation
//!
//! Security audit logging for:
//! - Authentication events (login, logout, failed attempts)
//! - Authorization decisions (permission checks)
//! - API key usage
//! - Administrative actions
//! - Privilege escalation attempts

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use tracing::{info, instrument, warn};

use separ_core::{
    AuditEvent, AuditEventType, AuditFilter, AuditRepository, Result, SeparError,
    TenantId,
};

/// PostgreSQL implementation of AuditRepository
pub struct PgAuditRepository {
    pool: PgPool,
}

impl PgAuditRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditRepository for PgAuditRepository {
    /// Log an audit event
    /// 
    /// Security-critical events are logged with additional context
    #[instrument(skip(self, event), fields(event_type = ?event.event_type, actor_id = %event.actor.id))]
    async fn log(&self, event: &AuditEvent) -> Result<()> {
        // Log security-critical events at warn level for visibility
        match event.event_type {
            AuditEventType::UserLoginFailed
            | AuditEventType::PrivilegeEscalation
            | AuditEventType::SuspiciousActivity
            | AuditEventType::ApiKeyRateLimited => {
                warn!(
                    event_type = ?event.event_type,
                    actor = %event.actor.id,
                    ip = ?event.ip_address,
                    result = ?event.result,
                    "Security audit event"
                );
            }
            _ => {
                info!(
                    event_type = ?event.event_type,
                    actor = %event.actor.id,
                    "Audit event logged"
                );
            }
        }

        let metadata_json = serde_json::to_value(&event.metadata).unwrap_or_default();
        let resource_type = event.resource.as_ref().map(|r| r.resource_type.clone());
        let resource_id = event.resource.as_ref().map(|r| r.id.clone());
        let event_type_str = format!("{:?}", event.event_type).to_lowercase();
        let result_str = format!("{:?}", event.result).to_lowercase();
        let actor_type_str = format!("{:?}", event.actor.actor_type).to_lowercase();

        sqlx::query(
            r#"
            INSERT INTO audit_events (
                id, tenant_id, event_type, actor_type, actor_id, actor_name,
                resource_type, resource_id, action, result,
                metadata, ip_address, user_agent, created_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
            )
            "#,
        )
        .bind(event.id.as_uuid())
        .bind(event.tenant_id.as_uuid())
        .bind(&event_type_str)
        .bind(&actor_type_str)
        .bind(&event.actor.id)
        .bind(&event.actor.display_name)
        .bind(&resource_type)
        .bind(&resource_id)
        .bind(&event.action)
        .bind(&result_str)
        .bind(&metadata_json)
        .bind(&event.ip_address)
        .bind(&event.user_agent)
        .bind(&event.timestamp)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            // Don't fail the main operation if audit logging fails
            // but log it for observability
            warn!(error = %e, "Failed to persist audit event");
            SeparError::database_error(e.to_string())
        })?;

        Ok(())
    }

    /// Query audit events with filtering
    #[instrument(skip(self))]
    async fn query(
        &self,
        tenant_id: TenantId,
        filter: &AuditFilter,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<AuditEvent>> {
        // Build query with optional filters
        let mut query = String::from(
            r#"
            SELECT id, tenant_id, event_type, actor_type, actor_id, actor_name,
                   resource_type, resource_id, action, result,
                   metadata, ip_address, user_agent, created_at
            FROM audit_events
            WHERE tenant_id = $1
            "#,
        );

        let mut bind_idx = 2;

        if let Some(ref event_types) = filter.event_types {
            if !event_types.is_empty() {
                query.push_str(&format!(" AND event_type = ANY(${}) ", bind_idx));
                bind_idx += 1;
            }
            let _ = event_types; // Used in binding below
        }

        if let Some(ref actor_id) = filter.actor_id {
            query.push_str(&format!(" AND actor_id = ${}", bind_idx));
            bind_idx += 1;
            let _ = actor_id;
        }

        if let Some(ref from_timestamp) = filter.from_timestamp {
            query.push_str(&format!(" AND created_at >= ${}", bind_idx));
            bind_idx += 1;
            let _ = from_timestamp;
        }

        if let Some(ref to_timestamp) = filter.to_timestamp {
            query.push_str(&format!(" AND created_at <= ${}", bind_idx));
            let _ = to_timestamp;
        }

        query.push_str(" ORDER BY created_at DESC LIMIT $L OFFSET $O");
        
        // For now, return empty - full implementation would build the query dynamically
        // This is a placeholder showing the structure
        let _ = (tenant_id, offset, limit, query);
        
        Ok(vec![])
    }
}

/// Helper to create audit events quickly
pub mod audit_helpers {
    use chrono::Utc;
    use separ_core::{
        AuditActor, AuditEvent, AuditEventId, AuditEventType, AuditResult, SubjectType, TenantId,
    };
    use std::collections::HashMap;

    /// Create a login success audit event
    pub fn login_success(
        tenant_id: TenantId,
        user_id: &str,
        user_name: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> AuditEvent {
        AuditEvent {
            id: AuditEventId::new(),
            tenant_id,
            event_type: AuditEventType::UserLogin,
            actor: AuditActor {
                actor_type: SubjectType::User,
                id: user_id.to_string(),
                display_name: user_name.map(String::from),
            },
            resource: None,
            action: "login".to_string(),
            result: AuditResult::Success,
            metadata: HashMap::new(),
            ip_address: ip_address.map(String::from),
            user_agent: user_agent.map(String::from),
            timestamp: Utc::now(),
        }
    }

    /// Create a login failed audit event
    pub fn login_failed(
        tenant_id: TenantId,
        email: &str,
        reason: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> AuditEvent {
        let mut metadata = HashMap::new();
        metadata.insert("reason".to_string(), serde_json::json!(reason));
        metadata.insert("email".to_string(), serde_json::json!(email));

        AuditEvent {
            id: AuditEventId::new(),
            tenant_id,
            event_type: AuditEventType::UserLoginFailed,
            actor: AuditActor {
                actor_type: SubjectType::Anonymous,
                id: "unknown".to_string(),
                display_name: Some(email.to_string()),
            },
            resource: None,
            action: "login_attempt".to_string(),
            result: AuditResult::Denied,
            metadata,
            ip_address: ip_address.map(String::from),
            user_agent: user_agent.map(String::from),
            timestamp: Utc::now(),
        }
    }

    /// Create an API key usage audit event
    pub fn api_key_used(
        tenant_id: TenantId,
        key_id: &str,
        key_name: &str,
        action: &str,
        ip_address: Option<&str>,
    ) -> AuditEvent {
        AuditEvent {
            id: AuditEventId::new(),
            tenant_id,
            event_type: AuditEventType::ApiKeyUsed,
            actor: AuditActor {
                actor_type: SubjectType::ServiceAccount,
                id: key_id.to_string(),
                display_name: Some(key_name.to_string()),
            },
            resource: None,
            action: action.to_string(),
            result: AuditResult::Success,
            metadata: HashMap::new(),
            ip_address: ip_address.map(String::from),
            user_agent: None,
            timestamp: Utc::now(),
        }
    }

    /// Create an API key rate limited audit event
    pub fn api_key_rate_limited(
        tenant_id: TenantId,
        key_id: &str,
        key_name: &str,
        limit: i32,
        ip_address: Option<&str>,
    ) -> AuditEvent {
        let mut metadata = HashMap::new();
        metadata.insert("rate_limit".to_string(), serde_json::json!(limit));

        AuditEvent {
            id: AuditEventId::new(),
            tenant_id,
            event_type: AuditEventType::ApiKeyRateLimited,
            actor: AuditActor {
                actor_type: SubjectType::ServiceAccount,
                id: key_id.to_string(),
                display_name: Some(key_name.to_string()),
            },
            resource: None,
            action: "rate_limited".to_string(),
            result: AuditResult::Denied,
            metadata,
            ip_address: ip_address.map(String::from),
            user_agent: None,
            timestamp: Utc::now(),
        }
    }

    /// Create an admin action audit event
    pub fn admin_action(
        tenant_id: TenantId,
        admin_id: &str,
        admin_name: Option<&str>,
        action: &str,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
        ip_address: Option<&str>,
    ) -> AuditEvent {
        let mut metadata = HashMap::new();
        if let Some(rt) = resource_type {
            metadata.insert("resource_type".to_string(), serde_json::json!(rt));
        }
        if let Some(ri) = resource_id {
            metadata.insert("resource_id".to_string(), serde_json::json!(ri));
        }

        AuditEvent {
            id: AuditEventId::new(),
            tenant_id,
            event_type: AuditEventType::AdminAction,
            actor: AuditActor {
                actor_type: SubjectType::User,
                id: admin_id.to_string(),
                display_name: admin_name.map(String::from),
            },
            resource: None,
            action: action.to_string(),
            result: AuditResult::Success,
            metadata,
            ip_address: ip_address.map(String::from),
            user_agent: None,
            timestamp: Utc::now(),
        }
    }
}
