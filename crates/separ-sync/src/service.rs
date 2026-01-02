//! Sync orchestration service

use std::sync::Arc;
use tracing::{error, info, instrument};

use separ_core::{
    AuthorizationService, GroupRepository, Result, SeparError, SyncConfig, SyncConfigDetails,
    SyncConfigRepository, SyncStatus, SyncType, TenantId, UserRepository,
};

/// Sync orchestration service
pub struct SyncOrchestrator<U, G, A, S>
where
    U: UserRepository,
    G: GroupRepository,
    A: AuthorizationService,
    S: SyncConfigRepository,
{
    user_repo: Arc<U>,
    group_repo: Arc<G>,
    auth_service: Arc<A>,
    sync_config_repo: Arc<S>,
}

impl<U, G, A, S> SyncOrchestrator<U, G, A, S>
where
    U: UserRepository + 'static,
    G: GroupRepository + 'static,
    A: AuthorizationService + 'static,
    S: SyncConfigRepository + 'static,
{
    pub fn new(
        user_repo: Arc<U>,
        group_repo: Arc<G>,
        auth_service: Arc<A>,
        sync_config_repo: Arc<S>,
    ) -> Self {
        Self {
            user_repo,
            group_repo,
            auth_service,
            sync_config_repo,
        }
    }

    /// Trigger a sync for a specific configuration
    #[instrument(skip(self))]
    pub async fn trigger_sync(&self, config_id: separ_core::SyncConfigId) -> Result<SyncResult> {
        let config = self
            .sync_config_repo
            .get_by_id(config_id)
            .await?
            .ok_or_else(|| SeparError::not_found("sync_config", config_id.to_string()))?;

        if !config.enabled {
            return Err(SeparError::invalid_input("Sync configuration is disabled"));
        }

        info!(
            "Starting sync for config {} (type: {:?})",
            config.name, config.sync_type
        );

        let result = match config.sync_type {
            SyncType::Scim => {
                // SCIM syncs are push-based, so this is a no-op
                SyncResult {
                    status: SyncStatus::Success,
                    users_synced: 0,
                    groups_synced: 0,
                    errors: vec![],
                }
            }
            SyncType::Webhook => {
                // Webhooks are push-based
                SyncResult {
                    status: SyncStatus::Success,
                    users_synced: 0,
                    groups_synced: 0,
                    errors: vec![],
                }
            }
            SyncType::LdapPull => self.sync_ldap(&config).await?,
            SyncType::ApiPull => self.sync_api(&config).await?,
        };

        // Update sync status
        let mut updated_config = config.clone();
        updated_config.last_sync_at = Some(chrono::Utc::now());
        updated_config.last_sync_status = Some(result.status);
        updated_config.updated_at = chrono::Utc::now();
        self.sync_config_repo.update(&updated_config).await?;

        info!("Sync completed: {:?}", result);
        Ok(result)
    }

    /// Sync from LDAP
    async fn sync_ldap(&self, config: &SyncConfig) -> Result<SyncResult> {
        let SyncConfigDetails::LdapPull { server_url, .. } = &config.config else {
            return Err(SeparError::invalid_input("Invalid LDAP config"));
        };

        info!("Syncing from LDAP server: {}", server_url);

        // In a real implementation, we would:
        // 1. Connect to LDAP server
        // 2. Query users matching user_filter
        // 3. Query groups matching group_filter
        // 4. Sync users and groups to our database
        // 5. Update SpiceDB relationships

        // Placeholder implementation
        Ok(SyncResult {
            status: SyncStatus::Success,
            users_synced: 0,
            groups_synced: 0,
            errors: vec![],
        })
    }

    /// Sync from external API
    async fn sync_api(&self, config: &SyncConfig) -> Result<SyncResult> {
        let SyncConfigDetails::ApiPull { endpoint_url, .. } = &config.config else {
            return Err(SeparError::invalid_input("Invalid API config"));
        };

        info!("Syncing from API: {}", endpoint_url);

        // In a real implementation, we would:
        // 1. Make authenticated request to the endpoint
        // 2. Parse user/group data
        // 3. Sync to our database
        // 4. Update SpiceDB relationships

        // Placeholder implementation
        Ok(SyncResult {
            status: SyncStatus::Success,
            users_synced: 0,
            groups_synced: 0,
            errors: vec![],
        })
    }

    /// Run scheduled syncs for all enabled configurations
    #[instrument(skip(self))]
    pub async fn run_scheduled_syncs(&self, tenant_id: TenantId) -> Result<Vec<SyncResult>> {
        let configs = self.sync_config_repo.list_by_tenant(tenant_id).await?;
        let mut results = Vec::new();

        for config in configs {
            if !config.enabled {
                continue;
            }

            // Check if it's time to sync based on interval
            let should_sync = match &config.config {
                SyncConfigDetails::LdapPull {
                    sync_interval_secs, ..
                }
                | SyncConfigDetails::ApiPull {
                    sync_interval_secs, ..
                } => match config.last_sync_at {
                    Some(last_sync) => {
                        let elapsed = chrono::Utc::now() - last_sync;
                        elapsed.num_seconds() as u32 >= *sync_interval_secs
                    }
                    None => true,
                },
                _ => false, // SCIM and Webhook are push-based
            };

            if should_sync {
                match self.trigger_sync(config.id).await {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        error!("Failed to sync config {}: {}", config.id, e);
                        results.push(SyncResult {
                            status: SyncStatus::Failed,
                            users_synced: 0,
                            groups_synced: 0,
                            errors: vec![e.to_string()],
                        });
                    }
                }
            }
        }

        Ok(results)
    }
}

/// Result of a sync operation
#[derive(Debug, Clone)]
pub struct SyncResult {
    pub status: SyncStatus,
    pub users_synced: u32,
    pub groups_synced: u32,
    pub errors: Vec<String>,
}
