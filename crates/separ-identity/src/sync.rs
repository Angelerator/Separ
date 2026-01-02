//! Sync Orchestrator - coordinates identity sync across providers
//!
//! The orchestrator:
//! - Manages sync schedules for all providers
//! - Handles incremental and full syncs
//! - Updates Separ's user/group repositories
//! - Maintains SpiceDB relationships

use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, instrument};

use separ_core::{
    identity::*, AuthorizationService, Group, GroupId, GroupRepository, IdentityProviderId,
    Relationship, Resource, Result, SeparError, Subject, SubjectType, TenantId, User, UserId,
    UserRepository, UserStatus,
};

use crate::registry::ProviderRegistry;

/// Sync state tracking per provider
#[derive(Debug, Clone)]
pub struct SyncState {
    pub provider_id: IdentityProviderId,
    pub last_full_sync: Option<DateTime<Utc>>,
    pub last_incremental_sync: Option<DateTime<Utc>>,
    pub last_sync_result: Option<SyncResult>,
}

/// Sync orchestrator coordinates syncing across all identity providers
pub struct SyncOrchestrator<U, G, A>
where
    U: UserRepository,
    G: GroupRepository,
    A: AuthorizationService,
{
    registry: Arc<ProviderRegistry>,
    user_repo: Arc<U>,
    group_repo: Arc<G>,
    auth_service: Arc<A>,
    identity_mapping: Arc<dyn IdentityMappingRepository>,
    sync_states: RwLock<std::collections::HashMap<IdentityProviderId, SyncState>>,
}

impl<U, G, A> SyncOrchestrator<U, G, A>
where
    U: UserRepository + 'static,
    G: GroupRepository + 'static,
    A: AuthorizationService + 'static,
{
    /// Create a new sync orchestrator
    pub fn new(
        registry: Arc<ProviderRegistry>,
        user_repo: Arc<U>,
        group_repo: Arc<G>,
        auth_service: Arc<A>,
        identity_mapping: Arc<dyn IdentityMappingRepository>,
    ) -> Self {
        Self {
            registry,
            user_repo,
            group_repo,
            auth_service,
            identity_mapping,
            sync_states: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Sync a specific provider
    #[instrument(skip(self))]
    pub async fn sync_provider(
        &self,
        provider_id: IdentityProviderId,
        full_sync: bool,
    ) -> Result<SyncResult> {
        let started_at = Utc::now();
        info!(
            "Starting {} sync for provider {}",
            if full_sync { "full" } else { "incremental" },
            provider_id
        );

        let provider = self
            .registry
            .get_sync_provider(provider_id)
            .await
            .ok_or_else(|| SeparError::not_found("identity_provider", provider_id.to_string()))?;

        let tenant_id = {
            let configs = self.registry.get_configs_for_tenant(TenantId::new()).await; // This needs proper tenant lookup
            configs
                .iter()
                .find(|c| c.id == provider_id)
                .map(|c| c.tenant_id)
                .ok_or_else(|| SeparError::not_found("provider_config", provider_id.to_string()))?
        };

        // Get last sync time for incremental
        let last_sync = if !full_sync {
            self.sync_states
                .read()
                .await
                .get(&provider_id)
                .and_then(|s| s.last_incremental_sync)
        } else {
            None
        };

        let mut result = SyncResult {
            provider_id,
            provider_type: provider.provider_type(),
            status: SyncResultStatus::Success,
            users_created: 0,
            users_updated: 0,
            users_deleted: 0,
            groups_created: 0,
            groups_updated: 0,
            groups_deleted: 0,
            apps_created: 0,
            apps_updated: 0,
            apps_deleted: 0,
            errors: vec![],
            started_at,
            completed_at: Utc::now(),
            duration_ms: 0,
        };

        // Sync users
        let synced_users = if full_sync || last_sync.is_none() {
            provider.sync_users().await
        } else {
            provider.sync_users_incremental(last_sync.unwrap()).await
        };

        match synced_users {
            Ok(users) => {
                for user in users {
                    match self.upsert_user(tenant_id, provider_id, &user).await {
                        Ok(created) => {
                            if created {
                                result.users_created += 1;
                            } else {
                                result.users_updated += 1;
                            }
                        }
                        Err(e) => {
                            result.errors.push(SyncError {
                                entity_type: "user".to_string(),
                                external_id: Some(user.external_id.clone()),
                                error_type: "upsert_failed".to_string(),
                                message: e.to_string(),
                                timestamp: Utc::now(),
                            });
                        }
                    }
                }
            }
            Err(e) => {
                result.errors.push(SyncError {
                    entity_type: "users".to_string(),
                    external_id: None,
                    error_type: "sync_failed".to_string(),
                    message: e.to_string(),
                    timestamp: Utc::now(),
                });
                result.status = SyncResultStatus::PartialSuccess;
            }
        }

        // Sync groups
        let synced_groups = if full_sync || last_sync.is_none() {
            provider.sync_groups().await
        } else {
            provider.sync_groups_incremental(last_sync.unwrap()).await
        };

        match synced_groups {
            Ok(groups) => {
                for group in groups {
                    match self.upsert_group(tenant_id, provider_id, &group).await {
                        Ok(created) => {
                            if created {
                                result.groups_created += 1;
                            } else {
                                result.groups_updated += 1;
                            }
                        }
                        Err(e) => {
                            result.errors.push(SyncError {
                                entity_type: "group".to_string(),
                                external_id: Some(group.external_id.clone()),
                                error_type: "upsert_failed".to_string(),
                                message: e.to_string(),
                                timestamp: Utc::now(),
                            });
                        }
                    }
                }
            }
            Err(e) => {
                result.errors.push(SyncError {
                    entity_type: "groups".to_string(),
                    external_id: None,
                    error_type: "sync_failed".to_string(),
                    message: e.to_string(),
                    timestamp: Utc::now(),
                });
                result.status = SyncResultStatus::PartialSuccess;
            }
        }

        // Update completion time
        result.completed_at = Utc::now();
        result.duration_ms = (result.completed_at - result.started_at).num_milliseconds() as u64;

        // Update status
        if !result.errors.is_empty()
            && result.users_created
                + result.users_updated
                + result.groups_created
                + result.groups_updated
                == 0
        {
            result.status = SyncResultStatus::Failed;
        }

        // Update sync state
        {
            let mut states = self.sync_states.write().await;
            let state = states.entry(provider_id).or_insert_with(|| SyncState {
                provider_id,
                last_full_sync: None,
                last_incremental_sync: None,
                last_sync_result: None,
            });

            if full_sync {
                state.last_full_sync = Some(Utc::now());
            }
            state.last_incremental_sync = Some(Utc::now());
            state.last_sync_result = Some(result.clone());
        }

        info!(
            "Sync completed: {} users created, {} updated; {} groups created, {} updated; {} errors",
            result.users_created,
            result.users_updated,
            result.groups_created,
            result.groups_updated,
            result.errors.len()
        );

        Ok(result)
    }

    /// Sync all providers for a tenant
    #[instrument(skip(self))]
    pub async fn sync_tenant(
        &self,
        tenant_id: TenantId,
        full_sync: bool,
    ) -> Result<Vec<SyncResult>> {
        info!("Starting sync for tenant {}", tenant_id);

        let providers = self.registry.get_sync_providers_for_tenant(tenant_id).await;
        let mut results = Vec::with_capacity(providers.len());

        for provider in providers {
            match self.sync_provider(provider.provider_id(), full_sync).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    error!("Failed to sync provider {}: {}", provider.provider_id(), e);
                    results.push(SyncResult {
                        provider_id: provider.provider_id(),
                        provider_type: provider.provider_type(),
                        status: SyncResultStatus::Failed,
                        users_created: 0,
                        users_updated: 0,
                        users_deleted: 0,
                        groups_created: 0,
                        groups_updated: 0,
                        groups_deleted: 0,
                        apps_created: 0,
                        apps_updated: 0,
                        apps_deleted: 0,
                        errors: vec![SyncError {
                            entity_type: "provider".to_string(),
                            external_id: None,
                            error_type: "sync_failed".to_string(),
                            message: e.to_string(),
                            timestamp: Utc::now(),
                        }],
                        started_at: Utc::now(),
                        completed_at: Utc::now(),
                        duration_ms: 0,
                    });
                }
            }
        }

        Ok(results)
    }

    /// Upsert a synced user
    async fn upsert_user(
        &self,
        tenant_id: TenantId,
        provider_id: IdentityProviderId,
        synced_user: &SyncedUser,
    ) -> Result<bool> {
        // Check if user already exists by external ID
        let existing = self
            .identity_mapping
            .get_user_by_external_id(tenant_id, provider_id, &synced_user.external_id)
            .await?;

        let (user_id, created) = if let Some(id) = existing {
            // Update existing user
            if let Some(mut user) = self.user_repo.get_by_id(id).await? {
                user.email = synced_user.email.clone();
                user.display_name = synced_user.display_name.clone();
                user.given_name = synced_user.given_name.clone();
                user.family_name = synced_user.family_name.clone();
                user.picture_url = synced_user.picture_url.clone();
                user.status = if synced_user.active {
                    UserStatus::Active
                } else {
                    UserStatus::Inactive
                };
                user.email_verified = synced_user.email_verified;
                user.updated_at = Utc::now();

                self.user_repo.update(&user).await?;
            }
            (id, false)
        } else {
            // Create new user
            let user = User {
                id: UserId::new(),
                tenant_id,
                external_id: Some(synced_user.external_id.clone()),
                email: synced_user.email.clone(),
                email_verified: synced_user.email_verified,
                display_name: synced_user.display_name.clone(),
                given_name: synced_user.given_name.clone(),
                family_name: synced_user.family_name.clone(),
                picture_url: synced_user.picture_url.clone(),
                locale: None,
                timezone: None,
                status: if synced_user.active {
                    UserStatus::Active
                } else {
                    UserStatus::Inactive
                },
                metadata: synced_user.attributes.clone(),
                last_login_at: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let created_user = self.user_repo.create(&user).await?;

            // Create mapping
            self.identity_mapping
                .upsert_user_mapping(
                    tenant_id,
                    provider_id,
                    &synced_user.external_id,
                    created_user.id,
                )
                .await?;

            // Create SpiceDB relationship
            self.auth_service
                .write_relationship(&Relationship {
                    resource: Resource {
                        resource_type: "user".to_string(),
                        id: created_user.id.to_string(),
                    },
                    relation: "tenant".to_string(),
                    subject: Subject {
                        subject_type: SubjectType::User,
                        id: tenant_id.to_string(),
                        relation: None,
                    },
                    caveat: None,
                })
                .await?;

            (created_user.id, true)
        };

        // Sync group memberships
        for group_external_id in &synced_user.groups {
            if let Some(group_id) = self
                .identity_mapping
                .get_group_by_external_id(tenant_id, provider_id, group_external_id)
                .await?
            {
                // Add user to group in SpiceDB
                self.auth_service
                    .write_relationship(&Relationship {
                        resource: Resource {
                            resource_type: "group".to_string(),
                            id: group_id.to_string(),
                        },
                        relation: "member".to_string(),
                        subject: Subject {
                            subject_type: SubjectType::User,
                            id: user_id.to_string(),
                            relation: None,
                        },
                        caveat: None,
                    })
                    .await?;
            }
        }

        Ok(created)
    }

    /// Upsert a synced group
    async fn upsert_group(
        &self,
        tenant_id: TenantId,
        provider_id: IdentityProviderId,
        synced_group: &SyncedGroup,
    ) -> Result<bool> {
        // Check if group already exists by external ID
        let existing = self
            .identity_mapping
            .get_group_by_external_id(tenant_id, provider_id, &synced_group.external_id)
            .await?;

        let (group_id, created) = if let Some(id) = existing {
            // Update existing group
            if let Some(mut group) = self.group_repo.get_by_id(id).await? {
                group.name = synced_group.name.clone();
                group.description = synced_group.description.clone();
                group.updated_at = Utc::now();

                self.group_repo.update(&group).await?;
            }
            (id, false)
        } else {
            // Create new group
            let group = Group {
                id: GroupId::new(),
                tenant_id,
                name: synced_group.name.clone(),
                description: synced_group.description.clone(),
                external_id: Some(synced_group.external_id.clone()),
                metadata: synced_group.attributes.clone(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let created_group = self.group_repo.create(&group).await?;

            // Create mapping
            self.identity_mapping
                .upsert_group_mapping(
                    tenant_id,
                    provider_id,
                    &synced_group.external_id,
                    created_group.id,
                )
                .await?;

            // Create SpiceDB relationship
            self.auth_service
                .write_relationship(&Relationship {
                    resource: Resource {
                        resource_type: "group".to_string(),
                        id: created_group.id.to_string(),
                    },
                    relation: "tenant".to_string(),
                    subject: Subject {
                        subject_type: SubjectType::User,
                        id: tenant_id.to_string(),
                        relation: None,
                    },
                    caveat: None,
                })
                .await?;

            (created_group.id, true)
        };

        // Sync nested group relationships
        for child_group_external_id in &synced_group.child_groups {
            if let Some(child_group_id) = self
                .identity_mapping
                .get_group_by_external_id(tenant_id, provider_id, child_group_external_id)
                .await?
            {
                // Add nested group relationship
                self.auth_service
                    .write_relationship(&Relationship {
                        resource: Resource {
                            resource_type: "group".to_string(),
                            id: group_id.to_string(),
                        },
                        relation: "member".to_string(),
                        subject: Subject {
                            subject_type: SubjectType::Group,
                            id: child_group_id.to_string(),
                            relation: Some("member".to_string()),
                        },
                        caveat: None,
                    })
                    .await?;
            }
        }

        Ok(created)
    }

    /// Get sync state for a provider
    pub async fn get_sync_state(&self, provider_id: IdentityProviderId) -> Option<SyncState> {
        self.sync_states.read().await.get(&provider_id).cloned()
    }

    /// Get all sync states
    pub async fn get_all_sync_states(&self) -> Vec<SyncState> {
        self.sync_states.read().await.values().cloned().collect()
    }

    /// JIT (Just-In-Time) provision a user from an authenticated principal
    #[instrument(skip(self, principal))]
    pub async fn jit_provision_user(&self, principal: &AuthenticatedPrincipal) -> Result<UserId> {
        info!(
            "JIT provisioning user: {} from provider {}",
            principal.subject, principal.provider_id
        );

        // Check if user already exists
        if let Some(user_id) = self
            .identity_mapping
            .get_user_by_external_id(
                principal.tenant_id,
                principal.provider_id,
                &principal.subject,
            )
            .await?
        {
            // Update last login
            if let Some(mut user) = self.user_repo.get_by_id(user_id).await? {
                user.last_login_at = Some(Utc::now());
                user.updated_at = Utc::now();
                self.user_repo.update(&user).await?;
            }
            return Ok(user_id);
        }

        // Create new user
        let user = User {
            id: UserId::new(),
            tenant_id: principal.tenant_id,
            external_id: Some(principal.subject.clone()),
            email: principal.email.clone().unwrap_or_default(),
            email_verified: true,
            display_name: principal.display_name.clone().unwrap_or_default(),
            given_name: None,
            family_name: None,
            picture_url: None,
            locale: None,
            timezone: None,
            status: UserStatus::Active,
            metadata: std::collections::HashMap::new(),
            last_login_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let created_user = self.user_repo.create(&user).await?;

        // Create mapping
        self.identity_mapping
            .upsert_user_mapping(
                principal.tenant_id,
                principal.provider_id,
                &principal.subject,
                created_user.id,
            )
            .await?;

        // Create SpiceDB relationships
        self.auth_service
            .write_relationship(&Relationship {
                resource: Resource {
                    resource_type: "user".to_string(),
                    id: created_user.id.to_string(),
                },
                relation: "tenant".to_string(),
                subject: Subject {
                    subject_type: SubjectType::User,
                    id: principal.tenant_id.to_string(),
                    relation: None,
                },
                caveat: None,
            })
            .await?;

        info!(
            "JIT provisioned user: {} as {}",
            principal.subject, created_user.id
        );

        Ok(created_user.id)
    }
}
