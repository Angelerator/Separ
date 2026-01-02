//! LDAP / Active Directory provider implementation
//!
//! This provider supports:
//! - User sync via LDAP queries
//! - Group sync with membership resolution
//! - LDAP bind authentication
//!
//! Requires the `ldap` feature to be enabled.

#[cfg(feature = "ldap")]
use ldap3::{LdapConnAsync, Scope, SearchEntry};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};

use separ_core::{identity::*, IdentityProviderId, Result, SeparError, TenantId};

/// LDAP / Active Directory Identity Provider
pub struct LdapProvider {
    config: LdapConfig,
    provider_id: IdentityProviderId,
    tenant_id: TenantId,
    features: ProviderFeatures,
}

impl LdapProvider {
    /// Create a new LDAP provider instance
    pub fn new(provider_config: &IdentityProviderConfig) -> Result<Self> {
        let config = match &provider_config.config {
            ProviderConfigDetails::Ldap(c) => c.clone(),
            _ => {
                return Err(SeparError::InvalidInput {
                    message: "Expected LDAP configuration".to_string(),
                })
            }
        };

        Ok(Self {
            config,
            provider_id: provider_config.id,
            tenant_id: provider_config.tenant_id,
            features: provider_config.features.clone(),
        })
    }

    #[cfg(feature = "ldap")]
    async fn connect(&self) -> Result<ldap3::Ldap> {
        use ldap3::LdapConnSettings;

        let settings = LdapConnSettings::new().set_starttls(self.config.start_tls);

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.config.server_url)
            .await
            .map_err(|e| SeparError::Internal {
                message: format!("LDAP connection failed: {}", e),
            })?;

        ldap3::drive!(conn);

        // Bind with service account
        ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password)
            .await
            .map_err(|e| SeparError::AuthError {
                message: format!("LDAP bind failed: {}", e),
            })?;

        Ok(ldap)
    }
}

#[async_trait]
impl IdentitySync for LdapProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Ldap
    }

    fn provider_id(&self) -> IdentityProviderId {
        self.provider_id
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn sync_users(&self) -> Result<Vec<SyncedUser>> {
        info!("Starting full user sync from LDAP");

        #[cfg(feature = "ldap")]
        {
            let mut ldap = self.connect().await?;
            let mappings = &self.config.attribute_mappings;

            let (rs, _result) = ldap
                .search(
                    &self.config.user_base_dn,
                    Scope::Subtree,
                    &self.config.user_filter,
                    vec!["*"],
                )
                .await
                .map_err(|e| SeparError::Internal {
                    message: format!("LDAP search failed: {}", e),
                })?
                .success()
                .map_err(|e| SeparError::Internal {
                    message: format!("LDAP search failed: {}", e),
                })?;

            let users = rs
                .into_iter()
                .filter_map(|entry| {
                    let se = SearchEntry::construct(entry);
                    self.ldap_entry_to_user(&se, mappings)
                })
                .collect();

            ldap.unbind().await.ok();

            info!("Fetched {} users from LDAP", users.len());
            Ok(users)
        }

        #[cfg(not(feature = "ldap"))]
        {
            Err(SeparError::ConfigError {
                message: "LDAP support not enabled. Compile with --features ldap".to_string(),
            })
        }
    }

    async fn sync_users_incremental(&self, _since: DateTime<Utc>) -> Result<Vec<SyncedUser>> {
        // LDAP doesn't have good incremental sync support
        self.sync_users().await
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn sync_groups(&self) -> Result<Vec<SyncedGroup>> {
        info!("Starting full group sync from LDAP");

        #[cfg(feature = "ldap")]
        {
            let group_base = match &self.config.group_base_dn {
                Some(dn) => dn.clone(),
                None => return Ok(vec![]),
            };

            let group_filter = self
                .config
                .group_filter
                .as_deref()
                .unwrap_or("(objectClass=group)");

            let mut ldap = self.connect().await?;

            let (rs, _result) = ldap
                .search(&group_base, Scope::Subtree, group_filter, vec!["*"])
                .await
                .map_err(|e| SeparError::Internal {
                    message: format!("LDAP search failed: {}", e),
                })?
                .success()
                .map_err(|e| SeparError::Internal {
                    message: format!("LDAP search failed: {}", e),
                })?;

            let groups = rs
                .into_iter()
                .filter_map(|entry| {
                    let se = SearchEntry::construct(entry);
                    self.ldap_entry_to_group(&se)
                })
                .collect();

            ldap.unbind().await.ok();

            info!("Fetched {} groups from LDAP", groups.len());
            Ok(groups)
        }

        #[cfg(not(feature = "ldap"))]
        {
            Err(SeparError::ConfigError {
                message: "LDAP support not enabled. Compile with --features ldap".to_string(),
            })
        }
    }

    async fn sync_groups_incremental(&self, _since: DateTime<Utc>) -> Result<Vec<SyncedGroup>> {
        self.sync_groups().await
    }

    async fn get_user(&self, _external_id: &str) -> Result<Option<SyncedUser>> {
        // Would need to search by DN or specific attribute
        Ok(None)
    }

    async fn get_group(&self, _external_id: &str) -> Result<Option<SyncedGroup>> {
        Ok(None)
    }

    async fn get_user_groups(&self, _user_external_id: &str) -> Result<Vec<SyncedGroup>> {
        Ok(vec![])
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn test_connection(&self) -> Result<bool> {
        #[cfg(feature = "ldap")]
        {
            match self.connect().await {
                Ok(mut ldap) => {
                    ldap.unbind().await.ok();
                    Ok(true)
                }
                Err(_) => Ok(false),
            }
        }

        #[cfg(not(feature = "ldap"))]
        {
            Ok(false)
        }
    }
}

#[cfg(feature = "ldap")]
impl LdapProvider {
    fn ldap_entry_to_user(
        &self,
        entry: &SearchEntry,
        mappings: &LdapAttributeMappings,
    ) -> Option<SyncedUser> {
        let get_attr = |name: &str| -> Option<String> { entry.attrs.get(name)?.first().cloned() };

        let external_id = entry.dn.clone();
        let email = get_attr(&mappings.email)?;
        let username = get_attr(&mappings.username)?;

        Some(SyncedUser {
            external_id,
            email,
            display_name: mappings
                .display_name
                .as_ref()
                .and_then(|attr| get_attr(attr))
                .unwrap_or(username),
            given_name: mappings.given_name.as_ref().and_then(|attr| get_attr(attr)),
            family_name: mappings
                .family_name
                .as_ref()
                .and_then(|attr| get_attr(attr)),
            picture_url: None,
            active: true,
            email_verified: true,
            groups: mappings
                .member_of
                .as_ref()
                .and_then(|attr| entry.attrs.get(attr))
                .cloned()
                .unwrap_or_default(),
            roles: vec![],
            attributes: HashMap::new(),
            synced_at: Utc::now(),
        })
    }

    fn ldap_entry_to_group(&self, entry: &SearchEntry) -> Option<SyncedGroup> {
        let mappings = &self.config.attribute_mappings;
        let get_attr = |name: &str| -> Option<String> { entry.attrs.get(name)?.first().cloned() };

        let external_id = entry.dn.clone();
        let name = mappings
            .group_name
            .as_ref()
            .and_then(|attr| get_attr(attr))?;

        let members = mappings
            .group_member
            .as_ref()
            .and_then(|attr| entry.attrs.get(attr))
            .cloned()
            .unwrap_or_default();

        Some(SyncedGroup {
            external_id,
            name,
            description: None,
            group_type: Some("ldap".to_string()),
            members,
            parent_groups: vec![],
            child_groups: vec![],
            attributes: HashMap::new(),
            synced_at: Utc::now(),
        })
    }
}
