//! Provider Registry - manages multiple identity providers per tenant
//!
//! The registry provides:
//! - Provider lifecycle management (create, update, delete)
//! - Provider lookup by ID, type, or domain
//! - Automatic provider detection from tokens
//! - Provider health monitoring

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use separ_core::{identity::*, IdentityProviderId, Result, SeparError, TenantId};

#[cfg(feature = "azure")]
use crate::providers::azure::AzureAdProvider;

#[cfg(feature = "okta")]
use crate::providers::okta::OktaProvider;

#[cfg(feature = "google")]
use crate::providers::google::GoogleProvider;

#[cfg(feature = "oidc")]
use crate::providers::oidc::GenericOidcProvider;

/// Registry for managing identity providers
pub struct ProviderRegistry {
    /// Providers indexed by their ID
    sync_providers: RwLock<HashMap<IdentityProviderId, Arc<dyn IdentitySync>>>,
    auth_providers: RwLock<HashMap<IdentityProviderId, Arc<dyn IdentityAuth>>>,

    /// Provider configs indexed by tenant
    configs_by_tenant: RwLock<HashMap<TenantId, Vec<IdentityProviderConfig>>>,

    /// Domain to provider mapping for automatic detection
    domain_mapping: RwLock<HashMap<String, IdentityProviderId>>,
}

impl ProviderRegistry {
    /// Create a new provider registry
    pub fn new() -> Self {
        Self {
            sync_providers: RwLock::new(HashMap::new()),
            auth_providers: RwLock::new(HashMap::new()),
            configs_by_tenant: RwLock::new(HashMap::new()),
            domain_mapping: RwLock::new(HashMap::new()),
        }
    }

    /// Register a provider from configuration
    #[instrument(skip(self, config), fields(provider_id = %config.id, provider_type = ?config.provider_type))]
    pub async fn register(&self, config: IdentityProviderConfig) -> Result<()> {
        info!(
            "Registering identity provider: {} ({})",
            config.name, config.provider_type
        );

        if !config.enabled {
            debug!("Provider is disabled, skipping registration");
            return Ok(());
        }

        // Create provider instances based on type
        match config.provider_type {
            #[cfg(feature = "azure")]
            ProviderType::AzureAd => {
                let provider = AzureAdProvider::new(&config)?;
                let provider = Arc::new(provider);

                self.sync_providers
                    .write()
                    .await
                    .insert(config.id, provider.clone());
                self.auth_providers
                    .write()
                    .await
                    .insert(config.id, provider);
            }

            #[cfg(feature = "okta")]
            ProviderType::Okta => {
                let provider = OktaProvider::new(&config).await?;
                let provider = Arc::new(provider);

                self.sync_providers
                    .write()
                    .await
                    .insert(config.id, provider.clone());
                self.auth_providers
                    .write()
                    .await
                    .insert(config.id, provider);
            }

            #[cfg(feature = "google")]
            ProviderType::Google => {
                let provider = GoogleProvider::new(&config).await?;
                let provider = Arc::new(provider);

                self.sync_providers
                    .write()
                    .await
                    .insert(config.id, provider.clone());
                self.auth_providers
                    .write()
                    .await
                    .insert(config.id, provider);
            }

            #[cfg(feature = "oidc")]
            ProviderType::GenericOidc => {
                let provider = GenericOidcProvider::new(&config).await?;
                let provider = Arc::new(provider);

                self.sync_providers
                    .write()
                    .await
                    .insert(config.id, provider.clone());
                self.auth_providers
                    .write()
                    .await
                    .insert(config.id, provider);
            }

            _ => {
                warn!("Unsupported provider type: {:?}", config.provider_type);
                return Err(SeparError::InvalidInput {
                    message: format!("Unsupported provider type: {:?}", config.provider_type),
                });
            }
        }

        // Register domain mappings
        {
            let mut domain_map = self.domain_mapping.write().await;
            for domain in &config.domains {
                domain_map.insert(domain.to_lowercase(), config.id);
            }
        }

        // Store config by tenant
        {
            let mut configs = self.configs_by_tenant.write().await;
            configs
                .entry(config.tenant_id)
                .or_insert_with(Vec::new)
                .push(config);
        }

        Ok(())
    }

    /// Unregister a provider
    #[instrument(skip(self))]
    pub async fn unregister(&self, provider_id: IdentityProviderId) -> Result<()> {
        info!("Unregistering identity provider: {}", provider_id);

        self.sync_providers.write().await.remove(&provider_id);
        self.auth_providers.write().await.remove(&provider_id);

        // Remove from tenant configs
        {
            let mut configs = self.configs_by_tenant.write().await;
            for tenant_configs in configs.values_mut() {
                tenant_configs.retain(|c| c.id != provider_id);
            }
        }

        // Remove domain mappings
        {
            let mut domain_map = self.domain_mapping.write().await;
            domain_map.retain(|_, id| *id != provider_id);
        }

        Ok(())
    }

    /// Get a sync provider by ID
    pub async fn get_sync_provider(
        &self,
        provider_id: IdentityProviderId,
    ) -> Option<Arc<dyn IdentitySync>> {
        self.sync_providers.read().await.get(&provider_id).cloned()
    }

    /// Get an auth provider by ID
    pub async fn get_auth_provider(
        &self,
        provider_id: IdentityProviderId,
    ) -> Option<Arc<dyn IdentityAuth>> {
        self.auth_providers.read().await.get(&provider_id).cloned()
    }

    /// Get all sync providers for a tenant
    pub async fn get_sync_providers_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Vec<Arc<dyn IdentitySync>> {
        let configs = self.configs_by_tenant.read().await;
        let providers = self.sync_providers.read().await;

        configs
            .get(&tenant_id)
            .map(|tenant_configs| {
                tenant_configs
                    .iter()
                    .filter_map(|c| providers.get(&c.id).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all auth providers for a tenant
    pub async fn get_auth_providers_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Vec<Arc<dyn IdentityAuth>> {
        let configs = self.configs_by_tenant.read().await;
        let providers = self.auth_providers.read().await;

        configs
            .get(&tenant_id)
            .map(|tenant_configs| {
                tenant_configs
                    .iter()
                    .filter_map(|c| providers.get(&c.id).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find provider by domain (for automatic detection)
    pub async fn find_provider_by_domain(&self, domain: &str) -> Option<Arc<dyn IdentityAuth>> {
        let domain_lower = domain.to_lowercase();

        let provider_id = self
            .domain_mapping
            .read()
            .await
            .get(&domain_lower)
            .cloned()?;
        self.get_auth_provider(provider_id).await
    }

    /// Find provider by email domain
    pub async fn find_provider_by_email(&self, email: &str) -> Option<Arc<dyn IdentityAuth>> {
        let domain = email.split('@').next_back()?;
        self.find_provider_by_domain(domain).await
    }

    /// Try to authenticate with any provider for a tenant
    #[instrument(skip(self, token))]
    pub async fn authenticate_token(
        &self,
        tenant_id: TenantId,
        token: &str,
    ) -> Result<AuthenticatedPrincipal> {
        let providers = self.get_auth_providers_for_tenant(tenant_id).await;

        if providers.is_empty() {
            return Err(SeparError::AuthError {
                message: "No identity providers configured for tenant".to_string(),
            });
        }

        let options = ValidationOptions {
            audiences: vec![],
            issuers: vec![],
            clock_skew_secs: 60,
            validate_exp: true,
            validate_nbf: true,
        };

        let mut last_error = None;

        // Try each provider in priority order
        for provider in providers {
            match provider.validate_token(token, &options).await {
                Ok(principal) => return Ok(principal),
                Err(e) => {
                    debug!(
                        "Provider {:?} failed to validate token: {}",
                        provider.provider_type(),
                        e
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| SeparError::AuthError {
            message: "No provider could validate the token".to_string(),
        }))
    }

    /// Get provider configurations for a tenant
    pub async fn get_configs_for_tenant(&self, tenant_id: TenantId) -> Vec<IdentityProviderConfig> {
        self.configs_by_tenant
            .read()
            .await
            .get(&tenant_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Check health of all providers
    pub async fn health_check(&self) -> HashMap<IdentityProviderId, bool> {
        let providers = self.sync_providers.read().await;
        let mut results = HashMap::new();

        for (id, provider) in providers.iter() {
            let healthy = provider.test_connection().await.unwrap_or(false);
            results.insert(*id, healthy);
        }

        results
    }

    /// Get count of registered providers
    pub async fn provider_count(&self) -> usize {
        self.sync_providers.read().await.len()
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating and registering providers
pub struct ProviderBuilder {
    config: IdentityProviderConfig,
}

impl ProviderBuilder {
    pub fn new(tenant_id: TenantId, name: impl Into<String>, provider_type: ProviderType) -> Self {
        Self {
            config: IdentityProviderConfig {
                id: IdentityProviderId::new(),
                tenant_id,
                provider_type,
                name: name.into(),
                display_name: None,
                config: ProviderConfigDetails::Direct(DirectConfig::default()),
                features: ProviderFeatures::default(),
                sync_settings: SyncSettings::default(),
                domains: vec![],
                priority: 0,
                enabled: true,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
        }
    }

    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.config.display_name = Some(display_name.into());
        self
    }

    pub fn with_config(mut self, config: ProviderConfigDetails) -> Self {
        self.config.config = config;
        self
    }

    pub fn with_features(mut self, features: ProviderFeatures) -> Self {
        self.config.features = features;
        self
    }

    pub fn with_sync_settings(mut self, settings: SyncSettings) -> Self {
        self.config.sync_settings = settings;
        self
    }

    pub fn with_domains(mut self, domains: Vec<String>) -> Self {
        self.config.domains = domains;
        self
    }

    pub fn with_priority(mut self, priority: i32) -> Self {
        self.config.priority = priority;
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    pub fn build(self) -> IdentityProviderConfig {
        self.config
    }

    pub async fn register(self, registry: &ProviderRegistry) -> Result<IdentityProviderConfig> {
        let config = self.build();
        registry.register(config.clone()).await?;
        Ok(config)
    }
}
