//! Unit tests for separ-identity

use chrono::Utc;
use separ_core::identity::{
    AuthenticatedPrincipal, AzureAdConfig, ClaimMappings, GoogleConfig, OidcConfig, OktaConfig,
    PrincipalType, ProviderFeatures, ProviderType, SyncError, SyncResultStatus, SyncSettings,
    SyncedApp, SyncedAppType, SyncedGroup, SyncedUser,
};
use separ_core::{IdentityProviderId, TenantId};
use std::collections::HashMap;

// =============================================================================
// Provider Registry Tests
// =============================================================================

#[cfg(test)]
mod registry_tests {
    use super::*;
    use crate::registry::ProviderRegistry;

    #[tokio::test]
    async fn test_registry_creation() {
        let registry = ProviderRegistry::new();
        // Registry should be created successfully - check it has no providers initially
        let tenant_id = TenantId::new();
        let providers = registry.get_configs_for_tenant(tenant_id).await;
        assert!(providers.is_empty());
    }

    #[tokio::test]
    async fn test_registry_get_providers_for_tenant() {
        let registry = ProviderRegistry::new();
        let tenant_id = TenantId::new();

        // Get providers for a tenant with no providers
        let providers = registry.get_configs_for_tenant(tenant_id).await;
        assert!(providers.is_empty());
    }
}

// =============================================================================
// Provider Type Tests
// =============================================================================

#[cfg(test)]
mod provider_type_tests {
    use super::*;

    #[test]
    fn test_provider_type_serialization() {
        let types = vec![
            ProviderType::AzureAd,
            ProviderType::Okta,
            ProviderType::Google,
            ProviderType::GenericOidc,
            ProviderType::Direct,
        ];

        for provider_type in types {
            let json = serde_json::to_string(&provider_type).unwrap();
            let deserialized: ProviderType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, provider_type);
        }
    }

    #[test]
    fn test_provider_type_display() {
        assert_eq!(ProviderType::AzureAd.to_string(), "azure_ad");
        assert_eq!(ProviderType::Okta.to_string(), "okta");
        assert_eq!(ProviderType::Google.to_string(), "google");
        assert_eq!(ProviderType::Direct.to_string(), "direct");
    }
}

// =============================================================================
// Identity Data Model Tests
// =============================================================================

#[cfg(test)]
mod data_model_tests {
    use super::*;

    #[test]
    fn test_synced_user_serialization() {
        let user = SyncedUser {
            external_id: "ext_123".to_string(),
            email: "john.doe@example.com".to_string(),
            display_name: "John Doe".to_string(),
            given_name: Some("John".to_string()),
            family_name: Some("Doe".to_string()),
            picture_url: None,
            active: true,
            email_verified: true,
            groups: vec!["group1".to_string()],
            roles: vec!["admin".to_string()],
            attributes: HashMap::new(),
            synced_at: Utc::now(),
        };

        let json = serde_json::to_string(&user).unwrap();
        let deserialized: SyncedUser = serde_json::from_str(&json).unwrap();

        assert_eq!(user.email, deserialized.email);
        assert_eq!(user.display_name, deserialized.display_name);
        assert!(deserialized.active);
    }

    #[test]
    fn test_synced_group_serialization() {
        let group = SyncedGroup {
            external_id: "ext_group_456".to_string(),
            name: "Engineering".to_string(),
            description: Some("Engineering team".to_string()),
            group_type: Some("security".to_string()),
            members: vec!["user1".to_string(), "user2".to_string()],
            parent_groups: vec![],
            child_groups: vec![],
            attributes: HashMap::new(),
            synced_at: Utc::now(),
        };

        let json = serde_json::to_string(&group).unwrap();
        let deserialized: SyncedGroup = serde_json::from_str(&json).unwrap();

        assert_eq!(group.name, deserialized.name);
        assert_eq!(group.members.len(), deserialized.members.len());
    }

    #[test]
    fn test_synced_app_serialization() {
        let app = SyncedApp {
            external_id: "ext_app_789".to_string(),
            name: "My Service".to_string(),
            app_type: SyncedAppType::ServicePrincipal,
            description: Some("A service principal".to_string()),
            enabled: true,
            assigned_permissions: vec!["read".to_string()],
            attributes: HashMap::new(),
            synced_at: Utc::now(),
        };

        let json = serde_json::to_string(&app).unwrap();
        let deserialized: SyncedApp = serde_json::from_str(&json).unwrap();

        assert_eq!(app.name, deserialized.name);
        assert!(deserialized.enabled);
    }

    #[test]
    fn test_synced_app_type_variants() {
        let types = vec![
            SyncedAppType::Application,
            SyncedAppType::ServicePrincipal,
            SyncedAppType::ManagedIdentity,
        ];

        for app_type in types {
            let json = serde_json::to_string(&app_type).unwrap();
            let deserialized: SyncedAppType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, app_type);
        }
    }
}

// =============================================================================
// Provider Configuration Tests
// =============================================================================

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn test_provider_features_default() {
        let features = ProviderFeatures::default();

        // Default should have all features disabled
        assert!(!features.sync_users);
        assert!(!features.sync_groups);
        assert!(!features.authentication);
    }

    #[test]
    fn test_provider_features_all_enabled() {
        let features = ProviderFeatures {
            sync_users: true,
            sync_groups: true,
            sync_apps: true,
            authentication: true,
            jit_provisioning: true,
            resolve_nested_groups: true,
        };

        assert!(features.sync_users);
        assert!(features.sync_groups);
        assert!(features.authentication);
    }

    #[test]
    fn test_sync_settings_default() {
        let settings = SyncSettings::default();

        // Default should have reasonable values
        assert!(settings.interval_secs.is_some());
        assert!(settings.full_sync_enabled);
        assert_eq!(settings.batch_size, 100);
        assert_eq!(settings.max_retries, 3);
    }

    #[test]
    fn test_azure_ad_config_default() {
        let config = AzureAdConfig::default();

        assert!(config.tenant_id.is_empty());
        assert!(config.client_id.is_empty());
        assert!(!config.graph_scopes.is_empty());
    }

    #[test]
    fn test_okta_config_creation() {
        let config = OktaConfig {
            domain: "dev-123456.okta.com".to_string(),
            api_token: "api-token".to_string(),
            client_id: "client-id".to_string(),
            client_secret: "secret".to_string(),
            user_filter: None,
            group_filter: None,
            scim_endpoint: None,
        };

        assert!(!config.domain.is_empty());
        assert!(!config.client_id.is_empty());
    }

    #[test]
    fn test_google_config_creation() {
        let config = GoogleConfig {
            project_id: "my-project".to_string(),
            client_id: "123.apps.googleusercontent.com".to_string(),
            client_secret: "secret".to_string(),
            service_account_email: None,
            service_account_key: None,
            admin_email: Some("admin@example.com".to_string()),
            customer_id: None,
        };

        assert!(!config.client_id.is_empty());
        assert!(!config.project_id.is_empty());
    }

    #[test]
    fn test_oidc_config_creation() {
        let config = OidcConfig {
            issuer_url: "https://login.example.com".to_string(),
            client_id: "client-id".to_string(),
            client_secret: "secret".to_string(),
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            scopes: vec!["openid".to_string(), "profile".to_string()],
            claim_mappings: ClaimMappings::default(),
        };

        assert!(!config.issuer_url.is_empty());
        assert!(!config.scopes.is_empty());
    }
}

// =============================================================================
// Sync Result Tests
// =============================================================================

#[cfg(test)]
mod sync_tests {
    use super::*;

    #[test]
    fn test_sync_result_status_variants() {
        let statuses = vec![
            SyncResultStatus::Success,
            SyncResultStatus::PartialSuccess,
            SyncResultStatus::Failed,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: SyncResultStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, status);
        }
    }

    #[test]
    fn test_sync_error_creation() {
        let error = SyncError {
            entity_type: "user".to_string(),
            external_id: Some("user123".to_string()),
            error_type: "validation".to_string(),
            message: "Invalid email format".to_string(),
            timestamp: Utc::now(),
        };

        assert_eq!(error.entity_type, "user");
        assert!(error.external_id.is_some());
    }
}

// =============================================================================
// Principal Authentication Tests
// =============================================================================

#[cfg(test)]
mod auth_tests {
    use super::*;

    #[test]
    fn test_principal_type_variants() {
        let types = vec![
            PrincipalType::User,
            PrincipalType::Service,
            PrincipalType::Application,
            PrincipalType::ManagedIdentity,
        ];

        for principal_type in types {
            let json = serde_json::to_string(&principal_type).unwrap();
            let deserialized: PrincipalType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, principal_type);
        }
    }

    #[test]
    fn test_authenticated_principal_user() {
        let principal = AuthenticatedPrincipal {
            principal_type: PrincipalType::User,
            subject: "user@example.com".to_string(),
            separ_id: Some("user_123".to_string()),
            tenant_id: TenantId::new(),
            provider_id: IdentityProviderId::new(),
            provider_type: ProviderType::AzureAd,
            email: Some("user@example.com".to_string()),
            display_name: Some("Test User".to_string()),
            groups: vec!["group1".to_string()],
            roles: vec!["admin".to_string()],
            scopes: vec!["read".to_string(), "write".to_string()],
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            raw_claims: HashMap::new(),
        };

        assert_eq!(principal.principal_type, PrincipalType::User);
        assert!(principal.email.is_some());
        assert!(!principal.scopes.is_empty());
    }

    #[test]
    fn test_authenticated_principal_service() {
        let principal = AuthenticatedPrincipal {
            principal_type: PrincipalType::Service,
            subject: "sp_ext_456".to_string(),
            separ_id: None,
            tenant_id: TenantId::new(),
            provider_id: IdentityProviderId::new(),
            provider_type: ProviderType::AzureAd,
            email: None,
            display_name: Some("My Service App".to_string()),
            groups: vec![],
            roles: vec![],
            scopes: vec!["api.read".to_string()],
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            raw_claims: HashMap::new(),
        };

        assert_eq!(principal.principal_type, PrincipalType::Service);
        assert!(principal.email.is_none());
    }
}
