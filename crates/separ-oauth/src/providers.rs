//! Provider-specific OAuth configurations

use separ_core::OAuthProviderType;

/// Well-known OAuth provider configurations
pub struct ProviderConfig {
    pub provider_type: OAuthProviderType,
    pub display_name: &'static str,
    pub authorization_endpoint: &'static str,
    pub token_endpoint: &'static str,
    pub userinfo_endpoint: &'static str,
    pub jwks_uri: &'static str,
    pub issuer: &'static str,
    pub default_scopes: &'static [&'static str],
}

/// Microsoft Entra ID (Azure AD) configuration
pub const MICROSOFT_CONFIG: ProviderConfig = ProviderConfig {
    provider_type: OAuthProviderType::Microsoft,
    display_name: "Microsoft",
    authorization_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    userinfo_endpoint: "https://graph.microsoft.com/oidc/userinfo",
    jwks_uri: "https://login.microsoftonline.com/common/discovery/v2.0/keys",
    issuer: "https://login.microsoftonline.com/{tenantid}/v2.0",
    default_scopes: &["openid", "profile", "email", "offline_access"],
};

/// Google configuration
pub const GOOGLE_CONFIG: ProviderConfig = ProviderConfig {
    provider_type: OAuthProviderType::Google,
    display_name: "Google",
    authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    token_endpoint: "https://oauth2.googleapis.com/token",
    userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo",
    jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
    issuer: "https://accounts.google.com",
    default_scopes: &["openid", "profile", "email"],
};

/// Get provider configuration by type
pub fn get_provider_config(provider_type: OAuthProviderType) -> Option<&'static ProviderConfig> {
    match provider_type {
        OAuthProviderType::Microsoft => Some(&MICROSOFT_CONFIG),
        OAuthProviderType::Google => Some(&GOOGLE_CONFIG),
        _ => None, // Custom, Okta, Auth0 require tenant-specific configuration
    }
}

/// Okta discovery URL format
pub fn okta_discovery_url(domain: &str) -> String {
    format!(
        "https://{}/oauth2/default/.well-known/openid-configuration",
        domain
    )
}

/// Auth0 discovery URL format
pub fn auth0_discovery_url(domain: &str) -> String {
    format!("https://{}/.well-known/openid-configuration", domain)
}

/// Microsoft tenant-specific discovery URL
pub fn microsoft_discovery_url(tenant_id: &str) -> String {
    format!(
        "https://login.microsoftonline.com/{}/.well-known/openid-configuration",
        tenant_id
    )
}
