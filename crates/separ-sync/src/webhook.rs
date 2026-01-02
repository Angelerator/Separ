//! Webhook Handler for external IdP events

use serde::{Deserialize, Serialize};
use tracing::{instrument, warn};

use separ_core::{Result, SeparError, TenantId};

/// Webhook event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEventType {
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserActivated,
    UserDeactivated,
    GroupCreated,
    GroupUpdated,
    GroupDeleted,
    GroupMemberAdded,
    GroupMemberRemoved,
}

/// Generic webhook payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event_type: WebhookEventType,
    pub timestamp: String,
    pub data: serde_json::Value,
    pub tenant_id: Option<String>,
}

/// Webhook verification result
pub struct WebhookVerification {
    pub valid: bool,
    pub tenant_id: Option<TenantId>,
}

/// Webhook handler trait
pub trait WebhookHandler: Send + Sync {
    /// Verify webhook signature
    fn verify_signature(&self, payload: &[u8], signature: &str, secret: &[u8]) -> bool;

    /// Parse webhook payload
    fn parse_payload(&self, body: &[u8]) -> Result<WebhookPayload>;
}

/// Default HMAC-SHA256 webhook handler
pub struct HmacWebhookHandler;

impl HmacWebhookHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HmacWebhookHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookHandler for HmacWebhookHandler {
    fn verify_signature(&self, payload: &[u8], signature: &str, secret: &[u8]) -> bool {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = match HmacSha256::new_from_slice(secret) {
            Ok(m) => m,
            Err(_) => return false,
        };

        mac.update(payload);

        // Parse the signature (expected format: "sha256=<hex>")
        let expected_signature = if let Some(hex) = signature.strip_prefix("sha256=") {
            hex
        } else {
            signature
        };

        let expected_bytes = match hex::decode(expected_signature) {
            Ok(b) => b,
            Err(_) => return false,
        };

        mac.verify_slice(&expected_bytes).is_ok()
    }

    fn parse_payload(&self, body: &[u8]) -> Result<WebhookPayload> {
        serde_json::from_slice(body)
            .map_err(|e| SeparError::invalid_input(format!("Invalid webhook payload: {}", e)))
    }
}

/// Webhook processor for handling incoming events
pub struct WebhookProcessor {
    handler: Box<dyn WebhookHandler>,
}

impl WebhookProcessor {
    pub fn new(handler: Box<dyn WebhookHandler>) -> Self {
        Self { handler }
    }

    #[instrument(skip(self, payload, signature, secret))]
    pub fn verify_and_parse(
        &self,
        payload: &[u8],
        signature: &str,
        secret: &[u8],
    ) -> Result<WebhookPayload> {
        if !self.handler.verify_signature(payload, signature, secret) {
            return Err(SeparError::auth_error("Invalid webhook signature"));
        }

        self.handler.parse_payload(payload)
    }
}

/// Hex encoding helper
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
        if s.len() % 2 != 0 {
            return Err("Invalid hex string length");
        }

        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "Invalid hex character"))
            .collect()
    }
}

// Provider-specific webhook handlers

/// Microsoft Entra ID webhook handler
pub struct EntraWebhookHandler;

impl Default for EntraWebhookHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl EntraWebhookHandler {
    pub fn new() -> Self {
        Self
    }
}

/// Okta webhook handler
pub struct OktaWebhookHandler;

impl Default for OktaWebhookHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl OktaWebhookHandler {
    pub fn new() -> Self {
        Self
    }
}

/// Google Workspace webhook handler  
pub struct GoogleWebhookHandler;

impl Default for GoogleWebhookHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl GoogleWebhookHandler {
    pub fn new() -> Self {
        Self
    }
}
