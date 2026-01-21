//! Application state for API handlers

use governor::{Quota, RateLimiter};
use moka::future::Cache;
use sqlx::PgPool;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use separ_db::repositories::{
    ApiKey, PgApiKeyRepository, PgApplicationRepository, PgAuditRepository, PgGroupRepository,
    PgOAuthProviderRepository, PgSyncConfigRepository, PgTenantRepository, PgUserRepository,
    PgWorkspaceRepository,
};
use separ_oauth::JwtService;
use separ_spicedb::{
    CachedClientConfig, CachedSpiceDbClient, SpiceDbAuthorizationService, SpiceDbClient,
};

/// Rate limiter type alias for IP-based limiting
pub type IpRateLimiter = RateLimiter<
    String,
    governor::state::keyed::DefaultKeyedStateStore<String>,
    governor::clock::DefaultClock,
>;

/// Rate limiter type alias for API-key-based limiting
pub type ApiKeyRateLimiter = RateLimiter<
    Uuid,
    governor::state::keyed::DefaultKeyedStateStore<Uuid>,
    governor::clock::DefaultClock,
>;

/// Per-API-key rate limiter entry
#[derive(Clone)]
pub struct ApiKeyRateLimitEntry {
    pub limiter: Arc<ApiKeyRateLimiter>,
    pub limit_per_minute: i32,
}

/// Concrete application state with all services
#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
    pub auth_service: Arc<SpiceDbAuthorizationService>,
    /// Raw SpiceDB client (for health checks)
    pub spicedb_client: Arc<SpiceDbClient>,
    /// Cached SpiceDB client (for permission checks)
    pub cached_spicedb: Arc<CachedSpiceDbClient>,
    pub tenant_repo: Arc<PgTenantRepository>,
    pub workspace_repo: Arc<PgWorkspaceRepository>,
    pub app_repo: Arc<PgApplicationRepository>,
    pub user_repo: Arc<PgUserRepository>,
    pub group_repo: Arc<PgGroupRepository>,
    pub oauth_repo: Arc<PgOAuthProviderRepository>,
    pub sync_repo: Arc<PgSyncConfigRepository>,
    pub audit_repo: Arc<PgAuditRepository>,
    pub api_key_repo: Arc<PgApiKeyRepository>,
    pub jwt_service: Arc<JwtService>,
    /// API key validation cache (key_hash -> ApiKey)
    pub api_key_cache: Cache<String, ApiKey>,
    /// Global rate limiter by IP
    pub rate_limiter: Arc<IpRateLimiter>,
    /// Per-API-key rate limiters (api_key_id -> limiter)
    /// Each API key can have its own rate limit defined in the database
    pub api_key_rate_limiters: Cache<Uuid, ApiKeyRateLimitEntry>,
}

impl AppState {
    /// Create new application state from components
    pub fn new(
        db_pool: PgPool,
        spicedb_client: SpiceDbClient,
        auth_service: SpiceDbAuthorizationService,
        jwt_service: JwtService,
    ) -> Self {
        // Create cached SpiceDB client with default config
        let cached_spicedb =
            CachedSpiceDbClient::new(spicedb_client.clone(), CachedClientConfig::default());

        // API key cache: 1000 entries, 5 minute TTL
        let api_key_cache = Cache::builder()
            .max_capacity(1000)
            .time_to_live(Duration::from_secs(300))
            .build();

        // Rate limiter: 100 requests per second per IP with burst of 200
        let quota = Quota::per_second(NonZeroU32::new(100).unwrap())
            .allow_burst(NonZeroU32::new(200).unwrap());
        let rate_limiter = Arc::new(RateLimiter::keyed(quota));

        // Per-API-key rate limiters: 1000 entries, 10 minute TTL
        let api_key_rate_limiters = Cache::builder()
            .max_capacity(1000)
            .time_to_live(Duration::from_secs(600))
            .build();

        Self {
            tenant_repo: Arc::new(PgTenantRepository::new(db_pool.clone())),
            workspace_repo: Arc::new(PgWorkspaceRepository::new(db_pool.clone())),
            app_repo: Arc::new(PgApplicationRepository::new(db_pool.clone())),
            user_repo: Arc::new(PgUserRepository::new(db_pool.clone())),
            group_repo: Arc::new(PgGroupRepository::new(db_pool.clone())),
            oauth_repo: Arc::new(PgOAuthProviderRepository::new(db_pool.clone())),
            sync_repo: Arc::new(PgSyncConfigRepository::new(db_pool.clone())),
            audit_repo: Arc::new(PgAuditRepository::new(db_pool.clone())),
            api_key_repo: Arc::new(PgApiKeyRepository::new(db_pool.clone())),
            db_pool,
            spicedb_client: Arc::new(spicedb_client),
            cached_spicedb: Arc::new(cached_spicedb),
            auth_service: Arc::new(auth_service),
            jwt_service: Arc::new(jwt_service),
            api_key_cache,
            rate_limiter,
            api_key_rate_limiters,
        }
    }

    /// Get or create a rate limiter for a specific API key
    ///
    /// Creates a new rate limiter based on the key's rate_limit_per_minute setting.
    pub async fn get_api_key_rate_limiter(&self, api_key: &ApiKey) -> ApiKeyRateLimitEntry {
        let key_id = *api_key.id.as_uuid();

        // Check if we already have a limiter for this key
        if let Some(entry) = self.api_key_rate_limiters.get(&key_id).await {
            // If the rate limit changed, we need to create a new limiter
            if entry.limit_per_minute == api_key.rate_limit_per_minute {
                return entry;
            }
        }

        // Create a new rate limiter for this API key
        let limit_per_minute = api_key.rate_limit_per_minute.max(1) as u32;
        let limit_per_second = (limit_per_minute / 60).max(1);
        let burst = (limit_per_minute / 30).max(2); // Allow ~2 seconds burst

        let quota = Quota::per_second(NonZeroU32::new(limit_per_second).unwrap())
            .allow_burst(NonZeroU32::new(burst).unwrap());

        let entry = ApiKeyRateLimitEntry {
            limiter: Arc::new(RateLimiter::keyed(quota)),
            limit_per_minute: api_key.rate_limit_per_minute,
        };

        self.api_key_rate_limiters
            .insert(key_id, entry.clone())
            .await;
        entry
    }

    /// Check rate limit for an API key
    ///
    /// Returns Ok(remaining) if allowed, Err(retry_after_seconds) if rate limited.
    pub async fn check_api_key_rate_limit(&self, api_key: &ApiKey) -> Result<u32, u64> {
        let entry = self.get_api_key_rate_limiter(api_key).await;
        let key_id = *api_key.id.as_uuid();

        match entry.limiter.check_key(&key_id) {
            Ok(_) => {
                // Approximate remaining (governor doesn't expose this directly)
                let limit_per_second = (api_key.rate_limit_per_minute / 60).max(1) as u32;
                Ok(limit_per_second)
            }
            Err(not_until) => {
                let clock = governor::clock::DefaultClock::default();
                let retry_after = not_until.wait_time_from(governor::clock::Clock::now(&clock));
                Err(retry_after.as_secs().max(1))
            }
        }
    }
}
