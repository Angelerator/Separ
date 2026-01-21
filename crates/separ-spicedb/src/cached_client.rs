//! Cached SpiceDB client with consistency mode support
//!
//! Implements SpiceDB best practices:
//! - ZedToken-based cache invalidation
//! - Multiple consistency modes for different use cases
//! - Moka async cache for high-performance caching
//! - Automatic cache invalidation on writes

use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument};

use separ_core::Result;

use crate::client::SpiceDbClient;

// =============================================================================
// Consistency Modes
// =============================================================================

/// SpiceDB consistency mode
/// 
/// Based on SpiceDB documentation:
/// - MinimizeLatency: Uses cached results aggressively (seconds of staleness acceptable)
/// - AtLeastAsFresh: Result is at least as fresh as the provided ZedToken
/// - FullyConsistent: Always uses latest data (no caching)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ConsistencyMode {
    /// Use cached results aggressively for best performance
    /// Best for: UI rendering, non-critical checks, high-volume reads
    #[default]
    MinimizeLatency,
    
    /// Result must be at least as fresh as the provided ZedToken
    /// Best for: After write operations, ensuring visibility of recent changes
    AtLeastAsFresh,
    
    /// Always use latest data, bypassing all caches
    /// Best for: Admin operations, permission changes, critical security checks
    FullyConsistent,
}

// =============================================================================
// Cache Key Types
// =============================================================================

/// Cache key for permission checks
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PermissionCacheKey {
    resource_type: String,
    resource_id: String,
    permission: String,
    subject_type: String,
    subject_id: String,
}

impl PermissionCacheKey {
    fn new(
        resource_type: &str,
        resource_id: &str,
        permission: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Self {
        Self {
            resource_type: resource_type.to_string(),
            resource_id: resource_id.to_string(),
            permission: permission.to_string(),
            subject_type: subject_type.to_string(),
            subject_id: subject_id.to_string(),
        }
    }
}

/// Cached permission result
#[derive(Debug, Clone)]
struct CachedPermission {
    allowed: bool,
    zed_token: Option<String>,
    cached_at: std::time::Instant,
}

// =============================================================================
// Cached SpiceDB Client
// =============================================================================

/// Configuration for the cached client
#[derive(Debug, Clone)]
pub struct CachedClientConfig {
    /// Maximum number of cached permission results
    pub max_permission_cache_size: u64,
    /// TTL for cached permission results (default: 30 seconds)
    pub permission_cache_ttl: Duration,
    /// TTL for cached schema (default: 5 minutes)
    pub schema_cache_ttl: Duration,
    /// Whether to invalidate cache on writes
    pub invalidate_on_write: bool,
}

impl Default for CachedClientConfig {
    fn default() -> Self {
        Self {
            max_permission_cache_size: 10_000,
            permission_cache_ttl: Duration::from_secs(30),
            schema_cache_ttl: Duration::from_secs(300),
            invalidate_on_write: true,
        }
    }
}

/// Cached SpiceDB client with consistency support
/// 
/// Wraps the base SpiceDB client and adds:
/// - Permission caching with configurable TTL
/// - ZedToken tracking for cache invalidation
/// - Multiple consistency modes
/// - Automatic cache invalidation on writes
pub struct CachedSpiceDbClient {
    inner: SpiceDbClient,
    config: CachedClientConfig,
    /// Permission check cache
    permission_cache: Cache<PermissionCacheKey, CachedPermission>,
    /// Latest known ZedToken (from writes)
    latest_zed_token: Arc<RwLock<Option<String>>>,
    /// Cache metrics
    metrics: Arc<CacheMetrics>,
}

/// Cache metrics for monitoring
#[derive(Debug, Default)]
pub struct CacheMetrics {
    pub hits: std::sync::atomic::AtomicU64,
    pub misses: std::sync::atomic::AtomicU64,
    pub invalidations: std::sync::atomic::AtomicU64,
}

impl CacheMetrics {
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.misses.load(std::sync::atomic::Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
}

impl CachedSpiceDbClient {
    /// Create a new cached client
    pub fn new(client: SpiceDbClient, config: CachedClientConfig) -> Self {
        let permission_cache = Cache::builder()
            .max_capacity(config.max_permission_cache_size)
            .time_to_live(config.permission_cache_ttl)
            .build();

        Self {
            inner: client,
            config,
            permission_cache,
            latest_zed_token: Arc::new(RwLock::new(None)),
            metrics: Arc::new(CacheMetrics::default()),
        }
    }

    /// Get the underlying SpiceDB client
    pub fn inner(&self) -> &SpiceDbClient {
        &self.inner
    }

    /// Get cache metrics
    pub fn metrics(&self) -> &CacheMetrics {
        &self.metrics
    }

    /// Get the latest ZedToken
    pub async fn latest_zed_token(&self) -> Option<String> {
        self.latest_zed_token.read().await.clone()
    }

    /// Check a permission with caching
    /// 
    /// # Arguments
    /// * `consistency` - Consistency mode to use
    /// * `zed_token` - Optional ZedToken for at_least_as_fresh consistency
    #[instrument(skip(self, zed_token))]
    pub async fn check_permission(
        &self,
        resource_type: &str,
        resource_id: &str,
        permission: &str,
        subject_type: &str,
        subject_id: &str,
        consistency: ConsistencyMode,
        zed_token: Option<&str>,
    ) -> Result<bool> {
        // For fully consistent mode, bypass cache entirely
        if consistency == ConsistencyMode::FullyConsistent {
            debug!("Bypassing cache for fully_consistent check");
            return self.inner.check_permission(
                resource_type,
                resource_id,
                permission,
                subject_type,
                subject_id,
            ).await;
        }

        let cache_key = PermissionCacheKey::new(
            resource_type,
            resource_id,
            permission,
            subject_type,
            subject_id,
        );

        // Try to get from cache
        if let Some(cached) = self.permission_cache.get(&cache_key).await {
            // For at_least_as_fresh, check if cache entry is fresh enough
            if consistency == ConsistencyMode::AtLeastAsFresh {
                if let Some(required_token) = zed_token {
                    if let Some(ref cached_token) = cached.zed_token {
                        // Compare tokens (lexicographic comparison works for SpiceDB tokens)
                        if cached_token.as_str() >= required_token {
                            self.metrics.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            debug!(
                                resource = %format!("{}:{}", resource_type, resource_id),
                                permission = %permission,
                                result = %cached.allowed,
                                "Permission check cache hit (at_least_as_fresh)"
                            );
                            return Ok(cached.allowed);
                        }
                        // Cache entry is stale, fall through to query
                    }
                }
            } else {
                // MinimizeLatency - use cache if available
                self.metrics.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                debug!(
                    resource = %format!("{}:{}", resource_type, resource_id),
                    permission = %permission,
                    result = %cached.allowed,
                    "Permission check cache hit (minimize_latency)"
                );
                return Ok(cached.allowed);
            }
        }

        // Cache miss - query SpiceDB
        self.metrics.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        debug!(
            resource = %format!("{}:{}", resource_type, resource_id),
            permission = %permission,
            "Permission check cache miss"
        );

        let allowed = self.inner.check_permission(
            resource_type,
            resource_id,
            permission,
            subject_type,
            subject_id,
        ).await?;

        // Cache the result
        let cached_result = CachedPermission {
            allowed,
            zed_token: self.latest_zed_token.read().await.clone(),
            cached_at: std::time::Instant::now(),
        };
        self.permission_cache.insert(cache_key, cached_result).await;

        Ok(allowed)
    }

    /// Write a relationship and invalidate relevant caches
    #[instrument(skip(self))]
    pub async fn write_relationship(
        &self,
        resource_type: &str,
        resource_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<String> {
        let token = self.inner.write_relationship(
            resource_type,
            resource_id,
            relation,
            subject_type,
            subject_id,
        ).await?;

        // Update latest ZedToken
        {
            let mut latest = self.latest_zed_token.write().await;
            *latest = Some(token.clone());
        }

        // Invalidate related cache entries if configured
        if self.config.invalidate_on_write {
            self.invalidate_for_resource(resource_type, resource_id).await;
            self.invalidate_for_subject(subject_type, subject_id).await;
        }

        Ok(token)
    }

    /// Delete a relationship and invalidate relevant caches
    #[instrument(skip(self))]
    pub async fn delete_relationship(
        &self,
        resource_type: &str,
        resource_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<String> {
        let token = self.inner.delete_relationship(
            resource_type,
            resource_id,
            relation,
            subject_type,
            subject_id,
        ).await?;

        // Update latest ZedToken
        {
            let mut latest = self.latest_zed_token.write().await;
            *latest = Some(token.clone());
        }

        // Invalidate related cache entries
        if self.config.invalidate_on_write {
            self.invalidate_for_resource(resource_type, resource_id).await;
            self.invalidate_for_subject(subject_type, subject_id).await;
        }

        Ok(token)
    }

    /// Invalidate all cache entries for a specific resource
    /// 
    /// Note: Moka doesn't support efficient partial invalidation by predicate,
    /// so we invalidate all entries when relationships change. This is conservative
    /// but correct. For production, consider more targeted invalidation.
    async fn invalidate_for_resource(&self, _resource_type: &str, _resource_id: &str) {
        // Conservative approach: invalidate all entries
        // In production, you might want to track keys by resource for targeted invalidation
        self.permission_cache.invalidate_all();
        self.metrics.invalidations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        debug!("Invalidated permission cache due to resource change");
    }

    /// Invalidate all cache entries for a specific subject
    async fn invalidate_for_subject(&self, _subject_type: &str, _subject_id: &str) {
        // Conservative approach: invalidate all entries
        self.permission_cache.invalidate_all();
        self.metrics.invalidations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        debug!("Invalidated permission cache due to subject change");
    }

    /// Invalidate entire cache
    pub async fn invalidate_all(&self) {
        self.permission_cache.invalidate_all();
        self.metrics.invalidations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        info!("Invalidated entire permission cache");
    }

    // =============================================================================
    // Resource-based consistency helpers
    // =============================================================================

    /// Check permission with resource's stored ZedToken
    /// 
    /// This is the recommended pattern for post-write consistency:
    /// 1. After modifying relationships, store the returned ZedToken on the resource
    /// 2. Use this method for subsequent permission checks on that resource
    /// 3. Ensures read-after-write consistency without fully_consistent overhead
    /// 
    /// # Example
    /// ```ignore
    /// // After granting permission, save the token
    /// let token = client.write_relationship(...).await?;
    /// resource.zed_token = Some(token);
    /// save_resource(&resource).await?;
    /// 
    /// // Later, check permission with the resource's token
    /// let allowed = client.check_permission_for_resource(
    ///     &resource.zed_token,
    ///     "document", &resource.id, "view",
    ///     "user", &user.id,
    /// ).await?;
    /// ```
    #[instrument(skip(self, resource_zed_token))]
    pub async fn check_permission_for_resource(
        &self,
        resource_zed_token: &Option<String>,
        resource_type: &str,
        resource_id: &str,
        permission: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<bool> {
        // Use at_least_as_fresh if we have a token, otherwise minimize_latency
        let (consistency, token) = match resource_zed_token {
            Some(token) => (ConsistencyMode::AtLeastAsFresh, Some(token.as_str())),
            None => (ConsistencyMode::MinimizeLatency, None),
        };

        self.check_permission(
            resource_type,
            resource_id,
            permission,
            subject_type,
            subject_id,
            consistency,
            token,
        ).await
    }

    /// Write relationship and return the ZedToken for storage
    /// 
    /// Use this when you want to track the token for a specific resource.
    /// The returned token should be stored on the resource for future
    /// `at_least_as_fresh` consistency checks.
    #[instrument(skip(self))]
    pub async fn write_relationship_with_token(
        &self,
        resource_type: &str,
        resource_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<String> {
        self.write_relationship(resource_type, resource_id, relation, subject_type, subject_id).await
    }

    /// Delete relationship and return the ZedToken for storage
    /// 
    /// Use this when you want to track the token for a specific resource.
    /// The returned token should be stored on the resource for future
    /// `at_least_as_fresh` consistency checks.
    #[instrument(skip(self))]
    pub async fn delete_relationship_with_token(
        &self,
        resource_type: &str,
        resource_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<String> {
        self.delete_relationship(resource_type, resource_id, relation, subject_type, subject_id).await
    }

    // =============================================================================
    // Passthrough methods (no caching needed)
    // =============================================================================

    /// Write schema (clears all caches)
    pub async fn write_schema(&self, schema: &str) -> Result<String> {
        let token = self.inner.write_schema(schema).await?;
        
        // Schema change invalidates everything
        self.invalidate_all().await;
        
        // Update ZedToken
        {
            let mut latest = self.latest_zed_token.write().await;
            *latest = Some(token.clone());
        }
        
        Ok(token)
    }

    /// Read schema (could be cached but typically low volume)
    pub async fn read_schema(&self) -> Result<String> {
        self.inner.read_schema().await
    }

    /// Health check
    pub async fn health_check(&self) -> Result<bool> {
        self.inner.health_check().await
    }

    /// Lookup resources (not cached - results can be large)
    pub async fn lookup_resources(
        &self,
        resource_type: &str,
        permission: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Vec<String>> {
        self.inner.lookup_resources(resource_type, permission, subject_type, subject_id).await
    }

    /// Lookup subjects (not cached - results can be large)
    pub async fn lookup_subjects(
        &self,
        resource_type: &str,
        resource_id: &str,
        permission: &str,
        subject_type: &str,
    ) -> Result<Vec<String>> {
        self.inner.lookup_subjects(resource_type, resource_id, permission, subject_type).await
    }

    /// Read relationships (not cached - typically for admin/debugging)
    #[allow(clippy::type_complexity)]
    pub async fn read_relationships(
        &self,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
        relation: Option<&str>,
        subject_type: Option<&str>,
        subject_id: Option<&str>,
    ) -> Result<Vec<(String, String, String, String, String, Option<String>)>> {
        self.inner.read_relationships(
            resource_type,
            resource_id,
            relation,
            subject_type,
            subject_id,
        ).await
    }
}

impl Clone for CachedSpiceDbClient {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config.clone(),
            permission_cache: self.permission_cache.clone(),
            latest_zed_token: self.latest_zed_token.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

impl std::fmt::Debug for CachedSpiceDbClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedSpiceDbClient")
            .field("cache_size", &self.permission_cache.entry_count())
            .field("hit_rate", &format!("{:.1}%", self.metrics.hit_rate() * 100.0))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_cache_key_equality() {
        let key1 = PermissionCacheKey::new("document", "doc1", "view", "user", "alice");
        let key2 = PermissionCacheKey::new("document", "doc1", "view", "user", "alice");
        let key3 = PermissionCacheKey::new("document", "doc1", "edit", "user", "alice");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_cache_metrics() {
        let metrics = CacheMetrics::default();
        assert_eq!(metrics.hit_rate(), 0.0);

        metrics.hits.fetch_add(3, std::sync::atomic::Ordering::Relaxed);
        metrics.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        assert_eq!(metrics.hit_rate(), 0.75);
    }
}
