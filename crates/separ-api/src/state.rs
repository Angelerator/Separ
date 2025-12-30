//! Application state for API handlers

use std::sync::Arc;
use sqlx::PgPool;

use separ_db::repositories::{
    PgTenantRepository, PgWorkspaceRepository, PgApplicationRepository,
    PgUserRepository, PgGroupRepository, PgOAuthProviderRepository,
    PgSyncConfigRepository, PgAuditRepository,
};
use separ_spicedb::SpiceDbAuthorizationService;
use separ_oauth::JwtService;

/// Concrete application state with all services
#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
    pub auth_service: Arc<SpiceDbAuthorizationService>,
    pub tenant_repo: Arc<PgTenantRepository>,
    pub workspace_repo: Arc<PgWorkspaceRepository>,
    pub app_repo: Arc<PgApplicationRepository>,
    pub user_repo: Arc<PgUserRepository>,
    pub group_repo: Arc<PgGroupRepository>,
    pub oauth_repo: Arc<PgOAuthProviderRepository>,
    pub sync_repo: Arc<PgSyncConfigRepository>,
    pub audit_repo: Arc<PgAuditRepository>,
    pub jwt_service: Arc<JwtService>,
}

impl AppState {
    /// Create new application state from components
    pub fn new(
        db_pool: PgPool,
        auth_service: SpiceDbAuthorizationService,
        jwt_service: JwtService,
    ) -> Self {
        Self {
            tenant_repo: Arc::new(PgTenantRepository::new(db_pool.clone())),
            workspace_repo: Arc::new(PgWorkspaceRepository::new(db_pool.clone())),
            app_repo: Arc::new(PgApplicationRepository::new(db_pool.clone())),
            user_repo: Arc::new(PgUserRepository::new(db_pool.clone())),
            group_repo: Arc::new(PgGroupRepository::new(db_pool.clone())),
            oauth_repo: Arc::new(PgOAuthProviderRepository::new(db_pool.clone())),
            sync_repo: Arc::new(PgSyncConfigRepository::new(db_pool.clone())),
            audit_repo: Arc::new(PgAuditRepository::new(db_pool.clone())),
            db_pool,
            auth_service: Arc::new(auth_service),
            jwt_service: Arc::new(jwt_service),
        }
    }
}
