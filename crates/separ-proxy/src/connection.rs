//! Connection management and pooling

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{info, warn};

use separ_core::{Result, SeparError};

use crate::auth::ProxyPrincipal;
use crate::config::PoolConfig;

/// Connection identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u64);

impl ConnectionId {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "conn_{}", self.0)
    }
}

/// Active connection state
#[derive(Debug)]
pub struct Connection {
    /// Unique connection ID
    pub id: ConnectionId,
    /// Authenticated principal
    pub principal: ProxyPrincipal,
    /// Target database
    pub database: String,
    /// When the connection was established
    pub connected_at: DateTime<Utc>,
    /// Last activity time
    pub last_activity: DateTime<Utc>,
    /// Number of queries executed
    pub query_count: u64,
    /// Connection metadata
    pub metadata: HashMap<String, String>,
}

impl Connection {
    pub fn new(principal: ProxyPrincipal, database: String) -> Self {
        let now = Utc::now();
        Self {
            id: ConnectionId::new(),
            principal,
            database,
            connected_at: now,
            last_activity: now,
            query_count: 0,
            metadata: HashMap::new(),
        }
    }

    pub fn record_activity(&mut self) {
        self.last_activity = Utc::now();
        self.query_count += 1;
    }
}

/// Backend connection to the actual database
pub struct BackendConnection {
    pub stream: TcpStream,
    pub process_id: i32,
    pub secret_key: i32,
    pub parameters: HashMap<String, String>,
}

/// Connection pool for backend connections
pub struct ConnectionPool {
    config: PoolConfig,
    /// Active connections by connection ID
    active_connections: DashMap<ConnectionId, Arc<Mutex<Connection>>>,
    /// Connection counts by user
    connections_by_user: DashMap<String, u32>,
    /// Total connection count
    total_connections: AtomicU64,
}

impl ConnectionPool {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            active_connections: DashMap::new(),
            connections_by_user: DashMap::new(),
            total_connections: AtomicU64::new(0),
        }
    }

    /// Register a new connection
    pub fn register_connection(
        &self,
        principal: ProxyPrincipal,
        database: String,
    ) -> Result<Arc<Mutex<Connection>>> {
        // Check user limit
        let user_key = principal.identifier.clone();
        let user_count = self
            .connections_by_user
            .get(&user_key)
            .map(|c| *c)
            .unwrap_or(0);

        if user_count >= self.config.max_connections_per_user {
            return Err(SeparError::Internal {
                message: format!(
                    "Maximum connections per user ({}) exceeded",
                    self.config.max_connections_per_user
                ),
            });
        }

        // Check total limit
        let total = self.total_connections.load(Ordering::Relaxed);
        if total >= self.config.max_total_connections as u64 {
            return Err(SeparError::Internal {
                message: format!(
                    "Maximum total connections ({}) exceeded",
                    self.config.max_total_connections
                ),
            });
        }

        // Create connection
        let connection = Connection::new(principal, database);
        let connection_id = connection.id;
        let connection = Arc::new(Mutex::new(connection));

        // Register
        self.active_connections
            .insert(connection_id, connection.clone());
        *self.connections_by_user.entry(user_key).or_insert(0) += 1;
        self.total_connections.fetch_add(1, Ordering::Relaxed);

        info!("Registered new connection: {}", connection_id);

        Ok(connection)
    }

    /// Unregister a connection
    pub fn unregister_connection(&self, connection_id: ConnectionId, user_identifier: &str) {
        if self.active_connections.remove(&connection_id).is_some() {
            self.total_connections.fetch_sub(1, Ordering::Relaxed);

            if let Some(mut count) = self.connections_by_user.get_mut(user_identifier) {
                if *count > 0 {
                    *count -= 1;
                }
            }

            info!("Unregistered connection: {}", connection_id);
        }
    }

    /// Get connection by ID
    pub fn get_connection(&self, connection_id: ConnectionId) -> Option<Arc<Mutex<Connection>>> {
        self.active_connections
            .get(&connection_id)
            .map(|c| c.clone())
    }

    /// Get current connection statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            total_connections: self.total_connections.load(Ordering::Relaxed),
            unique_users: self.connections_by_user.len(),
        }
    }

    /// Cleanup idle connections
    pub fn cleanup_idle(&self) {
        let cutoff = Utc::now() - chrono::Duration::seconds(self.config.idle_timeout_secs as i64);
        let mut to_remove = Vec::new();

        for entry in self.active_connections.iter() {
            let conn_id = *entry.key();
            if let Ok(conn) = entry.value().try_lock() {
                if conn.last_activity < cutoff {
                    to_remove.push((conn_id, conn.principal.identifier.clone()));
                }
            }
        }

        for (conn_id, user) in to_remove {
            warn!("Removing idle connection: {}", conn_id);
            self.unregister_connection(conn_id, &user);
        }
    }
}

/// Connection pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: u64,
    pub unique_users: usize,
}
