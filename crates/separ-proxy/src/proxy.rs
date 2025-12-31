//! Main proxy server implementation

use std::net::SocketAddr;
use std::sync::Arc;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, instrument, warn, Instrument};

use separ_core::{Result, SeparError};
use separ_identity::ProviderRegistry;

use crate::auth::{AuthResult, ProxyAuthenticator, ProxyPrincipal};
use crate::config::ProxyConfig;
use crate::connection::{Connection, ConnectionPool};
use crate::protocol::{
    build_auth_request, build_backend_key_data, build_error_response,
    build_parameter_status, build_ready_for_query,
    parse_password_message, parse_startup_message, AuthRequest,
};

/// The main Separ Proxy server
pub struct SeparProxy {
    config: ProxyConfig,
    authenticator: Arc<ProxyAuthenticator>,
    connection_pool: Arc<ConnectionPool>,
}

impl SeparProxy {
    /// Create a new proxy server
    pub fn new(config: ProxyConfig, provider_registry: Arc<ProviderRegistry>) -> Self {
        let authenticator = Arc::new(ProxyAuthenticator::new(
            config.auth.clone(),
            provider_registry,
        ));
        let connection_pool = Arc::new(ConnectionPool::new(config.pool.clone()));

        Self {
            config,
            authenticator,
            connection_pool,
        }
    }

    /// Start the proxy server
    #[instrument(skip(self))]
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.listen_addr).await
            .map_err(|e| SeparError::Internal { message: e.to_string() })?;
        info!("Separ Proxy listening on {}", self.config.listen_addr);

        // Spawn cleanup task
        let pool = self.connection_pool.clone();
        let auth = self.authenticator.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                pool.cleanup_idle();
                auth.cleanup_cache();
            }
        });

        loop {
            let (stream, addr) = listener.accept().await
                .map_err(|e| SeparError::Internal { message: e.to_string() })?;
            info!("New connection from {}", addr);

            let handler = ConnectionHandler {
                config: self.config.clone(),
                authenticator: self.authenticator.clone(),
                connection_pool: self.connection_pool.clone(),
            };

            tokio::spawn(
                async move {
                    if let Err(e) = handler.handle(stream, addr).await {
                        error!("Connection error: {}", e);
                    }
                }
                .instrument(tracing::info_span!("connection", %addr)),
            );
        }
    }
}

/// Handles a single client connection
struct ConnectionHandler {
    config: ProxyConfig,
    authenticator: Arc<ProxyAuthenticator>,
    connection_pool: Arc<ConnectionPool>,
}

impl ConnectionHandler {
    #[instrument(skip(self, client_stream))]
    async fn handle(&self, mut client_stream: TcpStream, addr: SocketAddr) -> Result<()> {
        // Read startup message
        let startup = self.read_startup_message(&mut client_stream).await?;
        
        let username = startup.user().unwrap_or("unknown").to_string();
        let database = startup.database().unwrap_or(&username).to_string();

        debug!("Startup from user: {} database: {}", username, database);

        // Request password authentication
        let auth_request = build_auth_request(&AuthRequest::CleartextPassword);
        client_stream.write_all(&auth_request).await
            .map_err(|e| SeparError::Internal { message: e.to_string() })?;

        // Read password
        let password = self.read_password(&mut client_stream).await?;

        // Authenticate
        let principal = match self.authenticator.authenticate(
            &username,
            &password,
            startup.get("tenant"),
        ).await {
            AuthResult::Success(principal) => principal,
            AuthResult::Failed(failure) => {
                warn!("Authentication failed for {}: {}", username, failure.message);
                let error = build_error_response(
                    "FATAL",
                    "28P01",
                    &format!("authentication failed: {}", failure.message),
                );
                let _ = client_stream.write_all(&error).await;
                return Ok(());
            }
            AuthResult::NotApplicable => {
                let error = build_error_response(
                    "FATAL",
                    "28000",
                    "no applicable authentication method",
                );
                let _ = client_stream.write_all(&error).await;
                return Ok(());
            }
        };

        info!(
            "Authenticated {} as {} ({})",
            username,
            principal.identifier,
            principal.tenant_id
        );

        // Register connection
        let connection = match self.connection_pool.register_connection(
            principal.clone(),
            database.clone(),
        ) {
            Ok(conn) => conn,
            Err(e) => {
                let error = build_error_response(
                    "FATAL",
                    "53300",
                    &e.to_string(),
                );
                let _ = client_stream.write_all(&error).await;
                return Ok(());
            }
        };

        // Connect to backend
        let mut backend_stream = match TcpStream::connect(&self.config.backend_addr).await {
            Ok(stream) => stream,
            Err(e) => {
                error!("Failed to connect to backend: {}", e);
                let error = build_error_response(
                    "FATAL",
                    "08006",
                    &format!("backend connection failed: {}", e),
                );
                let _ = client_stream.write_all(&error).await;
                return Ok(());
            }
        };

        // Forward startup to backend
        self.forward_startup(&mut backend_stream, &startup, &principal).await?;

        // Complete authentication with client
        let auth_ok = build_auth_request(&AuthRequest::Ok);
        client_stream.write_all(&auth_ok).await
            .map_err(|e| SeparError::Internal { message: e.to_string() })?;

        // Send parameter statuses
        let params = build_parameter_status("server_version", "15.0");
        client_stream.write_all(&params).await
            .map_err(|e| SeparError::Internal { message: e.to_string() })?;

        let params = build_parameter_status("client_encoding", "UTF8");
        client_stream.write_all(&params).await
            .map_err(|e| SeparError::Internal { message: e.to_string() })?;

        // Send backend key data
        let conn_guard = connection.lock().await;
        let key_data = build_backend_key_data(
            conn_guard.id.0 as i32,
            rand::random(),
        );
        drop(conn_guard);
        client_stream.write_all(&key_data).await
            .map_err(|e| SeparError::Internal { message: e.to_string() })?;

        // Ready for query
        let ready = build_ready_for_query(b'I');
        client_stream.write_all(&ready).await
            .map_err(|e| SeparError::Internal { message: e.to_string() })?;

        // Proxy messages bidirectionally
        self.proxy_messages(
            &mut client_stream,
            &mut backend_stream,
            connection.clone(),
            &principal,
        ).await?;

        // Cleanup
        let conn_guard = connection.lock().await;
        self.connection_pool.unregister_connection(
            conn_guard.id,
            &principal.identifier,
        );

        Ok(())
    }

    async fn read_startup_message(
        &self,
        stream: &mut TcpStream,
    ) -> Result<crate::protocol::StartupMessage> {
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await
            .map_err(|e| SeparError::Internal { message: e.to_string() })?;
        
        if n < 8 {
            return Err(SeparError::Internal {
                message: "Invalid startup message".to_string(),
            });
        }

        parse_startup_message(&buf[..n]).map_err(|e| SeparError::Internal {
            message: format!("Failed to parse startup: {}", e),
        })
    }

    async fn read_password(&self, stream: &mut TcpStream) -> Result<String> {
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await
            .map_err(|e| SeparError::Internal { message: e.to_string() })?;

        parse_password_message(&buf[..n]).map_err(|e| SeparError::Internal {
            message: format!("Failed to parse password: {}", e),
        })
    }

    async fn forward_startup(
        &self,
        backend: &mut TcpStream,
        startup: &crate::protocol::StartupMessage,
        principal: &ProxyPrincipal,
    ) -> Result<()> {
        // Build startup message with principal metadata
        let mut buf = BytesMut::new();
        
        // Protocol version (3.0)
        buf.put_i32(196608);
        
        // User (from principal)
        buf.put_slice(b"user\0");
        buf.put_slice(principal.identifier.as_bytes());
        buf.put_u8(0);
        
        // Database
        if let Some(db) = startup.database() {
            buf.put_slice(b"database\0");
            buf.put_slice(db.as_bytes());
            buf.put_u8(0);
        }

        // Add tenant metadata
        buf.put_slice(b"separ_tenant_id\0");
        buf.put_slice(principal.tenant_id.to_string().as_bytes());
        buf.put_u8(0);

        // Add principal type
        buf.put_slice(b"separ_principal_type\0");
        buf.put_slice(format!("{:?}", principal.principal_type).as_bytes());
        buf.put_u8(0);

        // Terminator
        buf.put_u8(0);

        // Prepend length
        let length = buf.len() as i32 + 4;
        let mut msg = BytesMut::with_capacity(4 + buf.len());
        msg.put_i32(length);
        msg.put(buf);

        backend.write_all(&msg).await
            .map_err(|e| SeparError::Internal { message: e.to_string() })?;

        // Read and handle backend authentication
        let mut response = vec![0u8; 8192];
        let _n = backend.read(&mut response).await
            .map_err(|e| SeparError::Internal { message: e.to_string() })?;

        // TODO: Handle backend authentication properly
        // For now, assume trust authentication on backend

        Ok(())
    }

    async fn proxy_messages(
        &self,
        client: &mut TcpStream,
        backend: &mut TcpStream,
        connection: Arc<tokio::sync::Mutex<Connection>>,
        principal: &ProxyPrincipal,
    ) -> Result<()> {
        let mut client_buf = vec![0u8; 65536];
        let mut backend_buf = vec![0u8; 65536];

        loop {
            tokio::select! {
                // Client to backend
                result = client.read(&mut client_buf) => {
                    match result {
                        Ok(0) => {
                            debug!("Client disconnected");
                            return Ok(());
                        }
                        Ok(n) => {
                            // Record activity
                            connection.lock().await.record_activity();
                            
                            // TODO: Inspect query for authorization
                            // For now, pass through
                            backend.write_all(&client_buf[..n]).await
                                .map_err(|e| SeparError::Internal { message: e.to_string() })?;
                        }
                        Err(e) => {
                            error!("Client read error: {}", e);
                            return Err(SeparError::Internal { message: e.to_string() });
                        }
                    }
                }
                
                // Backend to client
                result = backend.read(&mut backend_buf) => {
                    match result {
                        Ok(0) => {
                            debug!("Backend disconnected");
                            return Ok(());
                        }
                        Ok(n) => {
                            client.write_all(&backend_buf[..n]).await
                                .map_err(|e| SeparError::Internal { message: e.to_string() })?;
                        }
                        Err(e) => {
                            error!("Backend read error: {}", e);
                            return Err(SeparError::Internal { message: e.to_string() });
                        }
                    }
                }
            }
        }
    }
}

fn rand_process_id() -> i32 {
    rand::random()
}

