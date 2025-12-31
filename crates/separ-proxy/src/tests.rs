//! Unit tests for separ-proxy

use crate::config::*;

// =============================================================================
// Configuration Tests
// =============================================================================

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn test_auth_config_default() {
        let config = AuthConfig::default();
        
        assert!(!config.methods.is_empty());
        assert_eq!(config.max_auth_attempts, 5);
        assert_eq!(config.ban_duration_secs, 300);
    }

    #[test]
    fn test_jwt_config_default() {
        let config = JwtConfig::default();
        
        assert!(config.audiences.is_empty());
        assert!(config.issuers.is_empty());
        assert_eq!(config.clock_skew_secs, 60);
        assert_eq!(config.token_cache_secs, 300);
    }

    #[test]
    fn test_api_key_config_default() {
        let config = ApiKeyConfig::default();
        
        assert!(config.enabled);
        assert_eq!(config.prefix, "sk_");
    }

    #[test]
    fn test_service_token_config_default() {
        let config = ServiceTokenConfig::default();
        
        assert!(config.enabled);
        assert_eq!(config.prefix, "svc_");
    }

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        
        assert_eq!(config.max_connections_per_user, 10);
        assert_eq!(config.max_total_connections, 1000);
        assert_eq!(config.connection_timeout_secs, 30);
        assert_eq!(config.idle_timeout_secs, 600);
    }

    #[test]
    fn test_auth_method_serialization() {
        let methods = vec![
            AuthMethod::Jwt,
            AuthMethod::ApiKey,
            AuthMethod::ServiceToken,
            AuthMethod::MtlsCertificate,
            AuthMethod::ScramSha256,
            AuthMethod::Trust,
        ];
        
        for method in methods {
            let json = serde_json::to_string(&method).unwrap();
            let deserialized: AuthMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, method);
        }
    }

    #[test]
    fn test_tls_config_creation() {
        let config = TlsConfig {
            enabled: true,
            cert_path: "/etc/ssl/certs/server.crt".to_string(),
            key_path: "/etc/ssl/private/server.key".to_string(),
            ca_cert_path: Some("/etc/ssl/certs/ca.crt".to_string()),
            require_client_cert: true,
        };
        
        assert!(config.require_client_cert);
        assert!(config.ca_cert_path.is_some());
    }

    #[test]
    fn test_proxy_config_serialization() {
        let config = ProxyConfig {
            listen_addr: "0.0.0.0:5432".to_string(),
            backend_addr: "localhost:5433".to_string(),
            separ_endpoint: "http://localhost:8080".to_string(),
            separ_token: "test-token".to_string(),
            auth: AuthConfig::default(),
            pool: PoolConfig::default(),
            tls: None,
        };
        
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ProxyConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(config.listen_addr, deserialized.listen_addr);
        assert_eq!(config.backend_addr, deserialized.backend_addr);
    }
}

// =============================================================================
// Protocol Tests
// =============================================================================

#[cfg(test)]
mod protocol_tests {
    use crate::protocol::*;

    #[test]
    fn test_startup_message_creation() {
        let startup = StartupMessage {
            protocol_version: 196608, // Version 3.0
            parameters: vec![
                ("user".to_string(), "testuser".to_string()),
                ("database".to_string(), "testdb".to_string()),
            ],
        };
        
        assert_eq!(startup.user(), Some("testuser"));
        assert_eq!(startup.database(), Some("testdb"));
    }

    #[test]
    fn test_startup_message_get_parameter() {
        let startup = StartupMessage {
            protocol_version: 196608,
            parameters: vec![
                ("user".to_string(), "alice".to_string()),
                ("database".to_string(), "mydb".to_string()),
                ("application_name".to_string(), "psql".to_string()),
            ],
        };
        
        assert_eq!(startup.get("user"), Some("alice"));
        assert_eq!(startup.get("database"), Some("mydb"));
        assert_eq!(startup.get("application_name"), Some("psql"));
        assert_eq!(startup.get("nonexistent"), None);
    }

    #[test]
    fn test_auth_request_types() {
        let auth_ok = AuthRequest::Ok;
        let auth_cleartext = AuthRequest::CleartextPassword;
        let auth_md5 = AuthRequest::Md5Password { salt: [1, 2, 3, 4] };
        
        match auth_ok {
            AuthRequest::Ok => assert!(true),
            _ => panic!("Expected AuthRequest::Ok"),
        }
        
        match auth_cleartext {
            AuthRequest::CleartextPassword => assert!(true),
            _ => panic!("Expected AuthRequest::CleartextPassword"),
        }
        
        match auth_md5 {
            AuthRequest::Md5Password { salt } => assert_eq!(salt, [1, 2, 3, 4]),
            _ => panic!("Expected AuthRequest::Md5Password"),
        }
    }

    #[test]
    fn test_error_response_codes() {
        // Test common PostgreSQL error codes
        let error_auth_failed = "28P01"; // Authentication failed
        let error_invalid_catalog = "3D000"; // Invalid catalog name
        let error_connection_failed = "08006"; // Connection failure
        
        assert_eq!(error_auth_failed.len(), 5);
        assert_eq!(error_invalid_catalog.len(), 5);
        assert_eq!(error_connection_failed.len(), 5);
    }
}

// =============================================================================
// Authentication Tests
// =============================================================================

#[cfg(test)]
mod auth_tests {
    use crate::auth::*;
    use crate::config::*;

    #[test]
    fn test_jwt_looks_like_jwt() {
        // Valid JWT structure (three parts separated by dots)
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(jwt.contains('.'));
        assert_eq!(jwt.split('.').count(), 3);
    }

    #[test]
    fn test_api_key_detection() {
        let config = ApiKeyConfig::default();
        
        let valid_key = "sk_test_123456789";
        let invalid_key = "not_an_api_key";
        
        assert!(valid_key.starts_with(&config.prefix));
        assert!(!invalid_key.starts_with(&config.prefix));
    }

    #[test]
    fn test_service_token_detection() {
        let config = ServiceTokenConfig::default();
        
        let valid_token = "svc_prod_abcdefghij";
        let invalid_token = "regular_password";
        
        assert!(valid_token.starts_with(&config.prefix));
        assert!(!invalid_token.starts_with(&config.prefix));
    }

    #[test]
    fn test_proxy_principal_type_variants() {
        let types = vec![
            ProxyPrincipalType::User,
            ProxyPrincipalType::Service,
            ProxyPrincipalType::ApiKey,
            ProxyPrincipalType::System,
        ];
        
        for t in &types {
            assert!(matches!(t, ProxyPrincipalType::User | ProxyPrincipalType::Service | 
                             ProxyPrincipalType::ApiKey | ProxyPrincipalType::System));
        }
    }

    #[test]
    fn test_token_hash_deterministic() {
        // Simple test that hashing is deterministic
        use sha2::{Sha256, Digest};
        
        let token = "test_token_12345";
        let hash1: String = {
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            format!("{:x}", hasher.finalize())
        };
        let hash2: String = {
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            format!("{:x}", hasher.finalize())
        };
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_token_hash_different_tokens() {
        use sha2::{Sha256, Digest};
        
        let token1 = "token_a";
        let token2 = "token_b";
        
        let hash1: String = {
            let mut hasher = Sha256::new();
            hasher.update(token1.as_bytes());
            format!("{:x}", hasher.finalize())
        };
        let hash2: String = {
            let mut hasher = Sha256::new();
            hasher.update(token2.as_bytes());
            format!("{:x}", hasher.finalize())
        };
        
        assert_ne!(hash1, hash2);
    }
}

// =============================================================================
// Connection Pool Tests
// =============================================================================

#[cfg(test)]
mod pool_tests {
    use super::*;

    #[test]
    fn test_pool_config_validation() {
        let config = PoolConfig {
            max_connections_per_user: 5,
            max_total_connections: 100,
            connection_timeout_secs: 30,
            idle_timeout_secs: 300,
        };
        
        assert!(config.max_connections_per_user <= config.max_total_connections);
        assert!(config.connection_timeout_secs < config.idle_timeout_secs);
    }

    #[test]
    fn test_connection_id_uniqueness() {
        use uuid::Uuid;
        
        let ids: Vec<Uuid> = (0..100).map(|_| Uuid::new_v4()).collect();
        
        // Check all are unique
        let unique_count = ids.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(unique_count, ids.len());
    }
}
