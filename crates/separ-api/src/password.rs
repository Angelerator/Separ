//! Password hashing and verification using Argon2id
//!
//! Follows OWASP Password Storage Cheat Sheet recommendations:
//! - Uses Argon2id variant (hybrid defense against side-channel and GPU attacks)
//! - Memory: 64 MiB (balanced profile)
//! - Iterations: 3 (time cost)
//! - Parallelism: 4 threads
//! - Salt: 16 bytes (128 bits)
//! - Hash length: 32 bytes (256 bits)
//!
//! Target latency: 250-500ms on modern hardware
//!
//! References:
//! - RFC 9106: https://www.rfc-editor.org/rfc/rfc9106.html
//! - OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use tracing::{debug, warn};

/// OWASP-recommended Argon2id parameters (balanced profile)
/// These provide ~300-500ms hashing time on typical server hardware
const MEMORY_COST_KIB: u32 = 64 * 1024; // 64 MiB
const TIME_COST: u32 = 3; // 3 iterations
const PARALLELISM: u32 = 4; // 4 threads
const OUTPUT_LEN: usize = 32; // 32 bytes (256 bits)

/// Create Argon2id hasher with OWASP-recommended parameters
fn create_argon2() -> Argon2<'static> {
    let params = Params::new(MEMORY_COST_KIB, TIME_COST, PARALLELISM, Some(OUTPUT_LEN))
        .expect("Valid Argon2 parameters");
    
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a password using Argon2id with OWASP-recommended parameters
/// 
/// This is a CPU-intensive operation. For async contexts, use `hash_password_async`.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = create_argon2();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Hash a password asynchronously (runs in spawn_blocking to avoid blocking async runtime)
/// 
/// Use this in async HTTP handlers to prevent blocking the Tokio runtime.
pub async fn hash_password_async(password: String) -> Result<String, argon2::password_hash::Error> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .expect("Hashing task panicked")
}

/// Verify a password against a stored hash
/// 
/// This is a CPU-intensive operation. For async contexts, use `verify_password_async`.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(e) => {
            warn!("Failed to parse password hash: {}", e);
            return false;
        }
    };

    // Use the same Argon2 configuration for verification
    // Note: The hash contains the parameters, so Argon2 will use those
    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => {
            debug!("Password verification successful");
            true
        }
        Err(_) => {
            debug!("Password verification failed");
            false
        }
    }
}

/// Verify a password asynchronously (runs in spawn_blocking to avoid blocking async runtime)
/// 
/// Use this in async HTTP handlers to prevent blocking the Tokio runtime.
pub async fn verify_password_async(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .unwrap_or(false)
}

/// Check if a password hash needs to be re-hashed with stronger parameters
/// 
/// Call this during login to detect legacy hashes that need upgrading.
/// Returns true if the hash uses weaker parameters than current recommendations.
pub fn needs_rehash(hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return true, // Invalid hash format, definitely needs rehash
    };

    // Check algorithm - must be Argon2id
    if parsed_hash.algorithm.as_str() != "argon2id" {
        return true;
    }

    // Extract memory cost (m parameter) - in the PHC format
    if let Some(m) = parsed_hash.params.get_str("m") {
        if let Ok(memory) = m.parse::<u32>() {
            if memory < MEMORY_COST_KIB {
                return true;
            }
        }
    }
    
    // Extract time cost (t parameter)
    if let Some(t) = parsed_hash.params.get_str("t") {
        if let Ok(time) = t.parse::<u32>() {
            if time < TIME_COST {
                return true;
            }
        }
    }

    false
}

/// Generate a random password
pub fn generate_password(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "my_secure_password_123!";
        let hash = hash_password(password).expect("hashing should work");

        // Verify correct password
        assert!(verify_password(password, &hash));

        // Verify wrong password fails
        assert!(!verify_password("wrong_password", &hash));
    }

    #[test]
    fn test_generate_password() {
        let password = generate_password(24);
        assert_eq!(password.len(), 24);

        // Generate another - should be different
        let password2 = generate_password(24);
        assert_ne!(password, password2);
    }

    #[test]
    fn test_hash_format_argon2id() {
        let password = "test";
        let hash = hash_password(password).expect("hashing should work");

        // Must use Argon2id variant
        assert!(hash.starts_with("$argon2id$"));
        
        // Verify parameters are in the hash
        assert!(hash.contains("m=65536")); // 64 MiB
        assert!(hash.contains("t=3"));     // 3 iterations
        assert!(hash.contains("p=4"));     // 4 parallelism
    }

    #[test]
    fn test_needs_rehash_current_params() {
        let password = "test";
        let hash = hash_password(password).expect("hashing should work");
        
        // Hash with current params should NOT need rehash
        assert!(!needs_rehash(&hash));
    }

    #[test]
    fn test_needs_rehash_weak_params() {
        // A hash with weaker parameters (default Argon2 with lower memory)
        // This simulates a legacy hash
        let weak_hash = "$argon2id$v=19$m=4096,t=3,p=1$salt$hash";
        
        // Should need rehash due to low memory cost
        assert!(needs_rehash(weak_hash));
    }

    #[test]
    fn test_needs_rehash_argon2i_variant() {
        // Argon2i variant (not recommended for password hashing)
        let argon2i_hash = "$argon2i$v=19$m=65536,t=3,p=4$salt$hash";
        
        // Should need rehash due to wrong variant
        assert!(needs_rehash(argon2i_hash));
    }

    #[tokio::test]
    async fn test_async_hash_and_verify() {
        let password = "async_test_password!";
        let hash = hash_password_async(password.to_string()).await.expect("hashing should work");
        
        // Verify async
        assert!(verify_password_async(password.to_string(), hash).await);
    }
}
