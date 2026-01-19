//! Password hashing and verification using Argon2
//!
//! Uses Argon2id which is the recommended variant for password hashing.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use tracing::{debug, warn};

/// Hash a password using Argon2id
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a password against a stored hash
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(e) => {
            warn!("Failed to parse password hash: {}", e);
            return false;
        }
    };

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
    fn test_hash_format() {
        let password = "test";
        let hash = hash_password(password).expect("hashing should work");

        // Argon2 hashes start with $argon2
        assert!(hash.starts_with("$argon2"));
    }
}
