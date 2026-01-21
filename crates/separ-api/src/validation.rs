//! Input validation and sanitization
//!
//! Security measures:
//! - Email format validation
//! - Password strength requirements
//! - Input length limits
//! - Character sanitization
//! - UUID validation

use once_cell::sync::Lazy;
use regex::Regex;

/// Maximum length for common string fields
pub const MAX_NAME_LENGTH: usize = 255;
pub const MAX_EMAIL_LENGTH: usize = 320; // RFC 5321
pub const MAX_DESCRIPTION_LENGTH: usize = 4096;
pub const MAX_SLUG_LENGTH: usize = 128;
pub const MIN_PASSWORD_LENGTH: usize = 8;
pub const MAX_PASSWORD_LENGTH: usize = 128;

/// Email validation regex (RFC 5322 simplified)
static EMAIL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap());

/// Slug validation regex (lowercase alphanumeric + hyphens)
static SLUG_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").unwrap());

/// UUID validation regex
static UUID_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap()
});

/// Validation error
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
    pub code: String,
}

impl ValidationError {
    pub fn new(field: &str, message: &str, code: &str) -> Self {
        Self {
            field: field.to_string(),
            message: message.to_string(),
            code: code.to_string(),
        }
    }
}

/// Validation result
pub type ValidationResult = Result<(), Vec<ValidationError>>;

/// Input validator
pub struct Validator {
    errors: Vec<ValidationError>,
}

impl Validator {
    pub fn new() -> Self {
        Self { errors: vec![] }
    }

    /// Validate and return result
    pub fn validate(self) -> ValidationResult {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors)
        }
    }

    /// Add an error
    pub fn error(&mut self, field: &str, message: &str, code: &str) -> &mut Self {
        self.errors.push(ValidationError::new(field, message, code));
        self
    }

    /// Validate email format
    pub fn email(&mut self, field: &str, value: &str) -> &mut Self {
        if value.is_empty() {
            self.error(field, "Email is required", "required");
        } else if value.len() > MAX_EMAIL_LENGTH {
            self.error(field, "Email is too long", "too_long");
        } else if !EMAIL_REGEX.is_match(value) {
            self.error(field, "Invalid email format", "invalid_format");
        }
        self
    }

    /// Validate optional email
    pub fn email_optional(&mut self, field: &str, value: Option<&str>) -> &mut Self {
        if let Some(v) = value {
            if !v.is_empty() {
                self.email(field, v);
            }
        }
        self
    }

    /// Validate password strength
    pub fn password(&mut self, field: &str, value: &str) -> &mut Self {
        if value.len() < MIN_PASSWORD_LENGTH {
            self.error(
                field,
                &format!(
                    "Password must be at least {} characters",
                    MIN_PASSWORD_LENGTH
                ),
                "too_short",
            );
        } else if value.len() > MAX_PASSWORD_LENGTH {
            self.error(field, "Password is too long", "too_long");
        }

        // Check for basic complexity
        let has_uppercase = value.chars().any(|c| c.is_uppercase());
        let has_lowercase = value.chars().any(|c| c.is_lowercase());
        let has_digit = value.chars().any(|c| c.is_ascii_digit());

        if !has_uppercase || !has_lowercase || !has_digit {
            self.error(
                field,
                "Password must contain uppercase, lowercase, and a number",
                "weak_password",
            );
        }

        self
    }

    /// Validate name/display name
    pub fn name(&mut self, field: &str, value: &str) -> &mut Self {
        if value.is_empty() {
            self.error(field, "Name is required", "required");
        } else if value.len() > MAX_NAME_LENGTH {
            self.error(field, "Name is too long", "too_long");
        } else if value.trim().is_empty() {
            self.error(field, "Name cannot be only whitespace", "invalid");
        }
        self
    }

    /// Validate optional name
    pub fn name_optional(&mut self, field: &str, value: Option<&str>) -> &mut Self {
        if let Some(v) = value {
            if !v.is_empty() && v.len() > MAX_NAME_LENGTH {
                self.error(field, "Name is too long", "too_long");
            }
        }
        self
    }

    /// Validate slug format
    pub fn slug(&mut self, field: &str, value: &str) -> &mut Self {
        if value.is_empty() {
            self.error(field, "Slug is required", "required");
        } else if value.len() > MAX_SLUG_LENGTH {
            self.error(field, "Slug is too long", "too_long");
        } else if !SLUG_REGEX.is_match(value) {
            self.error(
                field,
                "Slug must be lowercase alphanumeric with hyphens",
                "invalid_format",
            );
        }
        self
    }

    /// Validate UUID format
    pub fn uuid(&mut self, field: &str, value: &str) -> &mut Self {
        if !UUID_REGEX.is_match(&value.to_lowercase()) {
            self.error(field, "Invalid UUID format", "invalid_format");
        }
        self
    }

    /// Validate string length
    pub fn max_length(&mut self, field: &str, value: &str, max: usize) -> &mut Self {
        if value.len() > max {
            self.error(
                field,
                &format!("Must be at most {} characters", max),
                "too_long",
            );
        }
        self
    }

    /// Validate required field
    pub fn required(&mut self, field: &str, value: &str) -> &mut Self {
        if value.trim().is_empty() {
            self.error(field, "This field is required", "required");
        }
        self
    }

    /// Validate required option
    pub fn required_option<T>(&mut self, field: &str, value: &Option<T>) -> &mut Self {
        if value.is_none() {
            self.error(field, "This field is required", "required");
        }
        self
    }
}

impl Default for Validator {
    fn default() -> Self {
        Self::new()
    }
}

/// Sanitize a string by removing control characters
pub fn sanitize_string(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t')
        .collect()
}

/// Sanitize a string for logging (mask sensitive data)
pub fn sanitize_for_log(input: &str) -> String {
    if input.len() <= 4 {
        "*".repeat(input.len())
    } else {
        format!("{}***{}", &input[..2], &input[input.len() - 2..])
    }
}

/// Check if a string contains potentially dangerous characters
pub fn is_safe_string(input: &str) -> bool {
    !input
        .chars()
        .any(|c| c == '<' || c == '>' || c == '\'' || c == '"' || c == '\\' || c == '\0')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_validation() {
        let mut v = Validator::new();
        v.email("email", "test@example.com");
        assert!(v.validate().is_ok());

        let mut v = Validator::new();
        v.email("email", "invalid-email");
        assert!(v.validate().is_err());
    }

    #[test]
    fn test_password_validation() {
        let mut v = Validator::new();
        v.password("password", "StrongPass123");
        assert!(v.validate().is_ok());

        let mut v = Validator::new();
        v.password("password", "weak");
        assert!(v.validate().is_err());

        let mut v = Validator::new();
        v.password("password", "nouppercase123");
        assert!(v.validate().is_err());
    }

    #[test]
    fn test_slug_validation() {
        let mut v = Validator::new();
        v.slug("slug", "valid-slug-123");
        assert!(v.validate().is_ok());

        let mut v = Validator::new();
        v.slug("slug", "Invalid Slug!");
        assert!(v.validate().is_err());
    }

    #[test]
    fn test_uuid_validation() {
        let mut v = Validator::new();
        v.uuid("id", "550e8400-e29b-41d4-a716-446655440000");
        assert!(v.validate().is_ok());

        let mut v = Validator::new();
        v.uuid("id", "not-a-uuid");
        assert!(v.validate().is_err());
    }

    #[test]
    fn test_sanitize_string() {
        assert_eq!(sanitize_string("hello\x00world"), "helloworld");
        assert_eq!(sanitize_string("hello\nworld"), "hello\nworld");
    }

    #[test]
    fn test_sanitize_for_log() {
        assert_eq!(sanitize_for_log("password123"), "pa***23");
        assert_eq!(sanitize_for_log("abc"), "***");
    }
}
