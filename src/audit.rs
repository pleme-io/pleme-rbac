//! Audit logging utilities for authorization events
//!
//! This module provides standardized audit logging for security-sensitive operations.
//! All logged events include user context (user_id, email, product) for compliance tracking.
//!
//! # Usage
//!
//! ```rust,no_run
//! use async_graphql::Context;
//! use pleme_rbac::audit::{audit_info, audit_warn, audit_error, AuditEvent};
//!
//! async fn delete_product(ctx: &Context<'_>, product_id: uuid::Uuid) -> async_graphql::Result<bool> {
//!     // Log security-sensitive operation
//!     audit_warn!(ctx, "delete_product",
//!         product_id = %product_id,
//!         "Admin deleting product"
//!     );
//!
//!     // ... business logic
//!     Ok(true)
//! }
//! ```

use crate::AuthzContext;

#[cfg(feature = "logging")]
use tracing::{info, warn, error, debug};

/// Audit event severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLevel {
    /// Informational - normal operations (e.g., user viewed dashboard)
    Info,
    /// Warning - security-sensitive operations (e.g., admin deleted data)
    Warn,
    /// Error - security violations or auth failures
    Error,
    /// Debug - development/troubleshooting only
    Debug,
}

/// Structured audit event
///
/// Contains all context needed for security audit trails.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// User who performed the action
    pub user_id: uuid::Uuid,
    /// User email
    pub email: String,
    /// Product scope
    pub product: String,
    /// Action performed (e.g., "delete_product", "refund_order")
    pub action: String,
    /// Severity level
    pub level: AuditLevel,
    /// Human-readable message
    pub message: String,
    /// Additional structured data (key-value pairs)
    pub metadata: std::collections::HashMap<String, String>,
}

impl AuditEvent {
    /// Create new audit event from auth context
    #[cfg(feature = "logging")]
    pub fn new(
        authz: &AuthzContext,
        action: impl Into<String>,
        level: AuditLevel,
        message: impl Into<String>,
    ) -> Self {
        Self {
            user_id: authz.user_id,
            email: authz.email.clone(),
            product: authz.product.clone(),
            action: action.into(),
            level,
            message: message.into(),
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Add metadata field
    #[cfg(feature = "logging")]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Log the audit event using tracing
    #[cfg(feature = "logging")]
    pub fn log(&self) {
        match self.level {
            AuditLevel::Info => {
                info!(
                    user_id = %self.user_id,
                    email = %self.email,
                    product = %self.product,
                    action = %self.action,
                    "{}", self.message
                );
            }
            AuditLevel::Warn => {
                warn!(
                    user_id = %self.user_id,
                    email = %self.email,
                    product = %self.product,
                    action = %self.action,
                    "{}", self.message
                );
            }
            AuditLevel::Error => {
                error!(
                    user_id = %self.user_id,
                    email = %self.email,
                    product = %self.product,
                    action = %self.action,
                    "{}", self.message
                );
            }
            AuditLevel::Debug => {
                debug!(
                    user_id = %self.user_id,
                    email = %self.email,
                    product = %self.product,
                    action = %self.action,
                    "{}", self.message
                );
            }
        }
    }
}

// ============ Audit Logging Macros ============

/// Log INFO-level audit event
///
/// # Example
///
/// ```rust,ignore
/// use pleme_rbac::audit_info;
///
/// async fn approve_product(ctx: &Context<'_>, product_id: Uuid) -> Result<Product> {
///     audit_info!(ctx, "approve_product",
///         product_id = %product_id,
///         "Staff approved product for publication"
///     );
///     // ... business logic
/// }
/// ```
#[cfg(all(feature = "logging", feature = "graphql-integration"))]
#[macro_export]
macro_rules! audit_info {
    ($ctx:expr, $action:expr, $($key:tt = $value:expr),* $(,)? , $message:expr) => {{
        if let Ok(authz) = $crate::graphql::get_auth($ctx) {
            tracing::info!(
                user_id = %authz.user_id,
                email = %authz.email,
                product = %authz.product,
                action = $action,
                $($key = $value),*,
                "{}", $message
            );
        }
    }};
}

/// Log WARN-level audit event (for security-sensitive operations)
///
/// # Example
///
/// ```rust,ignore
/// use pleme_rbac::audit_warn;
///
/// async fn delete_product(ctx: &Context<'_>, product_id: Uuid) -> Result<bool> {
///     audit_warn!(ctx, "delete_product",
///         product_id = %product_id,
///         "Admin deleting product"
///     );
///     // ... business logic
/// }
/// ```
#[cfg(all(feature = "logging", feature = "graphql-integration"))]
#[macro_export]
macro_rules! audit_warn {
    ($ctx:expr, $action:expr, $($key:tt = $value:expr),* $(,)? , $message:expr) => {{
        if let Ok(authz) = $crate::graphql::get_auth($ctx) {
            tracing::warn!(
                user_id = %authz.user_id,
                email = %authz.email,
                product = %authz.product,
                action = $action,
                $($key = $value),*,
                "{}", $message
            );
        }
    }};
}

/// Log ERROR-level audit event (for auth failures or violations)
///
/// # Example
///
/// ```rust,ignore
/// use pleme_rbac::audit_error;
///
/// async fn sensitive_op(ctx: &Context<'_>) -> Result<bool> {
///     if !meets_security_requirements() {
///         audit_error!(ctx, "unauthorized_access",
///             endpoint = "sensitive_op",
///             "Unauthorized access attempt detected"
///         );
///         return Err(Error::new("Forbidden"));
///     }
///     // ... business logic
/// }
/// ```
#[cfg(all(feature = "logging", feature = "graphql-integration"))]
#[macro_export]
macro_rules! audit_error {
    ($ctx:expr, $action:expr, $($key:tt = $value:expr),* $(,)? , $message:expr) => {{
        if let Ok(authz) = $crate::graphql::get_auth($ctx) {
            tracing::error!(
                user_id = %authz.user_id,
                email = %authz.email,
                product = %authz.product,
                action = $action,
                $($key = $value),*,
                "{}", $message
            );
        }
    }};
}

/// Log DEBUG-level audit event (development/troubleshooting only)
#[cfg(all(feature = "logging", feature = "graphql-integration"))]
#[macro_export]
macro_rules! audit_debug {
    ($ctx:expr, $action:expr, $($key:tt = $value:expr),* $(,)? , $message:expr) => {{
        if let Ok(authz) = $crate::graphql::get_auth($ctx) {
            tracing::debug!(
                user_id = %authz.user_id,
                email = %authz.email,
                product = %authz.product,
                action = $action,
                $($key = $value),*,
                "{}", $message
            );
        }
    }};
}

// ============ Common Audit Patterns ============

/// Audit a permission check failure
///
/// Logs when a user attempts an operation without required permissions.
#[cfg(feature = "logging")]
pub fn audit_permission_denied(
    authz: &AuthzContext,
    action: &str,
    required_permission: &str,
) {
    error!(
        user_id = %authz.user_id,
        email = %authz.email,
        product = %authz.product,
        action = action,
        required_permission = required_permission,
        "Permission denied: user lacks required permission"
    );
}

/// Audit a product scope violation
///
/// Logs when a user attempts to access resources from a different product.
#[cfg(feature = "logging")]
pub fn audit_scope_violation(
    authz: &AuthzContext,
    action: &str,
    expected_product: &str,
) {
    error!(
        user_id = %authz.user_id,
        email = %authz.email,
        user_product = %authz.product,
        expected_product = expected_product,
        action = action,
        "Product scope violation: user attempted cross-product access"
    );
}

/// Audit a successful authentication
#[cfg(feature = "logging")]
pub fn audit_login(authz: &AuthzContext, ip_address: Option<&str>) {
    if let Some(ip) = ip_address {
        info!(
            user_id = %authz.user_id,
            email = %authz.email,
            product = %authz.product,
            ip_address = ip,
            "User authenticated successfully"
        );
    } else {
        info!(
            user_id = %authz.user_id,
            email = %authz.email,
            product = %authz.product,
            "User authenticated successfully"
        );
    }
}

/// Audit a failed authentication attempt
#[cfg(feature = "logging")]
pub fn audit_login_failed(email: &str, reason: &str, ip_address: Option<&str>) {
    if let Some(ip) = ip_address {
        warn!(
            email = email,
            reason = reason,
            ip_address = ip,
            "Authentication failed"
        );
    } else {
        warn!(
            email = email,
            reason = reason,
            "Authentication failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    #[cfg(feature = "logging")]
    fn test_audit_event_creation() {
        let authz = AuthzContext {
            user_id: Uuid::new_v4(),
            email: "admin@example.com".to_string(),
            product: "novaskyn".to_string(),
            roles: vec!["admin".to_string()],
            permissions: std::collections::HashSet::new(),
            relationships: std::collections::HashMap::new(),
        };

        let event = AuditEvent::new(
            &authz,
            "delete_product",
            AuditLevel::Warn,
            "Admin deleted product"
        )
        .with_metadata("product_id", "uuid-123");

        assert_eq!(event.user_id, authz.user_id);
        assert_eq!(event.email, "admin@example.com");
        assert_eq!(event.product, "novaskyn");
        assert_eq!(event.action, "delete_product");
        assert_eq!(event.level, AuditLevel::Warn);
        assert_eq!(event.message, "Admin deleted product");
        assert_eq!(event.metadata.get("product_id"), Some(&"uuid-123".to_string()));
    }
}
