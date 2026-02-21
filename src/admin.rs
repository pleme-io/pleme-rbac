//! Admin operation helpers and guards
//!
//! Provides standardized helpers for admin operations across all services:
//! - Admin permission checks
//! - Audit logging for admin actions
//! - Admin-specific guard macros
//!
//! # Example
//! ```rust
//! use pleme_rbac::admin::require_admin;
//!
//! async fn admin_operation(ctx: &AuthzContext) -> Result<()> {
//!     require_admin!(ctx, "manage_users");
//!
//!     // Admin operation here
//!     Ok(())
//! }
//! ```

use crate::{AuthzContext, AuthzError};

/// Check if user has admin role
///
/// Admin roles include:
/// - `admin` and `superadmin` (exact match, case-insensitive)
/// - Any role ending with `_admin` (e.g., `system_admin`, `finance_admin`)
///
/// NOTE: This delegates to AuthzContext::is_admin() for consistency.
/// Prefer using ctx.is_admin() directly when you have access to the context.
pub fn is_admin(ctx: &AuthzContext) -> bool {
    ctx.is_admin()
}

/// Check if user has specific admin permission
///
/// Requires the user to have an admin role AND the specific permission.
/// Supports wildcard permissions:
/// - `*` or `*.*` - Full access (matches everything)
/// - `admin:*` - All admin permissions
/// - Exact match on the permission string
pub fn has_admin_permission(ctx: &AuthzContext, permission: &str) -> bool {
    if !is_admin(ctx) {
        return false;
    }

    // Check for wildcard or exact permission match
    // Use has_permission which handles wildcard matching properly
    ctx.has_permission(permission) || ctx.has_permission("admin:*")
}

/// Require admin permission or return error
pub fn require_admin_permission(ctx: &AuthzContext, permission: &str) -> Result<(), AuthzError> {
    if !has_admin_permission(ctx, permission) {
        return Err(AuthzError::MissingPermission(
            format!("User {} does not have admin permission '{}'", ctx.user_id, permission)
        ));
    }
    Ok(())
}

/// Audit log entry for admin actions
#[derive(Debug, Clone)]
pub struct AdminAuditLog {
    pub user_id: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub changes: Option<serde_json::Value>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub product: String,
}

impl AdminAuditLog {
    pub fn new(ctx: &AuthzContext, action: &str, resource_type: &str) -> Self {
        Self {
            user_id: ctx.user_id.to_string(),
            action: action.to_string(),
            resource_type: resource_type.to_string(),
            resource_id: None,
            changes: None,
            timestamp: chrono::Utc::now(),
            product: ctx.product.clone(),
        }
    }

    pub fn with_resource_id(mut self, id: &str) -> Self {
        self.resource_id = Some(id.to_string());
        self
    }

    pub fn with_changes(mut self, changes: serde_json::Value) -> Self {
        self.changes = Some(changes);
        self
    }

    /// Log the admin action (to tracing)
    #[cfg(feature = "logging")]
    pub fn log(&self) {
        tracing::info!(
            user_id = %self.user_id,
            action = %self.action,
            resource_type = %self.resource_type,
            resource_id = ?self.resource_id,
            product = %self.product,
            "Admin action performed"
        );
    }

    /// Log the admin action (no-op when logging feature disabled)
    #[cfg(not(feature = "logging"))]
    pub fn log(&self) {
        // No-op
    }
}

