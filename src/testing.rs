//! Testing utilities for authorization
//!
//! This module provides helper functions and builders for creating mock AuthzContext
//! objects in unit tests. This eliminates boilerplate and makes tests more readable.
//!
//! # Usage
//!
//! ```rust
//! use pleme_rbac::testing::{MockAuthz, mock_admin, mock_user, mock_guest};
//!
//! #[test]
//! fn test_admin_access() {
//!     let authz = mock_admin("novaskyn");
//!     assert!(authz.is_admin());
//!     assert_eq!(authz.product, "novaskyn");
//! }
//!
//! #[test]
//! fn test_user_with_permissions() {
//!     let authz = MockAuthz::user("novaskyn")
//!         .with_permission("orders.read")
//!         .with_permission("orders.write")
//!         .build();
//!
//!     assert!(authz.has_permission("orders.read"));
//!     assert!(authz.has_permission("orders.write"));
//!     assert!(!authz.has_permission("orders.refund"));
//! }
//! ```

use crate::AuthzContext;
use uuid::Uuid;
use std::collections::{HashMap, HashSet};

/// Builder for creating mock AuthzContext objects in tests
///
/// Provides a fluent API for constructing test auth contexts with
/// specific permissions, roles, and relationships.
#[derive(Default)]
pub struct MockAuthz {
    user_id: Option<Uuid>,
    email: Option<String>,
    product: String,
    roles: Vec<String>,
    permissions: HashSet<String>,
    relationships: HashMap<String, Vec<Uuid>>,
}

impl MockAuthz {
    /// Create new builder for a regular user (no special permissions)
    ///
    /// # Example
    ///
    /// ```rust
    /// use pleme_rbac::testing::MockAuthz;
    ///
    /// let authz = MockAuthz::user("novaskyn").build();
    /// assert!(!authz.is_admin());
    /// assert_eq!(authz.product, "novaskyn");
    /// ```
    pub fn user(product: impl Into<String>) -> Self {
        Self {
            product: product.into(),
            roles: vec!["user".to_string()],
            ..Default::default()
        }
    }

    /// Create new builder for an admin user
    ///
    /// # Example
    ///
    /// ```rust
    /// use pleme_rbac::testing::MockAuthz;
    ///
    /// let authz = MockAuthz::admin("novaskyn").build();
    /// assert!(authz.is_admin());
    /// ```
    pub fn admin(product: impl Into<String>) -> Self {
        Self {
            product: product.into(),
            roles: vec!["admin".to_string()],
            ..Default::default()
        }
    }

    /// Create new builder for a staff user
    pub fn staff(product: impl Into<String>) -> Self {
        Self {
            product: product.into(),
            roles: vec!["staff".to_string()],
            ..Default::default()
        }
    }

    /// Create new builder for a guest/unauthenticated user
    pub fn guest() -> Self {
        Self {
            user_id: Some(Uuid::nil()),
            email: Some(String::new()),
            product: String::new(),
            roles: Vec::new(),
            permissions: HashSet::new(),
            relationships: HashMap::new(),
        }
    }

    /// Set specific user ID
    pub fn with_user_id(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Set specific email
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Add a role
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(role.into());
        self
    }

    /// Add a permission
    ///
    /// # Example
    ///
    /// ```rust
    /// use pleme_rbac::testing::MockAuthz;
    ///
    /// let authz = MockAuthz::user("novaskyn")
    ///     .with_permission("orders.read")
    ///     .with_permission("orders.write")
    ///     .build();
    ///
    /// assert!(authz.has_permission("orders.read"));
    /// assert!(authz.has_permission("orders.write"));
    /// ```
    pub fn with_permission(mut self, permission: impl Into<String>) -> Self {
        self.permissions.insert(permission.into());
        self
    }

    /// Add multiple permissions at once
    ///
    /// # Example
    ///
    /// ```rust
    /// use pleme_rbac::testing::MockAuthz;
    ///
    /// let authz = MockAuthz::user("novaskyn")
    ///     .with_permissions(&["orders.read", "orders.write", "products.read"])
    ///     .build();
    ///
    /// assert!(authz.has_permission("orders.read"));
    /// assert!(authz.has_permission("products.read"));
    /// ```
    pub fn with_permissions(mut self, permissions: &[&str]) -> Self {
        for perm in permissions {
            self.permissions.insert(perm.to_string());
        }
        self
    }

    /// Add ownership relationship
    ///
    /// # Example
    ///
    /// ```rust
    /// use pleme_rbac::testing::MockAuthz;
    /// use uuid::Uuid;
    ///
    /// let product_id = Uuid::new_v4();
    /// let authz = MockAuthz::user("novaskyn")
    ///     .owns("products", product_id)
    ///     .build();
    ///
    /// assert!(authz.owns("products", product_id));
    /// ```
    pub fn owns(mut self, object_type: impl Into<String>, object_id: Uuid) -> Self {
        let key = format!("{}:owner", object_type.into());
        self.relationships
            .entry(key)
            .or_insert_with(Vec::new)
            .push(object_id);
        self
    }

    /// Add membership relationship
    pub fn member_of(mut self, object_type: impl Into<String>, object_id: Uuid) -> Self {
        let key = format!("{}:member", object_type.into());
        self.relationships
            .entry(key)
            .or_insert_with(Vec::new)
            .push(object_id);
        self
    }

    /// Add custom relationship
    pub fn with_relationship(
        mut self,
        object_type: impl Into<String>,
        relation: impl Into<String>,
        object_id: Uuid,
    ) -> Self {
        let key = format!("{}:{}", object_type.into(), relation.into());
        self.relationships
            .entry(key)
            .or_insert_with(Vec::new)
            .push(object_id);
        self
    }

    /// Build the final AuthzContext
    pub fn build(self) -> AuthzContext {
        AuthzContext {
            user_id: self.user_id.unwrap_or_else(Uuid::new_v4),
            email: self.email.unwrap_or_else(|| "test@example.com".to_string()),
            product: self.product,
            roles: self.roles,
            permissions: self.permissions,
            relationships: self.relationships,
        }
    }
}

// ============ Convenience Functions ============

/// Create a mock admin user for testing
///
/// # Example
///
/// ```rust
/// use pleme_rbac::testing::mock_admin;
///
/// let authz = mock_admin("novaskyn");
/// assert!(authz.is_admin());
/// assert_eq!(authz.product, "novaskyn");
/// ```
pub fn mock_admin(product: impl Into<String>) -> AuthzContext {
    MockAuthz::admin(product).build()
}

/// Create a mock staff user for testing
pub fn mock_staff(product: impl Into<String>) -> AuthzContext {
    MockAuthz::staff(product).build()
}

/// Create a mock regular user for testing
pub fn mock_user(product: impl Into<String>) -> AuthzContext {
    MockAuthz::user(product).build()
}

/// Create a mock guest (unauthenticated) user for testing
///
/// # Example
///
/// ```rust
/// use pleme_rbac::testing::mock_guest;
///
/// let authz = mock_guest();
/// assert!(!authz.is_authenticated());
/// assert!(authz.user_id.is_nil());
/// ```
pub fn mock_guest() -> AuthzContext {
    MockAuthz::guest().build()
}

/// Create a mock user with specific permissions
///
/// # Example
///
/// ```rust
/// use pleme_rbac::testing::mock_user_with_perms;
///
/// let authz = mock_user_with_perms("novaskyn", &["orders.read", "orders.write"]);
/// assert!(authz.has_permission("orders.read"));
/// assert!(authz.has_permission("orders.write"));
/// assert!(!authz.has_permission("orders.refund"));
/// ```
pub fn mock_user_with_perms(product: impl Into<String>, permissions: &[&str]) -> AuthzContext {
    MockAuthz::user(product)
        .with_permissions(permissions)
        .build()
}

/// Create a mock user who owns specific resources
///
/// # Example
///
/// ```rust
/// use pleme_rbac::testing::mock_owner;
/// use uuid::Uuid;
///
/// let product_id = Uuid::new_v4();
/// let authz = mock_owner("novaskyn", "products", product_id);
/// assert!(authz.owns("products", product_id));
/// ```
pub fn mock_owner(
    product: impl Into<String>,
    object_type: impl Into<String>,
    object_id: Uuid,
) -> AuthzContext {
    MockAuthz::user(product)
        .owns(object_type, object_id)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_admin() {
        let authz = mock_admin("novaskyn");
        assert!(authz.is_admin());
        assert!(authz.is_staff());
        assert_eq!(authz.product, "novaskyn");
        assert!(authz.is_authenticated());
    }

    #[test]
    fn test_mock_staff() {
        let authz = mock_staff("novaskyn");
        assert!(!authz.is_admin());
        assert!(authz.is_staff());
        assert_eq!(authz.product, "novaskyn");
    }

    #[test]
    fn test_mock_user() {
        let authz = mock_user("novaskyn");
        assert!(!authz.is_admin());
        assert!(!authz.is_staff());
        assert_eq!(authz.product, "novaskyn");
        assert!(authz.is_authenticated());
    }

    #[test]
    fn test_mock_guest() {
        let authz = mock_guest();
        assert!(!authz.is_authenticated());
        assert!(authz.user_id.is_nil());
        assert_eq!(authz.email, "");
    }

    #[test]
    fn test_builder_with_permissions() {
        let authz = MockAuthz::user("novaskyn")
            .with_permission("orders.read")
            .with_permission("orders.write")
            .build();

        assert!(authz.has_permission("orders.read"));
        assert!(authz.has_permission("orders.write"));
        assert!(!authz.has_permission("orders.refund"));
    }

    #[test]
    fn test_builder_with_multiple_permissions() {
        let authz = MockAuthz::user("novaskyn")
            .with_permissions(&["orders.read", "orders.write", "products.read"])
            .build();

        assert!(authz.has_permission("orders.read"));
        assert!(authz.has_permission("orders.write"));
        assert!(authz.has_permission("products.read"));
        assert!(!authz.has_permission("orders.refund"));
    }

    #[test]
    fn test_builder_with_ownership() {
        let product_id = Uuid::new_v4();
        let authz = MockAuthz::user("novaskyn")
            .owns("products", product_id)
            .build();

        assert!(authz.owns("products", product_id));
        assert!(!authz.owns("products", Uuid::new_v4()));
    }

    #[test]
    fn test_builder_with_membership() {
        let team_id = Uuid::new_v4();
        let authz = MockAuthz::user("novaskyn")
            .member_of("teams", team_id)
            .build();

        assert!(authz.is_member_of("teams", team_id));
        assert!(!authz.is_member_of("teams", Uuid::new_v4()));
    }

    #[test]
    fn test_mock_user_with_perms() {
        let authz = mock_user_with_perms("novaskyn", &["orders.read", "orders.write"]);
        assert!(authz.has_permission("orders.read"));
        assert!(authz.has_permission("orders.write"));
        assert!(!authz.is_admin());
    }

    #[test]
    fn test_mock_owner() {
        let product_id = Uuid::new_v4();
        let authz = mock_owner("novaskyn", "products", product_id);
        assert!(authz.owns("products", product_id));
        assert!(!authz.owns("products", Uuid::new_v4()));
    }

    #[test]
    fn test_builder_with_specific_user_id() {
        let user_id = Uuid::new_v4();
        let authz = MockAuthz::user("novaskyn")
            .with_user_id(user_id)
            .build();

        assert_eq!(authz.user_id, user_id);
    }

    #[test]
    fn test_builder_with_email() {
        let authz = MockAuthz::user("novaskyn")
            .with_email("custom@example.com")
            .build();

        assert_eq!(authz.email, "custom@example.com");
    }
}
