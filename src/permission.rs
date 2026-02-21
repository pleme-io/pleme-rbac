use serde::{Deserialize, Serialize};

/// Permission identifier with wildcard support
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Permission {
    /// Permission ID (e.g., "products.edit", "support.*", "*")
    pub id: String,
}

impl Permission {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }

    /// Check if this permission grants access to the requested permission
    ///
    /// Supports:
    /// - Exact match: "products.edit" matches "products.edit"
    /// - Wildcard: "products.*" matches "products.edit", "products.delete"
    /// - Super-wildcard: "*" or "*.*" matches everything
    pub fn grants(&self, requested: &str) -> bool {
        // Exact match
        if self.id == requested {
            return true;
        }

        // Super-wildcard: "*" or "*.*" matches everything
        if self.id == "*" || self.id == "*.*" {
            return true;
        }

        // Wildcard match: "products.*" matches "products.edit"
        if self.id.ends_with(".*") {
            let prefix = &self.id[..self.id.len() - 1]; // Remove "*"
            return requested.starts_with(prefix);
        }

        false
    }

    /// Create permission from resource.action format
    pub fn from_resource_action(resource: &str, action: &str) -> Self {
        Self {
            id: format!("{}.{}", resource, action),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let perm = Permission::new("products.edit");
        assert!(perm.grants("products.edit"));
        assert!(!perm.grants("products.delete"));
    }

    #[test]
    fn test_wildcard() {
        let perm = Permission::new("products.*");
        assert!(perm.grants("products.edit"));
        assert!(perm.grants("products.delete"));
        assert!(perm.grants("products.create"));
        assert!(!perm.grants("orders.read"));
    }

    #[test]
    fn test_super_wildcard() {
        let perm = Permission::new("*");
        assert!(perm.grants("products.edit"));
        assert!(perm.grants("orders.delete"));
        assert!(perm.grants("anything.at.all"));
    }

    #[test]
    fn test_super_wildcard_star_dot_star() {
        let perm = Permission::new("*.*");
        assert!(perm.grants("products.edit"));
        assert!(perm.grants("orders.delete"));
        assert!(perm.grants("anything.at.all"));
        assert!(perm.grants("chat.support.access"));
    }

    #[test]
    fn test_from_resource_action() {
        let perm = Permission::from_resource_action("users", "read");
        assert_eq!(perm.id, "users.read");
        assert!(perm.grants("users.read"));
        assert!(!perm.grants("users.write"));
    }
}
