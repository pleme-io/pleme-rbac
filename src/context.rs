use crate::{AuthzError, AuthzResult, Permission};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Authorization context extracted from JWT headers
///
/// This is the main API that services use for authorization.
/// All data comes from JWT (embedded by Hive Router), so checks are LOCAL (no network).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzContext {
    /// Authenticated user ID
    pub user_id: Uuid,

    /// User email
    pub email: String,

    /// Product scope (novaskyn, lilitu, thai)
    pub product: String,

    /// User roles (for backward compatibility)
    pub roles: Vec<String>,

    /// Flattened permissions from all roles
    pub permissions: HashSet<String>,

    /// Hot relationships (frequently accessed, cached in JWT)
    /// Format: "object_type:relation" -> [object_ids]
    /// Example: {"products:owner": [uuid1, uuid2], "teams:member": [uuid3]}
    pub relationships: HashMap<String, Vec<Uuid>>,
}

/// JWT Claims structure matching auth service AccessTokenClaims
#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    sub: String,
    email: String,
    product: String,
    roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    permissions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relationships: Option<serde_json::Value>,
}

impl AuthzContext {
    /// Create from Hive Router headers
    ///
    /// Expected headers (added by Hive Router after JWT validation):
    /// - x-user-id: UUID
    /// - x-user-email: string
    /// - x-user-roles: comma-separated
    /// - x-user-permissions: comma-separated
    /// - x-user-relationships: JSON map
    /// - x-product: product name
    pub fn from_headers(headers: &HeaderMap) -> AuthzResult<Self> {
        let user_id = parse_uuid_header(headers, "x-user-id")?;
        let email = parse_string_header(headers, "x-user-email")?;
        let product = parse_string_header(headers, "x-product")?;
        let roles = parse_csv_header(headers, "x-user-roles")?;
        // Permissions are optional - default to empty if not present
        // This handles the case where JWT doesn't have permissions claim
        let permissions = parse_optional_csv_header(headers, "x-user-permissions")
            .into_iter()
            .collect();
        // Relationships are optional - default to empty map if not present
        // This handles the case where JWT doesn't have relationships claim
        let relationships = parse_optional_json_header(headers, "x-user-relationships")
            .unwrap_or_default();

        Ok(Self {
            user_id,
            email,
            product,
            roles,
            permissions,
            relationships,
        })
    }

    /// Create from JWT token without validation
    ///
    /// **WARNING**: This method is for INTERNAL USE ONLY (auth service, testing).
    /// Regular services should NEVER call this method - use `from_headers()` instead.
    ///
    /// ## Architecture Pattern
    ///
    /// - **Gateway (Hive Router)**: Validates JWT signature, injects x-user-* headers
    /// - **Services**: Call `from_headers()` to read trusted headers (NOT this method)
    /// - **Auth Service**: May call this method for token generation/testing purposes
    ///
    /// ## Why Services Should NOT Use This
    ///
    /// 1. **Zero-Trust Security**: Services should not trust Authorization headers from clients
    /// 2. **Centralized Validation**: JWT validation happens once at the gateway
    /// 3. **HMAC Protection**: Gateway signs requests; services verify HMAC then trust headers
    /// 4. **Consistent Pattern**: All services use same auth flow (from_headers)
    ///
    /// This method is kept for:
    /// - Auth service internal token handling
    /// - Testing and development
    /// - Non-service use cases
    ///
    /// Regular services MUST use `from_headers()` instead.
    pub fn from_jwt(token: &str) -> AuthzResult<Self> {
        // Decode without any validation (gateway already validated signature, exp, aud)
        // Uses dangerous::insecure_decode which is the recommended way in jsonwebtoken v10+
        let token_data = jsonwebtoken::dangerous::insecure_decode::<JwtClaims>(token)
            .map_err(|e| AuthzError::ParseError(format!("Invalid JWT: {}", e)))?;

        let claims = token_data.claims;

        // Parse user_id from sub claim
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|e| AuthzError::ParseError(format!("Invalid user_id in JWT sub claim: {}", e)))?;

        // Parse permissions
        let permissions: HashSet<String> = claims.permissions
            .unwrap_or_default()
            .into_iter()
            .collect();

        // Parse relationships
        let relationships: HashMap<String, Vec<Uuid>> = claims.relationships
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();

        Ok(Self {
            user_id,
            email: claims.email,
            product: claims.product,
            roles: claims.roles,
            permissions,
            relationships,
        })
    }

    /// Create empty context for unauthenticated requests
    ///
    /// Returns a context with no permissions or relationships.
    /// Useful for anonymous/guest access where some operations are permitted.
    pub fn empty() -> Self {
        Self {
            user_id: Uuid::nil(),
            email: String::new(),
            product: String::new(),
            roles: Vec::new(),
            permissions: HashSet::new(),
            relationships: HashMap::new(),
        }
    }

    /// Create AuthzContext from validated JWT claims
    ///
    /// **For Auth Service Use**: This method allows the auth service to construct
    /// an AuthzContext directly from validated JWT claims, without needing to
    /// pass through the full JWT parsing flow.
    ///
    /// Other services should use `from_headers()` which reads from gateway-injected headers.
    ///
    /// # Arguments
    ///
    /// * `user_id` - Authenticated user UUID
    /// * `email` - User email address
    /// * `product` - Product scope (novaskyn, lilitu, thai)
    /// * `roles` - User roles from JWT claims
    /// * `permissions` - Flattened permissions from JWT claims
    /// * `relationships` - Hot relationships from JWT claims
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use pleme_rbac::AuthzContext;
    /// use uuid::Uuid;
    /// use std::collections::{HashSet, HashMap};
    ///
    /// let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    /// let ctx = AuthzContext::from_claims(
    ///     user_id,
    ///     "user@example.com".to_string(),
    ///     "novaskyn".to_string(),
    ///     vec!["superadmin".to_string()],
    ///     vec!["admin.all".to_string(), "users.*".to_string()],
    ///     HashMap::new(),
    /// );
    ///
    /// assert!(ctx.can("admin", "all"));
    /// ```
    pub fn from_claims(
        user_id: Uuid,
        email: String,
        product: String,
        roles: Vec<String>,
        permissions: Vec<String>,
        relationships: HashMap<String, Vec<Uuid>>,
    ) -> Self {
        Self {
            user_id,
            email,
            product,
            roles,
            permissions: permissions.into_iter().collect(),
            relationships,
        }
    }

    // ============ Permission Checks (Fast, Local) ============

    /// Check if user has specific permission
    ///
    /// Example: `ctx.has_permission("support.dashboard.read")`
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| {
            Permission::new(p).grants(permission)
        })
    }

    /// Check if user can perform action on resource
    ///
    /// Example: `ctx.can("support", "dashboard.read")`
    pub fn can(&self, resource: &str, action: &str) -> bool {
        self.has_permission(&format!("{}.{}", resource, action))
    }

    /// Require permission or return error
    ///
    /// Example: `ctx.require("orders", "refund")?`
    pub fn require(&self, resource: &str, action: &str) -> AuthzResult<()> {
        if self.can(resource, action) {
            Ok(())
        } else {
            Err(AuthzError::MissingPermission(format!("{}.{}", resource, action)))
        }
    }

    /// Require any of the permissions (OR logic)
    ///
    /// Example: `ctx.require_any(&[("orders", "refund"), ("admin", "all")])?`
    pub fn require_any(&self, permissions: &[(&str, &str)]) -> AuthzResult<()> {
        for (resource, action) in permissions {
            if self.can(resource, action) {
                return Ok(());
            }
        }

        let perm_strings: Vec<String> = permissions
            .iter()
            .map(|(r, a)| format!("{}.{}", r, a))
            .collect();

        Err(AuthzError::MissingPermission(format!(
            "Requires one of: {}",
            perm_strings.join(" OR ")
        )))
    }

    /// Require all permissions (AND logic)
    ///
    /// Example: `ctx.require_all(&[("orders", "read"), ("orders", "update")])?`
    pub fn require_all(&self, permissions: &[(&str, &str)]) -> AuthzResult<()> {
        for (resource, action) in permissions {
            if !self.can(resource, action) {
                return Err(AuthzError::MissingPermission(format!("{}.{}", resource, action)));
            }
        }
        Ok(())
    }

    // ============ Relationship Checks (JWT-Cached) ============

    /// Check if user has relationship to object
    ///
    /// Example: `ctx.has_relationship("products", "owner", product_id)`
    pub fn has_relationship(
        &self,
        object_type: &str,
        relation: &str,
        object_id: Uuid,
    ) -> bool {
        let key = format!("{}:{}", object_type, relation);
        self.relationships
            .get(&key)
            .map(|ids| ids.contains(&object_id))
            .unwrap_or(false)
    }

    /// Check if user owns object
    ///
    /// Example: `ctx.owns("products", product_id)`
    pub fn owns(&self, object_type: &str, object_id: Uuid) -> bool {
        self.has_relationship(object_type, "owner", object_id)
    }

    /// Check if user is member of object
    ///
    /// Example: `ctx.is_member_of("teams", team_id)`
    pub fn is_member_of(&self, object_type: &str, object_id: Uuid) -> bool {
        self.has_relationship(object_type, "member", object_id)
    }

    /// Check if user can view object
    ///
    /// Example: `ctx.can_view("conversations", conv_id)`
    pub fn can_view(&self, object_type: &str, object_id: Uuid) -> bool {
        self.has_relationship(object_type, "viewer", object_id)
    }

    /// Check if user can edit object
    ///
    /// Example: `ctx.can_edit("products", product_id)`
    pub fn can_edit(&self, object_type: &str, object_id: Uuid) -> bool {
        self.has_relationship(object_type, "editor", object_id)
    }

    /// Require relationship or error
    ///
    /// Example: `ctx.require_relationship("products", "owner", product_id)?`
    pub fn require_relationship(
        &self,
        object_type: &str,
        relation: &str,
        object_id: Uuid,
    ) -> AuthzResult<()> {
        if self.has_relationship(object_type, relation, object_id) {
            Ok(())
        } else {
            Err(AuthzError::Forbidden(format!(
                "User {} does not have {} relationship to {}::{}",
                self.user_id, relation, object_type, object_id
            )))
        }
    }

    /// Get all objects of a type that user has relationship to
    ///
    /// Example: `let my_products = ctx.get_related_objects("products", "owner")`
    pub fn get_related_objects(&self, object_type: &str, relation: &str) -> Vec<Uuid> {
        let key = format!("{}:{}", object_type, relation);
        self.relationships
            .get(&key)
            .cloned()
            .unwrap_or_default()
    }

    // ============ Role Checks (Backward Compatibility) ============

    /// Check if user has role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r.eq_ignore_ascii_case(role))
    }

    /// Check if user is admin (any *_admin role)
    pub fn is_admin(&self) -> bool {
        self.roles.iter().any(|r| {
            let r_lower = r.to_lowercase();
            matches!(r_lower.as_str(), "admin" | "superadmin") || r_lower.ends_with("_admin")
        })
    }

    /// Check if user is staff
    pub fn is_staff(&self) -> bool {
        self.roles.iter().any(|r| {
            let r_lower = r.to_lowercase();
            matches!(r_lower.as_str(), "staff" | "moderator")
        }) || self.is_admin()
    }

    // ============ Utility Methods ============

    /// Check if user is the authenticated user (for "self" operations)
    pub fn is_self(&self, user_id: Uuid) -> bool {
        self.user_id == user_id
    }

    /// Combined check: is admin OR owns object OR has permission
    ///
    /// Common pattern: allow if admin, or owner, or has specific permission
    pub fn can_manage(&self, object_type: &str, object_id: Uuid, permission: &str) -> bool {
        self.is_admin()
            || self.owns(object_type, object_id)
            || self.has_permission(permission)
    }

    /// Check if user is authenticated (not an empty/guest context)
    ///
    /// Returns true if this is a valid authenticated user, false for empty/guest contexts.
    pub fn is_authenticated(&self) -> bool {
        !self.user_id.is_nil() && !self.email.is_empty()
    }

    /// Require that this is an authenticated user (not empty/guest context)
    ///
    /// Returns error if user is not authenticated.
    pub fn require_authenticated(&self) -> AuthzResult<()> {
        if self.is_authenticated() {
            Ok(())
        } else {
            Err(AuthzError::MissingPermission("Authentication required".to_string()))
        }
    }

    /// Require product scope matches expected value
    ///
    /// CRITICAL: All services MUST validate product scope to prevent cross-product data access.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use pleme_rbac::AuthzContext;
    /// # let authz = AuthzContext::empty();
    /// // In NovaSkyn service
    /// authz.require_product_scope("novaskyn")?;
    /// # Ok::<(), pleme_rbac::AuthzError>(())
    /// ```
    pub fn require_product_scope(&self, expected_product: &str) -> AuthzResult<()> {
        if self.product == expected_product {
            Ok(())
        } else {
            Err(AuthzError::Forbidden(format!(
                "Product scope mismatch: expected '{}', got '{}'",
                expected_product, self.product
            )))
        }
    }

    /// Get the product scope
    pub fn get_product(&self) -> &str {
        &self.product
    }

    /// Get the user ID
    pub fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    /// Get the user email
    pub fn get_email(&self) -> &str {
        &self.email
    }
}

// ============ Header Parsing Helpers ============

fn parse_uuid_header(headers: &HeaderMap, name: &str) -> AuthzResult<Uuid> {
    let value = headers
        .get(name)
        .ok_or_else(|| AuthzError::InvalidHeader(format!("Missing header: {}", name)))?
        .to_str()
        .map_err(|_| AuthzError::InvalidHeader(format!("Invalid UTF-8 in header: {}", name)))?;

    Uuid::parse_str(value)
        .map_err(|_| AuthzError::ParseError(format!("Invalid UUID in header {}: {}", name, value)))
}

fn parse_string_header(headers: &HeaderMap, name: &str) -> AuthzResult<String> {
    headers
        .get(name)
        .ok_or_else(|| AuthzError::InvalidHeader(format!("Missing header: {}", name)))?
        .to_str()
        .map(String::from)
        .map_err(|_| AuthzError::InvalidHeader(format!("Invalid UTF-8 in header: {}", name)))
}

fn parse_csv_header(headers: &HeaderMap, name: &str) -> AuthzResult<Vec<String>> {
    let value = parse_string_header(headers, name)?;
    if value.is_empty() {
        return Ok(Vec::new());
    }
    Ok(value.split(',').map(|s| s.trim().to_string()).collect())
}

/// Parse optional CSV header, returning empty vec if header is missing
fn parse_optional_csv_header(headers: &HeaderMap, name: &str) -> Vec<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            if s.is_empty() {
                Vec::new()
            } else {
                s.split(',').map(|s| s.trim().to_string()).collect()
            }
        })
        .unwrap_or_default()
}

#[allow(dead_code)]
fn parse_json_header<T: for<'de> Deserialize<'de>>(
    headers: &HeaderMap,
    name: &str,
) -> AuthzResult<T> {
    let value = parse_string_header(headers, name)?;
    serde_json::from_str(&value)
        .map_err(|e| AuthzError::ParseError(format!("Invalid JSON in header {}: {}", name, e)))
}

/// Parse optional JSON header, returning None if header is missing
fn parse_optional_json_header<T: for<'de> Deserialize<'de> + Default>(
    headers: &HeaderMap,
    name: &str,
) -> Option<T> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| serde_json::from_str(s).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_checks() {
        let mut perms = HashSet::new();
        perms.insert("support.dashboard.read".to_string());
        perms.insert("products.*".to_string());

        let ctx = AuthzContext {
            user_id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            product: "novaskyn".to_string(),
            roles: vec!["staff".to_string()],
            permissions: perms,
            relationships: HashMap::new(),
        };

        assert!(ctx.can("support", "dashboard.read"));
        assert!(ctx.can("products", "edit"));
        assert!(ctx.can("products", "delete"));
        assert!(!ctx.can("orders", "refund"));
    }

    #[test]
    fn test_relationship_checks() {
        let product_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let mut relationships = HashMap::new();
        relationships.insert("products:owner".to_string(), vec![product_id]);

        let ctx = AuthzContext {
            user_id,
            email: "test@example.com".to_string(),
            product: "novaskyn".to_string(),
            roles: vec!["user".to_string()],
            permissions: HashSet::new(),
            relationships,
        };

        assert!(ctx.owns("products", product_id));
        assert!(!ctx.owns("products", Uuid::new_v4()));
    }

    #[test]
    fn test_require_any() {
        let mut perms = HashSet::new();
        perms.insert("orders.read".to_string());

        let ctx = AuthzContext {
            user_id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            product: "novaskyn".to_string(),
            roles: vec![],
            permissions: perms,
            relationships: HashMap::new(),
        };

        // Should succeed (has orders.read)
        assert!(ctx.require_any(&[("orders", "read"), ("orders", "write")]).is_ok());

        // Should fail (has neither)
        assert!(ctx.require_any(&[("products", "edit"), ("orders", "delete")]).is_err());
    }

    #[test]
    fn test_is_admin() {
        // Test exact admin role
        let ctx = AuthzContext {
            user_id: Uuid::new_v4(),
            email: "admin@example.com".to_string(),
            product: "novaskyn".to_string(),
            roles: vec!["admin".to_string()],
            permissions: HashSet::new(),
            relationships: HashMap::new(),
        };
        assert!(ctx.is_admin());

        // Test *_admin role
        let ctx = AuthzContext {
            user_id: Uuid::new_v4(),
            email: "sysadmin@example.com".to_string(),
            product: "novaskyn".to_string(),
            roles: vec!["system_admin".to_string()],
            permissions: HashSet::new(),
            relationships: HashMap::new(),
        };
        assert!(ctx.is_admin());

        // Test non-admin
        let ctx = AuthzContext {
            user_id: Uuid::new_v4(),
            email: "user@example.com".to_string(),
            product: "novaskyn".to_string(),
            roles: vec!["user".to_string()],
            permissions: HashSet::new(),
            relationships: HashMap::new(),
        };
        assert!(!ctx.is_admin());
    }

    #[test]
    fn test_is_staff() {
        // Staff role
        let ctx = AuthzContext {
            user_id: Uuid::new_v4(),
            email: "staff@example.com".to_string(),
            product: "novaskyn".to_string(),
            roles: vec!["staff".to_string()],
            permissions: HashSet::new(),
            relationships: HashMap::new(),
        };
        assert!(ctx.is_staff());

        // Admin is also staff
        let ctx = AuthzContext {
            user_id: Uuid::new_v4(),
            email: "admin@example.com".to_string(),
            product: "novaskyn".to_string(),
            roles: vec!["admin".to_string()],
            permissions: HashSet::new(),
            relationships: HashMap::new(),
        };
        assert!(ctx.is_staff());
    }

    #[test]
    fn test_can_manage() {
        let product_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let mut relationships = HashMap::new();
        relationships.insert("products:owner".to_string(), vec![product_id]);

        let ctx = AuthzContext {
            user_id,
            email: "owner@example.com".to_string(),
            product: "novaskyn".to_string(),
            roles: vec!["user".to_string()],
            permissions: HashSet::new(),
            relationships,
        };

        // Owner can manage
        assert!(ctx.can_manage("products", product_id, "products.admin"));

        // Non-owner cannot manage
        assert!(!ctx.can_manage("products", Uuid::new_v4(), "products.admin"));
    }
}
