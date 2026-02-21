//! async-graphql integration helpers for authorization
//!
//! This module provides helper functions and utilities for integrating
//! pleme-rbac with async-graphql resolvers.
//!
//! # Usage
//!
//! ```rust,no_run
//! use async_graphql::{Context, Object, Result};
//! use pleme_rbac::graphql::{require_auth, require_permission, require_product_scope};
//!
//! #[Object]
//! impl Query {
//!     async fn my_orders(&self, ctx: &Context<'_>) -> Result<Vec<Order>> {
//!         // Require authentication
//!         let authz = require_auth(ctx)?;
//!
//!         // Require specific permission
//!         require_permission(ctx, "orders", "read")?;
//!
//!         // Require correct product scope
//!         require_product_scope(ctx, "novaskyn")?;
//!
//!         // ... rest of resolver logic
//!         Ok(vec![])
//!     }
//! }
//! ```

use crate::AuthzContext;
use async_graphql::{Context, Error as GraphQLError};
use uuid::Uuid;

/// Get AuthzContext from GraphQL context
///
/// Returns the auth context if present, otherwise returns GraphQL error.
///
/// # Example
///
/// ```rust,no_run
/// use async_graphql::{Context, Result};
/// use pleme_rbac::graphql::get_auth;
///
/// async fn my_resolver(ctx: &Context<'_>) -> Result<String> {
///     let authz = get_auth(ctx)?;
///     Ok(format!("Hello, {}", authz.email))
/// }
/// ```
pub fn get_auth<'a>(ctx: &'a Context<'a>) -> Result<&'a AuthzContext, GraphQLError> {
    ctx.data::<AuthzContext>()
        .map_err(|_| GraphQLError::new("Authentication required. Please provide a valid JWT token."))
}

/// Require authentication (alias for get_auth)
///
/// More explicit name that makes the intent clear in resolver code.
pub fn require_auth<'a>(ctx: &'a Context<'a>) -> Result<&'a AuthzContext, GraphQLError> {
    get_auth(ctx)
}

/// Try to get AuthzContext (returns None if not authenticated)
///
/// Useful for resolvers that support both authenticated and unauthenticated access.
///
/// # Example
///
/// ```rust,no_run
/// use async_graphql::{Context, Result};
/// use pleme_rbac::graphql::try_get_auth;
///
/// async fn public_resolver(ctx: &Context<'_>) -> Result<Vec<Product>> {
///     let authz = try_get_auth(ctx);
///
///     match authz {
///         Some(auth) => {
///             // Show personalized results
///             get_personalized_products(auth.user_id).await
///         }
///         None => {
///             // Show public catalog
///             get_public_products().await
///         }
///     }
/// }
/// ```
pub fn try_get_auth<'a>(ctx: &'a Context<'a>) -> Option<&'a AuthzContext> {
    ctx.data::<AuthzContext>().ok()
}

/// Require specific permission
///
/// Checks if the authenticated user has the required permission.
/// Returns GraphQLError if permission is missing.
///
/// # Example
///
/// ```rust,no_run
/// use async_graphql::{Context, Result};
/// use pleme_rbac::graphql::require_permission;
///
/// async fn refund_order(ctx: &Context<'_>, order_id: String) -> Result<Order> {
///     require_permission(ctx, "orders", "refund")?;
///     // ... refund logic
/// }
/// ```
pub fn require_permission(ctx: &Context<'_>, resource: &str, action: &str) -> Result<(), GraphQLError> {
    let authz = get_auth(ctx)?;
    authz.require(resource, action)
        .map_err(|e| GraphQLError::new(format!("Forbidden: {}", e)))
}

/// Require any of the specified permissions (OR logic)
///
/// # Example
///
/// ```rust,no_run
/// use async_graphql::{Context, Result};
/// use pleme_rbac::graphql::require_any_permission;
///
/// async fn admin_action(ctx: &Context<'_>) -> Result<bool> {
///     require_any_permission(ctx, &[
///         ("admin", "all"),
///         ("support", "admin_panel"),
///     ])?;
///     Ok(true)
/// }
/// ```
pub fn require_any_permission(ctx: &Context<'_>, permissions: &[(&str, &str)]) -> Result<(), GraphQLError> {
    let authz = get_auth(ctx)?;
    authz.require_any(permissions)
        .map_err(|e| GraphQLError::new(format!("Forbidden: {}", e)))
}

/// Require all of the specified permissions (AND logic)
pub fn require_all_permissions(ctx: &Context<'_>, permissions: &[(&str, &str)]) -> Result<(), GraphQLError> {
    let authz = get_auth(ctx)?;
    authz.require_all(permissions)
        .map_err(|e| GraphQLError::new(format!("Forbidden: {}", e)))
}

/// Require that user has specific role
///
/// # Example
///
/// ```rust,no_run
/// use async_graphql::{Context, Result};
/// use pleme_rbac::graphql::require_role;
///
/// async fn admin_only(ctx: &Context<'_>) -> Result<String> {
///     require_role(ctx, "admin")?;
///     Ok("Admin content".to_string())
/// }
/// ```
pub fn require_role(ctx: &Context<'_>, role: &str) -> Result<(), GraphQLError> {
    let authz = get_auth(ctx)?;
    if authz.has_role(role) {
        Ok(())
    } else {
        Err(GraphQLError::new(format!("Forbidden: Requires role '{}'", role)))
    }
}

/// Require admin role
pub fn require_admin(ctx: &Context<'_>) -> Result<(), GraphQLError> {
    let authz = get_auth(ctx)?;
    if authz.is_admin() {
        Ok(())
    } else {
        Err(GraphQLError::new("Forbidden: Admin access required"))
    }
}

/// Require staff role
pub fn require_staff(ctx: &Context<'_>) -> Result<(), GraphQLError> {
    let authz = get_auth(ctx)?;
    if authz.is_staff() {
        Ok(())
    } else {
        Err(GraphQLError::new("Forbidden: Staff access required"))
    }
}

/// Require ownership of resource
///
/// # Example
///
/// ```rust,no_run
/// use async_graphql::{Context, Result};
/// use pleme_rbac::graphql::require_ownership;
/// use uuid::Uuid;
///
/// async fn delete_product(ctx: &Context<'_>, product_id: Uuid) -> Result<bool> {
///     require_ownership(ctx, "products", product_id)?;
///     // ... delete logic
///     Ok(true)
/// }
/// ```
pub fn require_ownership(ctx: &Context<'_>, object_type: &str, object_id: Uuid) -> Result<(), GraphQLError> {
    let authz = get_auth(ctx)?;
    authz.require_relationship(object_type, "owner", object_id)
        .map_err(|e| GraphQLError::new(format!("Forbidden: {}", e)))
}

/// Require relationship to object
pub fn require_relationship(
    ctx: &Context<'_>,
    object_type: &str,
    relation: &str,
    object_id: Uuid,
) -> Result<(), GraphQLError> {
    let authz = get_auth(ctx)?;
    authz.require_relationship(object_type, relation, object_id)
        .map_err(|e| GraphQLError::new(format!("Forbidden: {}", e)))
}

/// Require that the operation is being performed on the user's own account
///
/// # Example
///
/// ```rust,no_run
/// use async_graphql::{Context, Result};
/// use pleme_rbac::graphql::require_self;
/// use uuid::Uuid;
///
/// async fn update_profile(ctx: &Context<'_>, user_id: Uuid) -> Result<User> {
///     require_self(ctx, user_id)?;
///     // ... update logic
/// }
/// ```
pub fn require_self(ctx: &Context<'_>, user_id: Uuid) -> Result<(), GraphQLError> {
    let authz = get_auth(ctx)?;
    if authz.is_self(user_id) {
        Ok(())
    } else {
        Err(GraphQLError::new("Forbidden: You can only modify your own account"))
    }
}

/// Require admin OR owner OR permission (common pattern)
///
/// This is a common authorization pattern: allow if user is admin,
/// or owns the resource, or has a specific permission.
///
/// # Example
///
/// ```rust,no_run
/// use async_graphql::{Context, Result};
/// use pleme_rbac::graphql::require_admin_or_owner_or_permission;
/// use uuid::Uuid;
///
/// async fn edit_product(ctx: &Context<'_>, product_id: Uuid) -> Result<Product> {
///     require_admin_or_owner_or_permission(
///         ctx,
///         "products",
///         product_id,
///         "products.admin"
///     )?;
///     // ... edit logic
/// }
/// ```
pub fn require_admin_or_owner_or_permission(
    ctx: &Context<'_>,
    object_type: &str,
    object_id: Uuid,
    permission: &str,
) -> Result<(), GraphQLError> {
    let authz = get_auth(ctx)?;
    if authz.can_manage(object_type, object_id, permission) {
        Ok(())
    } else {
        Err(GraphQLError::new("Forbidden: Insufficient permissions"))
    }
}

/// Require that the request is for the correct product
///
/// CRITICAL for multi-tenant isolation. All services MUST validate product scope.
///
/// # Example
///
/// ```rust,no_run
/// use async_graphql::{Context, Result};
/// use pleme_rbac::graphql::require_product_scope;
///
/// async fn get_orders(ctx: &Context<'_>) -> Result<Vec<Order>> {
///     require_product_scope(ctx, "novaskyn")?;
///     // ... query logic (WITH product filter)
/// }
/// ```
pub fn require_product_scope(ctx: &Context<'_>, expected_product: &str) -> Result<(), GraphQLError> {
    let authz = get_auth(ctx)?;

    if authz.product != expected_product {
        return Err(GraphQLError::new(format!(
            "Product scope mismatch: expected '{}', got '{}'",
            expected_product, authz.product
        )));
    }

    Ok(())
}

/// Get the current user's ID
///
/// Convenience helper that returns the authenticated user's ID.
pub fn get_user_id(ctx: &Context<'_>) -> Result<Uuid, GraphQLError> {
    let authz = get_auth(ctx)?;
    Ok(authz.user_id)
}

/// Get the current product scope
pub fn get_product(ctx: &Context<'_>) -> Result<String, GraphQLError> {
    let authz = get_auth(ctx)?;
    Ok(authz.product.clone())
}

/// Check if user is authenticated
///
/// Returns true if AuthzContext is present and valid (not empty context).
pub fn is_authenticated(ctx: &Context<'_>) -> bool {
    match ctx.data::<AuthzContext>() {
        Ok(authz) => !authz.user_id.is_nil(),
        Err(_) => false,
    }
}
