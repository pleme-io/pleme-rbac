//! Authorization guard macros and helpers
//!
//! This module provides convenient macros for common authorization patterns
//! that reduce boilerplate in resolvers and handlers.

/// Require permission macro for GraphQL resolvers
///
/// # Example
///
/// ```rust,ignore
/// use async_graphql::{Context, Object, Result};
/// use pleme_rbac::require_permission;
///
/// #[Object]
/// impl Mutation {
///     async fn refund_order(&self, ctx: &Context<'_>, order_id: String) -> Result<Order> {
///         require_permission!(ctx, "orders", "refund");
///         // ... refund logic
///     }
/// }
/// ```
#[macro_export]
macro_rules! require_permission {
    ($ctx:expr, $resource:expr, $action:expr) => {
        $crate::graphql::require_permission($ctx, $resource, $action)?
    };
}

/// Require admin role macro
///
/// # Example
///
/// ```rust,ignore
/// use async_graphql::{Context, Object, Result};
/// use pleme_rbac::require_admin;
///
/// #[Object]
/// impl Mutation {
///     async fn delete_all_data(&self, ctx: &Context<'_>) -> Result<bool> {
///         require_admin!(ctx);
///         // ... dangerous operation
///     }
/// }
/// ```
#[macro_export]
macro_rules! require_admin {
    ($ctx:expr) => {
        $crate::graphql::require_admin($ctx)?
    };
}

/// Require staff role macro
#[macro_export]
macro_rules! require_staff {
    ($ctx:expr) => {
        $crate::graphql::require_staff($ctx)?
    };
}

/// Require ownership macro
///
/// # Example
///
/// ```rust,ignore
/// use async_graphql::{Context, Object, Result};
/// use pleme_rbac::require_ownership;
/// use uuid::Uuid;
///
/// #[Object]
/// impl Mutation {
///     async fn delete_product(&self, ctx: &Context<'_>, product_id: Uuid) -> Result<bool> {
///         require_ownership!(ctx, "products", product_id);
///         // ... delete logic
///     }
/// }
/// ```
#[macro_export]
macro_rules! require_ownership {
    ($ctx:expr, $object_type:expr, $object_id:expr) => {
        $crate::graphql::require_ownership($ctx, $object_type, $object_id)?
    };
}

/// Require product scope macro (CRITICAL for multi-tenant isolation)
///
/// # Example
///
/// ```rust,ignore
/// use async_graphql::{Context, Object, Result};
/// use pleme_rbac::require_product_scope;
///
/// #[Object]
/// impl Query {
///     async fn get_orders(&self, ctx: &Context<'_>) -> Result<Vec<Order>> {
///         require_product_scope!(ctx, "novaskyn");
///         // ... query logic
///     }
/// }
/// ```
#[macro_export]
macro_rules! require_product_scope {
    ($ctx:expr, $product:expr) => {
        $crate::graphql::require_product_scope($ctx, $product)?
    };
}

/// Require self (user operating on their own account)
///
/// # Example
///
/// ```rust,ignore
/// use async_graphql::{Context, Object, Result};
/// use pleme_rbac::require_self;
/// use uuid::Uuid;
///
/// #[Object]
/// impl Mutation {
///     async fn update_my_profile(&self, ctx: &Context<'_>, user_id: Uuid) -> Result<User> {
///         require_self!(ctx, user_id);
///         // ... update logic
///     }
/// }
/// ```
#[macro_export]
macro_rules! require_self {
    ($ctx:expr, $user_id:expr) => {
        $crate::graphql::require_self($ctx, $user_id)?
    };
}

/// Require ANY of the specified permissions (OR logic)
///
/// # Example
///
/// ```rust,ignore
/// use async_graphql::{Context, Object, Result};
/// use pleme_rbac::require_any_permission;
///
/// #[Object]
/// impl Mutation {
///     async fn admin_action(&self, ctx: &Context<'_>) -> Result<bool> {
///         require_any_permission!(ctx, [
///             ("admin", "all"),
///             ("support", "admin_panel")
///         ]);
///         // ... logic
///     }
/// }
/// ```
#[macro_export]
macro_rules! require_any_permission {
    ($ctx:expr, [ $(($resource:expr, $action:expr)),* $(,)? ]) => {
        $crate::graphql::require_any_permission($ctx, &[ $(($resource, $action)),* ])?
    };
}

/// Require ALL of the specified permissions (AND logic)
#[macro_export]
macro_rules! require_all_permissions {
    ($ctx:expr, [ $(($resource:expr, $action:expr)),* $(,)? ]) => {
        $crate::graphql::require_all_permissions($ctx, &[ $(($resource, $action)),* ])?
    };
}

/// Combined guard: Require admin OR owner OR permission
///
/// # Example
///
/// ```rust,ignore
/// use async_graphql::{Context, Object, Result};
/// use pleme_rbac::require_admin_or_owner_or_permission;
/// use uuid::Uuid;
///
/// #[Object]
/// impl Mutation {
///     async fn edit_product(&self, ctx: &Context<'_>, product_id: Uuid) -> Result<Product> {
///         require_admin_or_owner_or_permission!(ctx, "products", product_id, "products.admin");
///         // ... edit logic
///     }
/// }
/// ```
#[macro_export]
macro_rules! require_admin_or_owner_or_permission {
    ($ctx:expr, $object_type:expr, $object_id:expr, $permission:expr) => {
        $crate::graphql::require_admin_or_owner_or_permission($ctx, $object_type, $object_id, $permission)?
    };
}

/// Get authenticated user ID macro
///
/// # Example
///
/// ```rust,ignore
/// use async_graphql::{Context, Object, Result};
/// use pleme_rbac::get_user_id;
///
/// #[Object]
/// impl Query {
///     async fn my_orders(&self, ctx: &Context<'_>) -> Result<Vec<Order>> {
///         let user_id = get_user_id!(ctx);
///         // ... fetch orders for user_id
///     }
/// }
/// ```
#[macro_export]
macro_rules! get_user_id {
    ($ctx:expr) => {
        $crate::graphql::get_user_id($ctx)?
    };
}

/// Get product scope macro
#[macro_export]
macro_rules! get_product {
    ($ctx:expr) => {
        $crate::graphql::get_product($ctx)?
    };
}

/// Get full AuthzContext macro
///
/// Returns the complete authorization context for the authenticated user.
/// Use this when you need access to multiple auth fields (user_id, email, permissions, etc.)
///
/// # Example
///
/// ```rust,ignore
/// use async_graphql::{Context, Object, Result};
/// use pleme_rbac::get_auth;
///
/// #[Object]
/// impl Mutation {
///     async fn create_order(&self, ctx: &Context<'_>) -> Result<Order> {
///         let authz = get_auth!(ctx);
///
///         tracing::info!(
///             user_id = %authz.user_id,
///             email = %authz.email,
///             product = %authz.product,
///             "User creating order"
///         );
///
///         // ... business logic
///     }
/// }
/// ```
#[macro_export]
macro_rules! get_auth {
    ($ctx:expr) => {
        $crate::graphql::get_auth($ctx)?
    };
}
