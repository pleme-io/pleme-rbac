//! pleme-rbac: Authorization library for Pleme platform
//!
//! This library provides a comprehensive authorization system with:
//! - **Permission-Based Access Control (PBAC)**: Fine-grained permissions
//! - **Relationship-Based Access Control (ReBAC)**: Cross-service ownership/membership
//! - **Multi-Product Isolation**: NovaSkyn, Lilitu, Thai separation
//! - **Zero Network Overhead**: All data from JWT headers (no database calls)
//! - **Batteries Included**: Axum middleware, GraphQL integration, authorization guards
//!
//! # Usage
//!
//! ## Basic Usage (JWT Extraction)
//!
//! ```rust,no_run
//! use pleme_rbac::AuthzContext;
//! use http::HeaderMap;
//!
//! # fn example(headers: &HeaderMap) -> pleme_rbac::AuthzResult<()> {
//! // Extract authorization context from Hive Router headers
//! let ctx = AuthzContext::from_headers(headers)?;
//!
//! // Permission checks
//! if ctx.can("support", "dashboard.read") {
//!     // User has support.dashboard.read permission
//! }
//!
//! // Require permission (returns error if missing)
//! ctx.require("orders", "refund")?;
//!
//! // Relationship checks
//! # let product_id = uuid::Uuid::new_v4();
//! if ctx.owns("products", product_id) {
//!     // User owns this product
//! }
//!
//! // Role checks (backward compatibility)
//! if ctx.is_admin() {
//!     // User has admin role
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Axum Integration (with `axum-integration` feature)
//!
//! ```rust,ignore
//! use axum::{Router, routing::get};
//! use pleme_rbac::axum_middleware::AuthLayer;
//!
//! let app = Router::new()
//!     .route("/api/orders", get(list_orders))
//!     .layer(AuthLayer::new());
//! ```
//!
//! ## GraphQL Integration (with `graphql-integration` feature)
//!
//! ```rust,ignore
//! use async_graphql::{Context, Object, Result};
//! use pleme_rbac::{require_permission, require_product_scope, get_user_id};
//!
//! #[Object]
//! impl Query {
//!     async fn my_orders(&self, ctx: &Context<'_>) -> Result<Vec<Order>> {
//!         require_permission!(ctx, "orders", "read");
//!         require_product_scope!(ctx, "novaskyn");
//!         let user_id = get_user_id!(ctx);
//!         // ... fetch orders
//!     }
//! }
//! ```

mod error;
mod permission;
mod relationship;
mod context;

#[cfg(feature = "axum-integration")]
pub mod axum_middleware;

#[cfg(feature = "graphql-integration")]
pub mod graphql;

#[cfg(feature = "logging")]
pub mod audit;

mod guards;
pub mod admin;

#[cfg(test)]
pub mod testing;

// Re-export public API
pub use error::{AuthzError, AuthzResult};
pub use permission::Permission;
pub use relationship::{Relationship, relations};
pub use context::AuthzContext;

// Note: Guard macros (require_permission!, get_user_id!, etc.) are automatically
// exported at crate root via #[macro_export] - no explicit re-export needed.

// Re-export audit utilities when logging feature is enabled
#[cfg(feature = "logging")]
pub use audit::{AuditEvent, AuditLevel};
