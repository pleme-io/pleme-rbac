# pleme-rbac

**Batteries-included authorization library** for Pleme platform with Google Zanzibar-inspired ReBAC.

## Features

- **Permission-Based Access Control (PBAC)**: Fine-grained permissions with wildcard support
- **Relationship-Based Access Control (ReBAC)**: Cross-service ownership and membership checks (Zanzibar-style tuples)
- **Multi-Product Isolation**: Scoped by product (novaskyn, lilitu, thai)
- **Zero Network Overhead**: All data from JWT headers (no database calls)
- **Axum Integration**: Built-in middleware for automatic auth extraction
- **GraphQL Integration**: Helper functions and guard macros for async-graphql
- **Authorization Guards**: Convenient macros for common authorization patterns
- **Backward Compatible**: Supports existing role-based checks

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
# Basic usage (JWT extraction only)
pleme-rbac = { path = "../../../libraries/rust/crates/pleme-rbac" }

# With web framework integrations
pleme-rbac = { path = "../../../libraries/rust/crates/pleme-rbac", features = ["web"] }

# Individual feature selection
pleme-rbac = { path = "../../../libraries/rust/crates/pleme-rbac", features = ["axum-integration", "graphql-integration"] }
```

## Feature Flags

- `axum-integration` - Axum middleware for auto-extracting auth from requests
- `graphql-integration` - async-graphql helpers and error conversions
- `web` - Enables both axum-integration and graphql-integration
- `db` - Database integration (PostgreSQL + Redis) for relationship storage
- `policies` - Cedar policy engine for complex business rules
- `full` - All features enabled

## Usage

### 1. AuthzContext Extraction

```rust
use pleme_rbac::AuthzContext;
use http::HeaderMap;

// RECOMMENDED: Extract from gateway-injected x-user-* headers
// This is the standard pattern for ALL microservices behind Hive Router
let authz = AuthzContext::from_headers(&headers)?;

// INTERNAL USE ONLY: from_jwt is for auth service internal use and testing
// Regular services MUST NOT use from_jwt - use from_headers instead
// let authz = AuthzContext::from_jwt(token)?; // DO NOT USE IN SERVICES

// Permission checks
if authz.can("support", "dashboard.read") {
    // User has permission
}

// Require permission (returns error if missing)
authz.require("orders", "refund")?;

// Relationship checks
if authz.owns("products", product_id) {
    // User owns this product
}

// Role checks (backward compatibility)
if authz.is_admin() {
    // User is admin
}
```

### 2. Axum Integration (Recommended for Services)

```rust
use axum::{Router, routing::get, Extension};
use pleme_rbac::axum_middleware::AuthLayer;

// Apply auth middleware to all routes
let app = Router::new()
    .route("/graphql", post(graphql_handler))
    .route("/api/orders", get(list_orders))
    .layer(AuthLayer::new());  // ← Automatically extracts JWT and injects AuthzContext

async fn graphql_handler(
    Extension(authz): Extension<AuthzContext>,  // ← Injected by middleware
    req: Json<GraphQLRequest>,
) -> Json<GraphQLResponse> {
    // AuthzContext is available, already validated
    if authz.can("orders", "read") {
        // ... handle request
    }
}
```

**For guest-friendly endpoints** (like cart service):

```rust
use pleme_rbac::axum_middleware::OptionalAuthLayer;

let app = Router::new()
    .route("/api/cart", get(get_cart))
    .layer(OptionalAuthLayer::new());  // ← Allows both authenticated and guest users

async fn get_cart(Extension(authz): Extension<AuthzContext>) -> Json<Cart> {
    if authz.is_authenticated() {
        // Load user cart
    } else {
        // Load guest cart
    }
}
```

### 3. GraphQL Integration (async-graphql)

Use **guard macros** in your resolvers for clean, declarative authorization:

```rust
use async_graphql::{Context, Object, Result};
use pleme_rbac::{require_permission, require_product_scope, get_user_id};

#[Object]
impl Query {
    async fn my_orders(&self, ctx: &Context<'_>) -> Result<Vec<Order>> {
        // Require authentication and permission
        require_permission!(ctx, "orders", "read");

        // CRITICAL: Validate product scope (multi-tenant isolation)
        require_product_scope!(ctx, "novaskyn");

        // Get authenticated user ID
        let user_id = get_user_id!(ctx);

        // Fetch orders (with product filter)
        Ok(self.order_repo.find_by_user(user_id, "novaskyn").await?)
    }
}

#[Object]
impl Mutation {
    async fn refund_order(&self, ctx: &Context<'_>, order_id: Uuid) -> Result<Order> {
        // Multiple authorization options
        require_admin_or_owner_or_permission!(
            ctx,
            "orders",
            order_id,
            "orders.refund"
        );

        // ... refund logic
        Ok(order)
    }

    async fn delete_product(&self, ctx: &Context<'_>, product_id: Uuid) -> Result<bool> {
        // Require ownership
        require_ownership!(ctx, "products", product_id);

        // ... delete logic
        Ok(true)
    }
}
```

### 4. Available Guard Macros

```rust
// Authentication
require_permission!(ctx, "resource", "action");
require_any_permission!(ctx, [("orders", "read"), ("admin", "all")]);
require_all_permissions!(ctx, [("orders", "read"), ("orders", "update")]);

// Roles
require_admin!(ctx);
require_staff!(ctx);

// Relationships (Zanzibar-style)
require_ownership!(ctx, "products", product_id);
require_self!(ctx, user_id);

// Combined guards
require_admin_or_owner_or_permission!(ctx, "products", product_id, "products.admin");

// Product scoping (CRITICAL for multi-tenant)
require_product_scope!(ctx, "novaskyn");

// Helpers
let user_id = get_user_id!(ctx);
let product = get_product!(ctx);
```

### Permission Patterns

```rust
// Exact permission
ctx.can("products", "edit")  // Checks for "products.edit"

// Wildcard permission
// User with "products.*" can do "products.edit", "products.delete", etc.

// Super-wildcard
// User with "*" has all permissions

// Require any (OR logic)
ctx.require_any(&[
    ("orders", "refund"),
    ("admin", "all")
])?;

// Require all (AND logic)
ctx.require_all(&[
    ("orders", "read"),
    ("orders", "update")
])?;
```

### Relationship Patterns

```rust
// Check ownership
if ctx.owns("products", product_id) { }

// Check membership
if ctx.is_member_of("teams", team_id) { }

// Check viewer access
if ctx.can_view("conversations", conv_id) { }

// Check editor access
if ctx.can_edit("documents", doc_id) { }

// Get all related objects
let my_products = ctx.get_related_objects("products", "owner");
```

### Combined Checks

```rust
// Admin OR owner OR has permission
if ctx.can_manage("products", product_id, "products.admin") {
    // Allow operation
}

// Check if operating on self
if ctx.is_self(target_user_id) {
    // User is modifying their own account
}
```

## Architecture

### JWT-Embedded Data

Hive Router validates JWTs and injects trusted headers:

- `x-user-id`: User UUID
- `x-user-email`: User email
- `x-user-roles`: Comma-separated roles
- `x-user-permissions`: Comma-separated permissions
- `x-user-relationships`: JSON map of hot relationships
- `x-product`: Product scope

### Performance

- **Header parsing**: <10μs (local operation)
- **Permission check**: <1μs (HashSet lookup)
- **Relationship check**: <1μs (HashMap lookup)
- **No network calls**: All data from JWT

### Multi-Product Isolation

All authorization checks are scoped by product:

```rust
ctx.product  // "novaskyn", "lilitu", or "thai"
```

Services MUST validate product scope matches the requested resource.

### 5. Audit Logging (with `logging` feature)

Standardized security audit logging with automatic user context:

```rust
use pleme_rbac::{audit_info, audit_warn, audit_error};

#[Object]
impl Mutation {
    async fn approve_product(&self, ctx: &Context<'_>, product_id: Uuid) -> Result<Product> {
        require_permission!(ctx, "products", "admin");

        // Log security-sensitive operation with user context
        audit_info!(ctx, "approve_product",
            product_id = %product_id,
            "Staff approved product for publication"
        );

        // ... business logic
        Ok(product)
    }

    async fn delete_product(&self, ctx: &Context<'_>, product_id: Uuid) -> Result<bool> {
        require_admin!(ctx);

        // Log destructive operation at WARN level
        audit_warn!(ctx, "delete_product",
            product_id = %product_id,
            "Admin deleting product"
        );

        // ... business logic
        Ok(true)
    }

    async fn sensitive_action(&self, ctx: &Context<'_>) -> Result<bool> {
        if !validate_security_requirements() {
            // Log security violation at ERROR level
            audit_error!(ctx, "unauthorized_access",
                endpoint = "sensitive_action",
                "Unauthorized access attempt detected"
            );
            return Err(Error::new("Forbidden"));
        }
        Ok(true)
    }
}
```

**Benefits:**
- Automatic user context (user_id, email, product) in all logs
- Consistent structured logging format across services
- Security compliance audit trails
- Three severity levels: `audit_info!`, `audit_warn!`, `audit_error!`

### 6. Testing Utilities

Create mock AuthzContext objects for unit tests:

```rust
use pleme_rbac::testing::{MockAuthz, mock_admin, mock_user, mock_guest};

#[test]
fn test_admin_access() {
    let authz = mock_admin("novaskyn");
    assert!(authz.is_admin());
    assert_eq!(authz.product, "novaskyn");
}

#[test]
fn test_user_with_permissions() {
    let authz = MockAuthz::user("novaskyn")
        .with_permission("orders.read")
        .with_permission("orders.write")
        .build();

    assert!(authz.has_permission("orders.read"));
    assert!(authz.has_permission("orders.write"));
    assert!(!authz.has_permission("orders.refund"));
}

#[test]
fn test_owner_permissions() {
    let product_id = Uuid::new_v4();
    let authz = MockAuthz::user("novaskyn")
        .owns("products", product_id)
        .build();

    assert!(authz.owns("products", product_id));
    assert!(!authz.owns("products", Uuid::new_v4()));
}

#[test]
fn test_guest_user() {
    let authz = mock_guest();
    assert!(!authz.is_authenticated());
    assert!(authz.user_id.is_nil());
}
```

**Convenience functions:**
- `mock_admin(product)` - Admin user
- `mock_staff(product)` - Staff user
- `mock_user(product)` - Regular user
- `mock_guest()` - Unauthenticated user
- `mock_user_with_perms(product, perms)` - User with specific permissions
- `mock_owner(product, object_type, object_id)` - User who owns resource

**Builder pattern for complex scenarios:**
```rust
let authz = MockAuthz::user("novaskyn")
    .with_user_id(specific_user_id)
    .with_email("test@example.com")
    .with_permission("orders.read")
    .with_permissions(&["products.edit", "products.delete"])
    .owns("products", product_id)
    .member_of("teams", team_id)
    .build();
```

## Examples

Run the basic usage example:

```bash
cargo run --example basic_usage
```

## Design Principles

1. **Local Checks**: Zero network overhead (all data in JWT)
2. **Simple Wildcards**: Phase 1 uses basic wildcard matching
3. **Zanzibar Tuples**: Relationships follow Google Zanzibar model
4. **Product Scoped**: All operations isolated by product
5. **Backward Compatible**: Supports existing role checks
6. **Batteries Included**: Audit logging, testing utilities, guard macros

## Future Enhancements

- **Phase 2**: Relationship inheritance (owner → editor → viewer)
- **Phase 3**: Cedar policy engine for complex business rules
- **Database Fallback**: Optional cold relationship lookups

## License

UNLICENSED - Internal use only
