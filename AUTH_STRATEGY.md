# pleme-rbac Authorization Strategy

**Last Updated:** 2025-01-15
**Status:** Implemented and Ready for Adoption
**Philosophy:** Google Zanzibar-inspired ReBAC with JWT-embedded permissions

---

## Executive Summary

pleme-rbac implements a comprehensive authorization system inspired by Google's Zanzibar, combining:
- **Permission-Based Access Control (PBAC)** for fine-grained action control
- **Relationship-Based Access Control (ReBAC)** for ownership and membership
- **Multi-Product Isolation** for tenant separation
- **Zero Network Overhead** via JWT-embedded authorization data

All authorization checks happen **locally in microseconds** without database calls, following the Google standard of embedding auth data in request context.

---

## Core Philosophy: The Google Standard

### 1. JWT as Authorization Carrier

Following Google's approach (used in Google Cloud, Firebase, etc.), we embed all authorization data in the JWT token:

```
JWT Payload:
{
  "sub": "user-uuid",
  "email": "user@example.com",
  "product": "novaskyn",
  "roles": ["user", "customer"],
  "permissions": ["orders.read", "products.*"],
  "relationships": {
    "products:owner": ["uuid1", "uuid2"],
    "teams:member": ["uuid3"]
  }
}
```

**Benefits:**
- ✅ Sub-microsecond authorization checks (no network calls)
- ✅ Stateless services (no session storage required)
- ✅ Scales horizontally (no auth service bottleneck)
- ✅ Works offline (services can validate independently)

**Trade-offs:**
- ⚠️ JWT size limits (keep under 4KB)
- ⚠️ Changes take effect on next token refresh (15min)
- ⚠️ Embed only "hot" relationships (most-used 30)

---

## Architecture: Three Layers

### Layer 1: API Gateway (Hive Router)

**Responsibility:** JWT validation and header injection

```
1. Client sends: Authorization: Bearer <JWT>
2. Hive Router validates JWT signature
3. Hive Router injects trusted headers:
   - x-user-id
   - x-user-email
   - x-user-roles
   - x-user-permissions
   - x-user-relationships
   - x-product
4. Forward request to microservice
```

**Why:** Centralized JWT validation prevents each service from implementing it.

### Layer 2: Service Middleware (pleme-rbac)

**Responsibility:** Extract auth context from headers/JWT

```rust
use pleme_rbac::axum_middleware::AuthLayer;

// Automatically extracts AuthzContext from headers
let app = Router::new()
    .route("/graphql", post(graphql_handler))
    .layer(AuthLayer::new());
```

**What it does:**
1. Parse `Authorization: Bearer <token>` header
2. Extract claims into `AuthzContext` struct
3. Inject into request extensions
4. Available to all handlers/resolvers

### Layer 3: Resolver Guards (Business Logic)

**Responsibility:** Enforce authorization rules

```rust
use pleme_rbac::{require_permission, require_product_scope};

async fn my_orders(ctx: &Context<'_>) -> Result<Vec<Order>> {
    require_permission!(ctx, "orders", "read");
    require_product_scope!(ctx, "novaskyn");

    let user_id = get_user_id!(ctx);
    // ... fetch orders
}
```

---

## Zanzibar-Inspired ReBAC

### Relationship Tuples

We use Google Zanzibar's tuple model for relationships:

```
(subject_type, subject_id, relation, object_type, object_id)
```

**Examples:**
```
("user", alice_id, "owner", "product", product_id)
("user", bob_id, "member", "team", support_team_id)
("user", charlie_id, "viewer", "conversation", conv_id)
```

### Standard Relations

Following Zanzibar conventions:

- `owner` - Full control over resource
- `editor` - Can modify resource
- `viewer` - Can read resource
- `member` - Belongs to group
- `participant` - Active in conversation/event
- `assignee` - Responsible for task/ticket

### Relationship Storage

**Phase 1 (Current):** JWT-embedded hot relationships only
- Top 30 most-accessed relationships per user
- Stored in `relationships` map in JWT

**Phase 2 (Future):** Database fallback
- PostgreSQL `relationships` table for cold storage
- Redis cache (5min TTL) for frequently checked relationships
- Fallback when relationship not in JWT

---

## Permission Model

### Permission Format

```
resource.action
```

**Examples:**
- `orders.read` - Read orders
- `orders.refund` - Refund orders
- `products.edit` - Edit products
- `admin.all` - Admin super-permission

### Wildcard Support

```rust
// User has permission: "products.*"

ctx.can("products", "edit")    // ✅ true
ctx.can("products", "delete")  // ✅ true
ctx.can("orders", "read")      // ❌ false
```

### Super-Wildcard

```rust
// User has permission: "*"

ctx.can("anything", "at_all")  // ✅ true
```

---

## Multi-Product Isolation (CRITICAL)

**Every service MUST validate product scope:**

```rust
require_product_scope!(ctx, "novaskyn");
```

**Why:** Prevents users from `lilitu` accessing `novaskyn` data.

**Database Queries:**
```sql
-- ALWAYS include product filter
SELECT * FROM orders
WHERE user_id = $1
  AND product = 'novaskyn'  -- ← MANDATORY
  AND deleted_at IS NULL;
```

**Products:**
- `novaskyn` - E-commerce marketplace (Brazil)
- `lilitu` - Dating platform (Brazil)
- `thai` - Emerging product (Thailand)

---

## Authorization Patterns

### Pattern 1: Permission-Only

```rust
require_permission!(ctx, "support", "dashboard");
```

**Use When:** Global permissions (admin actions, staff tools)

### Pattern 2: Ownership-Only

```rust
require_ownership!(ctx, "products", product_id);
```

**Use When:** User-specific resources (my products, my orders)

### Pattern 3: Admin OR Owner OR Permission

```rust
require_admin_or_owner_or_permission!(
    ctx,
    "products",
    product_id,
    "products.admin"
);
```

**Use When:** Resources that admins, owners, or privileged users can access

### Pattern 4: Self-Operation

```rust
require_self!(ctx, target_user_id);
```

**Use When:** User modifying their own account/profile

---

## Implementation Checklist for Services

### Step 1: Add pleme-rbac Dependency

```toml
[dependencies]
pleme-rbac = { path = "../../../../../libraries/rust/crates/pleme-rbac", features = ["web"] }
```

### Step 2: Apply Middleware

```rust
use pleme_rbac::axum_middleware::AuthLayer;

let app = Router::new()
    .route("/graphql", post(graphql_handler))
    .layer(AuthLayer::new());  // ← Add this
```

### Step 3: Inject into GraphQL Context

```rust
async fn graphql_handler(
    Extension(authz): Extension<AuthzContext>,
    Extension(schema): Extension<Schema>,
    req: Json<Request>,
) -> Json<Response> {
    let req = req.0.data(authz);  // ← Inject into GraphQL context
    Json(schema.execute(req).await)
}
```

### Step 4: Add Guards to Resolvers

```rust
use pleme_rbac::{require_permission, require_product_scope, get_user_id};

#[Object]
impl Query {
    async fn my_orders(&self, ctx: &Context<'_>) -> Result<Vec<Order>> {
        require_permission!(ctx, "orders", "read");
        require_product_scope!(ctx, "novaskyn");
        let user_id = get_user_id!(ctx);

        // Fetch with product filter
        Ok(self.repo.find_by_user(user_id, "novaskyn").await?)
    }
}
```

### Step 5: Remove Old Auth Code

Delete manual JWT parsing and role checking:

```rust
// DELETE THIS:
let user_id = headers
    .get("X-User-ID")
    .and_then(|h| h.to_str().ok())
    .and_then(|s| Uuid::parse_str(s).ok())
    .unwrap_or_else(Uuid::new_v4);

// DELETE THIS:
let authz = headers
    .get("Authorization")
    .and_then(|h| h.to_str().ok())
    .and_then(|auth| {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            pleme_rbac::AuthzContext::from_jwt(token).ok()
        } else {
            None
        }
    })
    .unwrap_or_else(pleme_rbac::AuthzContext::empty);
```

Middleware handles this automatically now.

---

## Migration Strategy

### Phase 1: Cart Service (Pilot)

✅ Complete standardization in cart service first
✅ Validate patterns work for guest + authenticated users
✅ Document lessons learned

### Phase 2: Critical Services (Order, Payment, Auth)

✅ Apply patterns to order, payment, and auth services
✅ These handle money - authorization is critical
✅ Verify no regressions

### Phase 3: Remaining Services

✅ Roll out to all 19 services
✅ Use cart/order as reference implementations
✅ Delete old auth code

---

## Security Principles

### 1. Fail-Closed by Default

```rust
// GOOD: Require authentication explicitly
require_permission!(ctx, "orders", "read");

// BAD: Permissive fallback
let authz = extract_auth().unwrap_or_else(AuthzContext::empty);
```

### 2. Explicit Product Scoping

```rust
// ALWAYS validate product
require_product_scope!(ctx, "novaskyn");

// ALWAYS filter database queries
WHERE product = 'novaskyn'
```

### 3. Principle of Least Privilege

```rust
// Specific permissions, not wildcards
require_permission!(ctx, "orders", "read");

// Not: require_permission!(ctx, "*", "*");
```

### 4. Defense in Depth

```
Layer 1: API Gateway validates JWT signature
Layer 2: Middleware extracts and validates claims
Layer 3: Resolvers check permissions/relationships
Layer 4: Database enforces product scoping
```

---

## Performance Characteristics

### Authorization Check Latency

| Operation | Latency | Network Calls |
|-----------|---------|---------------|
| Parse JWT | <10μs | 0 |
| Permission check | <1μs | 0 (HashSet lookup) |
| Relationship check | <1μs | 0 (HashMap lookup) |
| Product scope check | <1μs | 0 (string compare) |

### JWT Size Budget

| Data Type | Count | Size | Total |
|-----------|-------|------|-------|
| User metadata | 1 | 200B | 200B |
| Roles | 3 | 50B | 150B |
| Permissions | 20 | 100B | 2KB |
| Relationships | 30 | 40B | 1.2KB |
| **Total** | - | - | **~3.5KB** |

**Target:** Keep JWTs under 4KB (HTTP header limit is 8KB)

---

## Future Enhancements

### Phase 2: Relationship Inheritance

```rust
// owner implies editor implies viewer
if ctx.owns("product", id) {
    // Automatically has editor and viewer access
}
```

### Phase 3: Cedar Policy Engine

For complex business rules:

```cedar
permit(
    principal == User::"alice",
    action == Action::"refund",
    resource == Order::"123"
)
when {
    resource.amount < 500 &&
    resource.age < duration("24h")
};
```

### Phase 4: Database Fallback

For cold relationships not in JWT:

```rust
// Check JWT first (hot path)
if ctx.owns("product", id) {
    return Ok(());
}

// Fallback to database (cold path)
if relationship_store.has_relationship(user_id, "owner", "product", id).await? {
    return Ok(());
}
```

---

## References

- **Google Zanzibar Paper:** https://research.google/pubs/pub48190/
- **Cedar Policy Language:** https://www.cedarpolicy.com/
- **JWT Best Practices:** https://datatracker.ietf.org/doc/html/rfc8725
- **SpiceDB (Zanzibar OSS):** https://authzed.com/

---

## Questions & Answers

### Q: Why not use Casbin/Oso/other auth libraries?

**A:** We need Rust-native, async, zero-network auth that integrates with async-graphql and Axum. Existing libraries are either:
- Not Rust-native (Casbin is Java-focused)
- Deprecated (Oso shut down OSS)
- Too heavyweight (require external services)

pleme-rbac is purpose-built for our microservices architecture.

### Q: What if JWT gets too large?

**A:** We embed only "hot" data (top 30 relationships). Cold relationships use database fallback (Phase 2). Monitor JWT sizes and adjust limits.

### Q: How do permissions get updated?

**A:** Auth service manages roles and permissions. When changed, new JWT is issued on next refresh (15min). For critical changes, implement token invalidation.

### Q: Why product scoping in every query?

**A:** Defense in depth. Even if service bug allows cross-product request, database query prevents data leak. Multi-tenancy security.

---

**Document Owner:** Engineering Team
**Last Review:** 2025-01-15
**Next Review:** 2025-04-15 (quarterly)
