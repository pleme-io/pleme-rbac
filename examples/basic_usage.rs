//! Basic usage example for pleme-rbac
//!
//! This example demonstrates the main API patterns without requiring a database.

use pleme_rbac::{AuthzContext, AuthzResult};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

fn main() -> AuthzResult<()> {
    println!("=== pleme-rbac Basic Usage Example ===\n");

    // Example 1: Create a context with permissions
    let user_id = Uuid::new_v4();
    let product_id = Uuid::new_v4();

    let mut permissions = HashSet::new();
    permissions.insert("support.dashboard.read".to_string());
    permissions.insert("support.tickets.read".to_string());
    permissions.insert("products.*".to_string()); // Wildcard permission

    let mut relationships = HashMap::new();
    relationships.insert("products:owner".to_string(), vec![product_id]);

    let ctx = AuthzContext {
        user_id,
        email: "user@example.com".to_string(),
        product: "novaskyn".to_string(),
        roles: vec!["support_admin".to_string()],
        permissions,
        relationships,
    };

    println!("✓ Created AuthzContext for user: {}", ctx.email);
    println!("  Product: {}", ctx.product);
    println!("  Roles: {:?}", ctx.roles);
    println!();

    // Example 2: Permission checks
    println!("=== Permission Checks ===");

    if ctx.can("support", "dashboard.read") {
        println!("✓ User can read support dashboard");
    }

    if ctx.can("products", "edit") {
        println!("✓ User can edit products (via wildcard permission)");
    }

    if !ctx.can("orders", "refund") {
        println!("✗ User cannot refund orders (permission missing)");
    }
    println!();

    // Example 3: Require permission (returns error if missing)
    println!("=== Require Permission ===");

    match ctx.require("support", "dashboard.read") {
        Ok(_) => println!("✓ Required permission check passed"),
        Err(e) => println!("✗ Error: {}", e),
    }

    match ctx.require("admin", "delete_everything") {
        Ok(_) => println!("✓ Has admin permission"),
        Err(e) => println!("✗ Missing permission: {}", e),
    }
    println!();

    // Example 4: Require any permission (OR logic)
    println!("=== Require Any Permission (OR) ===");

    match ctx.require_any(&[("support", "dashboard.read"), ("admin", "all")]) {
        Ok(_) => println!("✓ User has at least one of the required permissions"),
        Err(e) => println!("✗ Error: {}", e),
    }
    println!();

    // Example 5: Relationship checks
    println!("=== Relationship Checks ===");

    if ctx.owns("products", product_id) {
        println!("✓ User owns product: {}", product_id);
    }

    if !ctx.owns("products", Uuid::new_v4()) {
        println!("✗ User does not own random product");
    }

    let owned_products = ctx.get_related_objects("products", "owner");
    println!("  User owns {} products", owned_products.len());
    println!();

    // Example 6: Role checks (backward compatibility)
    println!("=== Role Checks ===");

    if ctx.is_admin() {
        println!("✓ User is admin (support_admin ends with _admin)");
    }

    if ctx.is_staff() {
        println!("✓ User is staff (admins are also staff)");
    }

    if ctx.has_role("support_admin") {
        println!("✓ User has support_admin role");
    }
    println!();

    // Example 7: Combined checks
    println!("=== Combined Checks ===");

    if ctx.can_manage("products", product_id, "products.admin") {
        println!("✓ User can manage product (is admin OR owns it OR has permission)");
    }

    if ctx.is_self(user_id) {
        println!("✓ User is performing operation on their own account");
    }
    println!();

    println!("=== Example Complete ===");

    Ok(())
}
