//! Axum middleware for extracting and validating authorization context
//!
//! This module provides batteries-included middleware for Axum web servers
//! that automatically extracts authentication context from gateway-injected
//! x-user-* headers and injects AuthzContext into request extensions.
//!
//! # Architecture Pattern
//!
//! Services MUST read x-user-* headers injected by the gateway (Hive Router).
//! Services should NEVER parse JWT tokens - that's the gateway's responsibility.
//!
//! **Three-Layer Security**:
//! 1. Gateway: Validates JWT + signs with HMAC + injects x-user-* headers
//! 2. Services: Verify HMAC + read trusted headers (this middleware)
//! 3. Resolvers: Check permissions from AuthzContext
//!
//! # Usage
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//! use pleme_rbac::axum_middleware::{AuthLayer, OptionalAuthLayer};
//!
//! // Require authentication for all routes
//! let app = Router::new()
//!     .route("/api/orders", get(list_orders))
//!     .layer(AuthLayer::new());
//!
//! // Optional authentication (for guest checkout)
//! let app = Router::new()
//!     .route("/api/cart", get(get_cart))
//!     .layer(OptionalAuthLayer::new());
//! ```

use crate::{AuthzContext, AuthzError, AuthzResult};
use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tower::{Layer, Service};

/// Axum layer for required authentication
///
/// This layer reads authentication context from gateway-injected x-user-* headers
/// and injects AuthzContext into request extensions.
///
/// **CRITICAL**: This layer expects x-user-* headers from the gateway (Hive Router).
/// Services should NEVER parse JWT tokens directly.
///
/// If authentication fails (missing headers), returns 401 Unauthorized.
#[derive(Clone)]
pub struct AuthLayer;

impl AuthLayer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AuthLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware { inner }
    }
}

#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
}

impl<S> Service<Request> for AuthMiddleware<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Extract AuthzContext from headers
            let authz_result = extract_authz_from_headers(req.headers());

            match authz_result {
                Ok(authz) => {
                    // Inject into request extensions
                    req.extensions_mut().insert(authz);
                    // Continue to next middleware/handler
                    inner.call(req).await
                }
                Err(e) => {
                    // Return 401 Unauthorized
                    Ok(auth_error_response(e))
                }
            }
        })
    }
}

/// Axum layer for optional authentication
///
/// This layer attempts to extract authentication from x-user-* headers but continues even if it fails.
/// If headers are present and valid, injects AuthzContext. Otherwise, injects empty context.
///
/// Useful for endpoints that support both authenticated and guest users (e.g., cart service).
#[derive(Clone)]
pub struct OptionalAuthLayer;

impl OptionalAuthLayer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OptionalAuthLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for OptionalAuthLayer {
    type Service = OptionalAuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OptionalAuthMiddleware { inner }
    }
}

#[derive(Clone)]
pub struct OptionalAuthMiddleware<S> {
    inner: S,
}

impl<S> Service<Request> for OptionalAuthMiddleware<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Try to extract AuthzContext, fallback to empty if not present
            let authz = extract_authz_from_headers(req.headers())
                .unwrap_or_else(|_| AuthzContext::empty());

            // Inject into request extensions
            req.extensions_mut().insert(authz);

            // Continue to next middleware/handler
            inner.call(req).await
        })
    }
}

/// Extract AuthzContext from HTTP headers
///
/// **CRITICAL SECURITY PATTERN**: Services MUST read x-user-* headers injected by the gateway.
/// Services should NEVER parse JWT tokens directly - that's the gateway's responsibility.
///
/// ## Architecture (Three-Layer Security)
///
/// 1. **Gateway Layer** (Hive Router):
///    - Validates JWT signature via JWKS endpoint
///    - Signs request with HMAC signature
///    - Injects trusted x-user-* headers (x-user-id, x-user-email, x-user-roles, etc.)
///
/// 2. **Service Layer** (this code):
///    - Verifies HMAC signature (proves request came through gateway)
///    - Reads trusted x-user-* headers
///    - NEVER parses JWT (zero-trust: don't trust Authorization header)
///
/// 3. **Resolver Layer**:
///    - Checks permissions from AuthzContext
///    - Enforces authorization rules
///
/// This pattern provides:
/// - Centralized JWT validation (single source of truth)
/// - Zero-trust security (services don't trust clients)
/// - HMAC protection (prevents direct subgraph access)
/// - Consistent auth across all microservices
pub fn extract_authz_from_headers(headers: &HeaderMap) -> AuthzResult<AuthzContext> {
    // ONLY read x-user-* headers (gateway-injected after JWT validation + HMAC signing)
    // Services should NEVER parse JWTs directly
    AuthzContext::from_headers(headers)
}

/// Axum middleware function for required authentication
///
/// Alternative to using AuthLayer if you prefer function-based middleware.
///
/// # Usage
///
/// ```rust,no_run
/// use axum::{Router, routing::get, middleware};
/// use pleme_rbac::axum_middleware::auth_middleware;
///
/// let app = Router::new()
///     .route("/api/orders", get(list_orders))
///     .layer(middleware::from_fn(auth_middleware));
/// ```
pub async fn auth_middleware(
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    let authz = extract_authz_from_headers(req.headers())
        .map_err(auth_error_response)?;

    req.extensions_mut().insert(authz);
    Ok(next.run(req).await)
}

/// Axum middleware function for optional authentication
///
/// Alternative to using OptionalAuthLayer if you prefer function-based middleware.
pub async fn optional_auth_middleware(
    mut req: Request,
    next: Next,
) -> Response {
    let authz = extract_authz_from_headers(req.headers())
        .unwrap_or_else(|_| AuthzContext::empty());

    req.extensions_mut().insert(authz);
    next.run(req).await
}

/// Convert AuthzError to HTTP response in GraphQL format
///
/// Returns a GraphQL-compliant error response so Apollo Client and other
/// GraphQL clients can properly handle authentication/authorization failures.
///
/// ## Error Code Mapping
///
/// - `InvalidHeader` (missing x-user-* headers) → `GATEWAY_AUTH_ERROR` (500)
///   - This indicates the gateway didn't inject headers, NOT that the user is unauthenticated
///   - Should NOT trigger client-side token refresh (user's token may be valid)
///   - Common cause: gateway misconfiguration, direct subgraph access, or HMAC failure
///
/// - `ParseError` (malformed headers) → `UNAUTHENTICATED` (401)
///   - Headers present but couldn't be parsed (corrupted data)
///   - May indicate token tampering or encoding issues
///
/// - `Forbidden` / `MissingPermission` → `FORBIDDEN` (403)
///   - User is authenticated but lacks required permissions
///   - Should NOT trigger token refresh (user is logged in, just not authorized)
fn auth_error_response(error: AuthzError) -> Response {
    let (status_code, error_code, original_error) = match &error {
        // Missing headers from gateway - this is a server-side issue, not user auth issue
        // Using 500 and custom code so Apollo Client doesn't try to refresh token
        AuthzError::InvalidHeader(msg) if msg.contains("Missing header") => {
            (StatusCode::INTERNAL_SERVER_ERROR, "GATEWAY_AUTH_ERROR", "missing_gateway_headers")
        }
        // Other header issues (malformed values, invalid UTF-8, etc.)
        AuthzError::InvalidHeader(_) | AuthzError::ParseError(_) => {
            (StatusCode::UNAUTHORIZED, "UNAUTHENTICATED", "authentication_failed")
        }
        // Authorization failures - user is authenticated but lacks permission
        AuthzError::Forbidden(_) | AuthzError::MissingPermission(_) => {
            (StatusCode::FORBIDDEN, "FORBIDDEN", "authorization_failed")
        }
        // Database/cache errors are internal server errors
        #[cfg(feature = "db")]
        AuthzError::DatabaseError(_) | AuthzError::CacheError(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", "server_error")
        }
        // Policy errors
        #[cfg(feature = "policies")]
        AuthzError::PolicyError(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", "policy_error")
        }
    };

    // Return GraphQL-formatted error
    let body = serde_json::json!({
        "data": null,
        "errors": [{
            "message": error.to_string(),
            "extensions": {
                "code": error_code,
                "originalError": original_error
            }
        }]
    });

    (status_code, axum::Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_from_headers_missing() {
        let headers = HeaderMap::new();
        let result = extract_authz_from_headers(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_from_x_user_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-user-id", HeaderValue::from_static("550e8400-e29b-41d4-a716-446655440000"));
        headers.insert("x-user-email", HeaderValue::from_static("test@example.com"));
        headers.insert("x-product", HeaderValue::from_static("novaskyn"));
        headers.insert("x-user-roles", HeaderValue::from_static("user,customer"));
        headers.insert("x-user-permissions", HeaderValue::from_static("orders.read"));
        headers.insert("x-user-relationships", HeaderValue::from_static("{}"));

        let result = extract_authz_from_headers(&headers);
        assert!(result.is_ok());

        let authz = result.unwrap();
        assert_eq!(authz.email, "test@example.com");
        assert_eq!(authz.product, "novaskyn");
    }

    #[test]
    fn test_extract_without_optional_headers() {
        // Test that x-user-permissions and x-user-relationships are optional
        let mut headers = HeaderMap::new();
        headers.insert("x-user-id", HeaderValue::from_static("550e8400-e29b-41d4-a716-446655440000"));
        headers.insert("x-user-email", HeaderValue::from_static("test@example.com"));
        headers.insert("x-product", HeaderValue::from_static("novaskyn"));
        headers.insert("x-user-roles", HeaderValue::from_static("user,customer"));
        // x-user-permissions and x-user-relationships are intentionally omitted

        let result = extract_authz_from_headers(&headers);
        assert!(result.is_ok(), "Should succeed without optional headers");

        let authz = result.unwrap();
        assert_eq!(authz.email, "test@example.com");
        assert_eq!(authz.product, "novaskyn");
        assert!(authz.permissions.is_empty(), "Permissions should default to empty");
        assert!(authz.relationships.is_empty(), "Relationships should default to empty");
    }
}
