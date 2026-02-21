use thiserror::Error;

pub type AuthzResult<T> = Result<T, AuthzError>;

#[derive(Debug, Error)]
pub enum AuthzError {
    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Missing permission: {0}")]
    MissingPermission(String),

    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[cfg(feature = "db")]
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[cfg(feature = "db")]
    #[error("Cache error: {0}")]
    CacheError(#[from] redis::RedisError),

    #[cfg(feature = "policies")]
    #[error("Policy evaluation error: {0}")]
    PolicyError(String),
}

// Convert to HTTP status codes for web services
impl AuthzError {
    pub fn status_code(&self) -> u16 {
        match self {
            AuthzError::Forbidden(_) | AuthzError::MissingPermission(_) => 403,
            AuthzError::InvalidHeader(_) | AuthzError::ParseError(_) => 401,
            #[cfg(feature = "db")]
            AuthzError::DatabaseError(_) | AuthzError::CacheError(_) => 500,
            #[cfg(feature = "policies")]
            AuthzError::PolicyError(_) => 500,
        }
    }
}
