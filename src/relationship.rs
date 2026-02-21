use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Relationship between subject and object
///
/// Examples:
/// - User alice owns Product 123
/// - User bob is member of Team support
/// - User charlie can view Conversation 456
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Relationship {
    /// Subject type (e.g., "user", "team", "organization")
    pub subject_type: String,

    /// Subject ID
    pub subject_id: Uuid,

    /// Relation type (e.g., "owner", "member", "viewer", "editor")
    pub relation: String,

    /// Object type (e.g., "product", "conversation", "ticket", "booking")
    pub object_type: String,

    /// Object ID
    pub object_id: Uuid,
}

impl Relationship {
    pub fn new(
        subject_type: impl Into<String>,
        subject_id: Uuid,
        relation: impl Into<String>,
        object_type: impl Into<String>,
        object_id: Uuid,
    ) -> Self {
        Self {
            subject_type: subject_type.into(),
            subject_id,
            relation: relation.into(),
            object_type: object_type.into(),
            object_id,
        }
    }

    /// Generate cache key for this relationship
    pub fn cache_key(&self) -> String {
        format!(
            "rel:{}:{}:{}:{}:{}",
            self.subject_type,
            self.subject_id,
            self.relation,
            self.object_type,
            self.object_id
        )
    }

    /// Format for JWT embedding (compact)
    pub fn jwt_key(&self) -> String {
        format!("{}:{}", self.object_type, self.relation)
    }
}

/// Standard relation types
pub mod relations {
    pub const OWNER: &str = "owner";
    pub const MEMBER: &str = "member";
    pub const VIEWER: &str = "viewer";
    pub const EDITOR: &str = "editor";
    pub const ASSIGNEE: &str = "assignee";
    pub const PARTICIPANT: &str = "participant";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relationship_creation() {
        let user_id = Uuid::new_v4();
        let product_id = Uuid::new_v4();

        let rel = Relationship::new(
            "user",
            user_id,
            relations::OWNER,
            "product",
            product_id,
        );

        assert_eq!(rel.subject_type, "user");
        assert_eq!(rel.subject_id, user_id);
        assert_eq!(rel.relation, "owner");
        assert_eq!(rel.object_type, "product");
        assert_eq!(rel.object_id, product_id);
    }

    #[test]
    fn test_cache_key() {
        let user_id = Uuid::new_v4();
        let product_id = Uuid::new_v4();

        let rel = Relationship::new(
            "user",
            user_id,
            relations::OWNER,
            "product",
            product_id,
        );

        let cache_key = rel.cache_key();
        assert!(cache_key.starts_with("rel:user:"));
        assert!(cache_key.contains(":owner:product:"));
    }

    #[test]
    fn test_jwt_key() {
        let user_id = Uuid::new_v4();
        let product_id = Uuid::new_v4();

        let rel = Relationship::new(
            "user",
            user_id,
            relations::OWNER,
            "product",
            product_id,
        );

        assert_eq!(rel.jwt_key(), "product:owner");
    }
}
