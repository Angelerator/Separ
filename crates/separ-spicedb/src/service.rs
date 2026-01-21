//! High-level authorization service using SpiceDB

use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, info, instrument};

use separ_core::{
    AuthorizationService, CheckResult, Relationship, RelationshipFilter, Resource, Result,
    SeparError, Subject, SubjectType,
};

use crate::client::SpiceDbClient;

/// SpiceDB-backed authorization service
#[derive(Clone)]
pub struct SpiceDbAuthorizationService {
    client: Arc<SpiceDbClient>,
}

impl SpiceDbAuthorizationService {
    /// Create a new authorization service
    pub fn new(client: SpiceDbClient) -> Self {
        Self {
            client: Arc::new(client),
        }
    }

    /// Get the underlying client for advanced operations
    pub fn client(&self) -> &SpiceDbClient {
        &self.client
    }

    /// Initialize the schema in SpiceDB
    #[instrument(skip(self))]
    pub async fn initialize_schema(&self) -> Result<()> {
        info!("Initializing SpiceDB schema");
        self.client.write_schema(crate::YEKTA_SCHEMA).await?;
        info!("Schema initialized successfully");
        Ok(())
    }

    fn subject_type_to_str(subject_type: &SubjectType) -> &'static str {
        match subject_type {
            SubjectType::User => "user",
            SubjectType::ServiceAccount => "service_account",
            SubjectType::Group => "group",
            SubjectType::Platform => "platform",
            SubjectType::Tenant => "tenant",
            SubjectType::Workspace => "workspace",
            SubjectType::Application => "application",
            SubjectType::Role => "role",
            SubjectType::Anonymous => "anonymous",
            SubjectType::Wildcard => "*",
        }
    }

    fn str_to_subject_type(s: &str) -> SubjectType {
        match s {
            "user" => SubjectType::User,
            "service_account" => SubjectType::ServiceAccount,
            "group" => SubjectType::Group,
            "platform" => SubjectType::Platform,
            "tenant" => SubjectType::Tenant,
            "workspace" => SubjectType::Workspace,
            "application" => SubjectType::Application,
            "role" => SubjectType::Role,
            "anonymous" => SubjectType::Anonymous,
            "*" => SubjectType::Wildcard,
            _ => SubjectType::User, // Default fallback
        }
    }
}

#[async_trait]
impl AuthorizationService for SpiceDbAuthorizationService {
    #[instrument(skip(self))]
    async fn check_permission(
        &self,
        subject: &Subject,
        resource: &Resource,
        permission: &str,
    ) -> Result<CheckResult> {
        debug!(
            "Checking permission: {:?} -> {} on {:?}",
            subject, permission, resource
        );

        let subject_type = Self::subject_type_to_str(&subject.subject_type);

        let allowed = self
            .client
            .check_permission(
                &resource.resource_type,
                &resource.id,
                permission,
                subject_type,
                &subject.id,
            )
            .await?;

        Ok(CheckResult {
            allowed,
            checked_at: chrono::Utc::now(),
            debug_trace: None,
        })
    }

    #[instrument(skip(self))]
    async fn check_permissions_bulk(
        &self,
        checks: Vec<(Subject, Resource, String)>,
    ) -> Result<Vec<CheckResult>> {
        debug!("Bulk checking {} permissions", checks.len());

        // For now, do them sequentially. Could be optimized with SpiceDB's bulk check API
        let mut results = Vec::with_capacity(checks.len());
        for (subject, resource, permission) in checks {
            let result = self
                .check_permission(&subject, &resource, &permission)
                .await?;
            results.push(result);
        }

        Ok(results)
    }

    #[instrument(skip(self))]
    async fn write_relationship(&self, relationship: &Relationship) -> Result<String> {
        debug!("Writing relationship: {:?}", relationship);

        let subject_type = Self::subject_type_to_str(&relationship.subject.subject_type);

        self.client
            .write_relationship(
                &relationship.resource.resource_type,
                &relationship.resource.id,
                &relationship.relation,
                subject_type,
                &relationship.subject.id,
            )
            .await
    }

    #[instrument(skip(self))]
    async fn write_relationships(&self, relationships: &[Relationship]) -> Result<String> {
        debug!("Writing {} relationships", relationships.len());

        // Write each relationship (could be optimized with batching)
        let mut last_token = String::new();
        for relationship in relationships {
            last_token = self.write_relationship(relationship).await?;
        }

        Ok(last_token)
    }

    #[instrument(skip(self))]
    async fn delete_relationship(&self, relationship: &Relationship) -> Result<String> {
        debug!("Deleting relationship: {:?}", relationship);

        let subject_type = Self::subject_type_to_str(&relationship.subject.subject_type);

        self.client
            .delete_relationship(
                &relationship.resource.resource_type,
                &relationship.resource.id,
                &relationship.relation,
                subject_type,
                &relationship.subject.id,
            )
            .await
    }

    #[instrument(skip(self))]
    async fn delete_relationships(&self, _filter: &RelationshipFilter) -> Result<u64> {
        debug!("Deleting relationships by filter (not fully implemented)");
        // This would use DeleteRelationships API with a filter
        Err(SeparError::Internal {
            message: "Bulk delete by filter not implemented".to_string(),
        })
    }

    #[instrument(skip(self))]
    async fn lookup_resources(
        &self,
        subject: &Subject,
        permission: &str,
        resource_type: &str,
    ) -> Result<Vec<Resource>> {
        debug!(
            "Looking up resources: {:?} with {} on {}",
            subject, permission, resource_type
        );

        let subject_type = Self::subject_type_to_str(&subject.subject_type);

        let resource_ids = self
            .client
            .lookup_resources(resource_type, permission, subject_type, &subject.id)
            .await?;

        Ok(resource_ids
            .into_iter()
            .map(|id| Resource {
                resource_type: resource_type.to_string(),
                id,
            })
            .collect())
    }

    #[instrument(skip(self))]
    async fn lookup_subjects(
        &self,
        resource: &Resource,
        permission: &str,
        subject_type: &str,
    ) -> Result<Vec<Subject>> {
        debug!(
            "Looking up subjects: {} with {} on {:?}",
            subject_type, permission, resource
        );

        let subject_ids = self
            .client
            .lookup_subjects(
                &resource.resource_type,
                &resource.id,
                permission,
                subject_type,
            )
            .await?;

        let parsed_type = Self::str_to_subject_type(subject_type);

        Ok(subject_ids
            .into_iter()
            .map(|id| Subject {
                subject_type: parsed_type,
                id,
                relation: None,
            })
            .collect())
    }

    #[instrument(skip(self))]
    async fn read_relationships(&self, filter: &RelationshipFilter) -> Result<Vec<Relationship>> {
        debug!("Reading relationships with filter: {:?}", filter);

        let results = self
            .client
            .read_relationships(
                filter.resource_type.as_deref(),
                filter.resource_id.as_deref(),
                filter.relation.as_deref(),
                filter.subject_type.as_deref(),
                filter.subject_id.as_deref(),
            )
            .await?;

        let relationships: Vec<Relationship> = results
            .into_iter()
            .map(
                |(res_type, res_id, relation, sub_type, sub_id, sub_rel)| Relationship {
                    resource: Resource {
                        resource_type: res_type,
                        id: res_id,
                    },
                    relation,
                    subject: Subject {
                        subject_type: Self::str_to_subject_type(&sub_type),
                        id: sub_id,
                        relation: sub_rel,
                    },
                    caveat: None,
                },
            )
            .collect();

        debug!("Found {} relationships", relationships.len());
        Ok(relationships)
    }
}

impl std::fmt::Debug for SpiceDbAuthorizationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiceDbAuthorizationService").finish()
    }
}
