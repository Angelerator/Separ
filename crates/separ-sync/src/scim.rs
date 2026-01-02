//! SCIM 2.0 Protocol Handler
//!
//! Implements SCIM (System for Cross-domain Identity Management) protocol
//! for user and group provisioning from external IdPs.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, instrument, warn};

use separ_core::{
    AuthorizationService, Group, GroupId, GroupRepository, Relationship, Resource, Result,
    ScimEmail, ScimGroup, ScimHandler, ScimMember, ScimUser, SeparError, Subject, SubjectType,
    TenantId, User, UserId, UserRepository, UserStatus,
};

/// SCIM Service implementation
pub struct ScimService<U, G, A>
where
    U: UserRepository,
    G: GroupRepository,
    A: AuthorizationService,
{
    user_repo: Arc<U>,
    group_repo: Arc<G>,
    auth_service: Arc<A>,
}

impl<U, G, A> ScimService<U, G, A>
where
    U: UserRepository,
    G: GroupRepository,
    A: AuthorizationService,
{
    pub fn new(user_repo: Arc<U>, group_repo: Arc<G>, auth_service: Arc<A>) -> Self {
        Self {
            user_repo,
            group_repo,
            auth_service,
        }
    }
}

#[async_trait]
impl<U, G, A> ScimHandler for ScimService<U, G, A>
where
    U: UserRepository + 'static,
    G: GroupRepository + 'static,
    A: AuthorizationService + 'static,
{
    #[instrument(skip(self, scim_user))]
    async fn create_user(&self, tenant_id: TenantId, scim_user: ScimUser) -> Result<User> {
        info!(
            "SCIM: Creating user {} for tenant {}",
            scim_user.user_name, tenant_id
        );

        // Check if user already exists
        let primary_email = scim_user
            .emails
            .iter()
            .find(|e| e.primary)
            .or(scim_user.emails.first())
            .map(|e| e.value.clone())
            .unwrap_or(scim_user.user_name.clone());

        if let Some(existing) = self
            .user_repo
            .get_by_email(tenant_id, &primary_email)
            .await?
        {
            warn!("SCIM: User {} already exists", primary_email);
            return Ok(existing);
        }

        let user = User {
            id: UserId::new(),
            tenant_id,
            external_id: scim_user.external_id,
            email: primary_email,
            email_verified: true, // SCIM provisioned users are pre-verified
            display_name: scim_user.display_name.unwrap_or(scim_user.user_name),
            given_name: scim_user.given_name,
            family_name: scim_user.family_name,
            picture_url: None,
            locale: None,
            timezone: None,
            status: if scim_user.active {
                UserStatus::Active
            } else {
                UserStatus::Inactive
            },
            metadata: Default::default(),
            last_login_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let created_user = self.user_repo.create(&user).await?;

        // Create relationship in SpiceDB: user is member of tenant
        let relationship = Relationship {
            resource: Resource {
                resource_type: "tenant".to_string(),
                id: tenant_id.to_spicedb_id(),
            },
            relation: "member".to_string(),
            subject: Subject {
                subject_type: SubjectType::User,
                id: created_user.id.to_spicedb_id(),
                relation: None,
            },
            caveat: None,
        };
        self.auth_service.write_relationship(&relationship).await?;

        info!(
            "SCIM: Created user {} with id {}",
            created_user.email, created_user.id
        );
        Ok(created_user)
    }

    #[instrument(skip(self, scim_user))]
    async fn update_user(
        &self,
        tenant_id: TenantId,
        external_id: &str,
        scim_user: ScimUser,
    ) -> Result<User> {
        info!(
            "SCIM: Updating user {} for tenant {}",
            external_id, tenant_id
        );

        let existing = self
            .user_repo
            .get_by_external_id(tenant_id, external_id)
            .await?
            .ok_or_else(|| SeparError::not_found("user", external_id))?;

        let primary_email = scim_user
            .emails
            .iter()
            .find(|e| e.primary)
            .or(scim_user.emails.first())
            .map(|e| e.value.clone())
            .unwrap_or(existing.email.clone());

        let updated_user = User {
            id: existing.id,
            tenant_id,
            external_id: scim_user.external_id.or(Some(external_id.to_string())),
            email: primary_email,
            email_verified: existing.email_verified,
            display_name: scim_user.display_name.unwrap_or(existing.display_name),
            given_name: scim_user.given_name.or(existing.given_name),
            family_name: scim_user.family_name.or(existing.family_name),
            picture_url: existing.picture_url,
            locale: existing.locale,
            timezone: existing.timezone,
            status: if scim_user.active {
                UserStatus::Active
            } else {
                UserStatus::Inactive
            },
            metadata: existing.metadata,
            last_login_at: existing.last_login_at,
            created_at: existing.created_at,
            updated_at: chrono::Utc::now(),
        };

        let result = self.user_repo.update(&updated_user).await?;
        info!("SCIM: Updated user {}", result.id);
        Ok(result)
    }

    #[instrument(skip(self))]
    async fn delete_user(&self, tenant_id: TenantId, external_id: &str) -> Result<()> {
        info!(
            "SCIM: Deleting user {} for tenant {}",
            external_id, tenant_id
        );

        let user = self
            .user_repo
            .get_by_external_id(tenant_id, external_id)
            .await?
            .ok_or_else(|| SeparError::not_found("user", external_id))?;

        // Delete SpiceDB relationships
        let relationship = Relationship {
            resource: Resource {
                resource_type: "tenant".to_string(),
                id: tenant_id.to_spicedb_id(),
            },
            relation: "member".to_string(),
            subject: Subject {
                subject_type: SubjectType::User,
                id: user.id.to_spicedb_id(),
                relation: None,
            },
            caveat: None,
        };
        self.auth_service.delete_relationship(&relationship).await?;

        // Delete user from database
        self.user_repo.delete(user.id).await?;

        info!("SCIM: Deleted user {}", external_id);
        Ok(())
    }

    #[instrument(skip(self, scim_group))]
    async fn create_group(&self, tenant_id: TenantId, scim_group: ScimGroup) -> Result<Group> {
        info!(
            "SCIM: Creating group {} for tenant {}",
            scim_group.display_name, tenant_id
        );

        let group = Group {
            id: GroupId::new(),
            tenant_id,
            name: scim_group.display_name,
            description: None,
            external_id: scim_group.external_id,
            metadata: Default::default(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let created_group = self.group_repo.create(&group).await?;

        // Add members to the group
        for member in scim_group.members {
            if let Some(user) = self
                .user_repo
                .get_by_external_id(tenant_id, &member.value)
                .await?
            {
                self.group_repo
                    .add_member(created_group.id, user.id)
                    .await?;

                // Create SpiceDB relationship: user is member of group
                let relationship = Relationship {
                    resource: Resource {
                        resource_type: "group".to_string(),
                        id: created_group.id.to_spicedb_id(),
                    },
                    relation: "member".to_string(),
                    subject: Subject {
                        subject_type: SubjectType::User,
                        id: user.id.to_spicedb_id(),
                        relation: None,
                    },
                    caveat: None,
                };
                self.auth_service.write_relationship(&relationship).await?;
            }
        }

        info!(
            "SCIM: Created group {} with id {}",
            created_group.name, created_group.id
        );
        Ok(created_group)
    }

    #[instrument(skip(self, scim_group))]
    async fn update_group(
        &self,
        tenant_id: TenantId,
        external_id: &str,
        scim_group: ScimGroup,
    ) -> Result<Group> {
        info!(
            "SCIM: Updating group {} for tenant {}",
            external_id, tenant_id
        );

        // Find group by external_id (would need to add this to repository)
        // For now, simplified implementation
        let existing_groups = self.group_repo.list_by_tenant(tenant_id, 0, 1000).await?;
        let existing = existing_groups
            .into_iter()
            .find(|g| g.external_id.as_deref() == Some(external_id))
            .ok_or_else(|| SeparError::not_found("group", external_id))?;

        let updated_group = Group {
            id: existing.id,
            tenant_id,
            name: scim_group.display_name,
            description: existing.description,
            external_id: scim_group.external_id.or(Some(external_id.to_string())),
            metadata: existing.metadata,
            created_at: existing.created_at,
            updated_at: chrono::Utc::now(),
        };

        let result = self.group_repo.update(&updated_group).await?;

        // Update group members would require more complex logic
        // to diff current vs new members

        info!("SCIM: Updated group {}", result.id);
        Ok(result)
    }

    #[instrument(skip(self))]
    async fn delete_group(&self, tenant_id: TenantId, external_id: &str) -> Result<()> {
        info!(
            "SCIM: Deleting group {} for tenant {}",
            external_id, tenant_id
        );

        let existing_groups = self.group_repo.list_by_tenant(tenant_id, 0, 1000).await?;
        let group = existing_groups
            .into_iter()
            .find(|g| g.external_id.as_deref() == Some(external_id))
            .ok_or_else(|| SeparError::not_found("group", external_id))?;

        self.group_repo.delete(group.id).await?;

        info!("SCIM: Deleted group {}", external_id);
        Ok(())
    }
}

// =============================================================================
// SCIM Request/Response Types
// =============================================================================

/// SCIM 2.0 User Resource
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUserResource {
    pub schemas: Vec<String>,
    pub id: Option<String>,
    pub external_id: Option<String>,
    pub user_name: String,
    pub name: Option<ScimName>,
    pub display_name: Option<String>,
    pub emails: Option<Vec<ScimEmailResource>>,
    pub active: Option<bool>,
    pub groups: Option<Vec<ScimGroupRef>>,
    pub meta: Option<ScimMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    pub formatted: Option<String>,
    pub family_name: Option<String>,
    pub given_name: Option<String>,
    pub middle_name: Option<String>,
    pub honorific_prefix: Option<String>,
    pub honorific_suffix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimEmailResource {
    pub value: String,
    pub primary: Option<bool>,
    #[serde(rename = "type")]
    pub email_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroupRef {
    pub value: String,
    #[serde(rename = "$ref")]
    pub reference: Option<String>,
    pub display: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimMeta {
    pub resource_type: Option<String>,
    pub created: Option<String>,
    pub last_modified: Option<String>,
    pub location: Option<String>,
    pub version: Option<String>,
}

/// SCIM 2.0 Group Resource
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroupResource {
    pub schemas: Vec<String>,
    pub id: Option<String>,
    pub external_id: Option<String>,
    pub display_name: String,
    pub members: Option<Vec<ScimMemberResource>>,
    pub meta: Option<ScimMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimMemberResource {
    pub value: String,
    #[serde(rename = "$ref")]
    pub reference: Option<String>,
    pub display: Option<String>,
}

/// SCIM List Response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimListResponse<T> {
    pub schemas: Vec<String>,
    pub total_results: u32,
    pub items_per_page: u32,
    pub start_index: u32,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

/// SCIM Error Response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimErrorResponse {
    pub schemas: Vec<String>,
    pub status: String,
    pub scim_type: Option<String>,
    pub detail: String,
}

impl ScimUserResource {
    pub fn to_scim_user(&self) -> ScimUser {
        ScimUser {
            external_id: self.external_id.clone().or(self.id.clone()),
            user_name: self.user_name.clone(),
            display_name: self.display_name.clone(),
            given_name: self.name.as_ref().and_then(|n| n.given_name.clone()),
            family_name: self.name.as_ref().and_then(|n| n.family_name.clone()),
            emails: self
                .emails
                .as_ref()
                .map(|emails| {
                    emails
                        .iter()
                        .map(|e| ScimEmail {
                            value: e.value.clone(),
                            primary: e.primary.unwrap_or(false),
                            email_type: e.email_type.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            active: self.active.unwrap_or(true),
            groups: self
                .groups
                .as_ref()
                .map(|groups| groups.iter().map(|g| g.value.clone()).collect())
                .unwrap_or_default(),
        }
    }
}

impl ScimGroupResource {
    pub fn to_scim_group(&self) -> ScimGroup {
        ScimGroup {
            external_id: self.external_id.clone().or(self.id.clone()),
            display_name: self.display_name.clone(),
            members: self
                .members
                .as_ref()
                .map(|members| {
                    members
                        .iter()
                        .map(|m| ScimMember {
                            value: m.value.clone(),
                            display: m.display.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}
