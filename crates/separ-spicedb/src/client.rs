//! SpiceDB gRPC client implementation

use std::sync::Arc;
use tonic::transport::{Channel, Endpoint};
use tonic::{metadata::MetadataValue, Request, Status};
use tracing::{debug, info, instrument};

use separ_core::{Result, SeparError};

use crate::proto;

/// Configuration for SpiceDB connection
#[derive(Debug, Clone)]
pub struct SpiceDbConfig {
    /// SpiceDB endpoint URL (e.g., "http://localhost:50051")
    pub endpoint: String,
    /// Pre-shared key for authentication
    pub token: String,
    /// Whether to use TLS
    pub use_tls: bool,
    /// Connection timeout in milliseconds
    pub connect_timeout_ms: u64,
    /// Request timeout in milliseconds
    pub request_timeout_ms: u64,
}

impl Default for SpiceDbConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:50051".to_string(),
            token: "somerandomkeyhere".to_string(),
            use_tls: false,
            connect_timeout_ms: 5000,
            request_timeout_ms: 30000,
        }
    }
}

/// SpiceDB client wrapper providing typed access to SpiceDB APIs
#[derive(Clone)]
pub struct SpiceDbClient {
    channel: Channel,
    token: Arc<String>,
}

impl SpiceDbClient {
    /// Create a new SpiceDB client
    #[instrument(skip(config), fields(endpoint = %config.endpoint))]
    pub async fn new(config: SpiceDbConfig) -> Result<Self> {
        info!("Connecting to SpiceDB at {}", config.endpoint);
        
        let endpoint = Endpoint::from_shared(config.endpoint.clone())
            .map_err(|e| SeparError::spicedb_error(format!("Invalid endpoint: {}", e)))?
            .connect_timeout(std::time::Duration::from_millis(config.connect_timeout_ms))
            .timeout(std::time::Duration::from_millis(config.request_timeout_ms));

        let channel = endpoint
            .connect()
            .await
            .map_err(|e| SeparError::spicedb_error(format!("Failed to connect: {}", e)))?;

        info!("Connected to SpiceDB successfully");

        Ok(Self {
            channel,
            token: Arc::new(config.token),
        })
    }

    /// Get the gRPC channel
    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }

    /// Get the auth token
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Create an authenticated request
    pub fn create_request<T>(&self, inner: T) -> std::result::Result<Request<T>, Status> {
        let mut request = Request::new(inner);
        
        if !self.token.is_empty() {
            let bearer = format!("Bearer {}", self.token);
            let metadata_value = MetadataValue::try_from(&bearer)
                .map_err(|e| Status::internal(format!("Invalid token: {}", e)))?;
            request.metadata_mut().insert("authorization", metadata_value);
        }
        
        Ok(request)
    }

    /// Get permissions service client
    pub fn permissions_client(&self) -> proto::permissions_service_client::PermissionsServiceClient<Channel> {
        proto::permissions_service_client::PermissionsServiceClient::new(self.channel.clone())
    }

    /// Get schema service client
    pub fn schema_client(&self) -> proto::schema_service_client::SchemaServiceClient<Channel> {
        proto::schema_service_client::SchemaServiceClient::new(self.channel.clone())
    }

    /// Check if the client is connected by pinging SpiceDB
    #[instrument(skip(self))]
    pub async fn health_check(&self) -> Result<bool> {
        debug!("Performing SpiceDB health check");
        // Try to read schema as a health check
        let mut client = self.schema_client();
        let request = self.create_request(proto::ReadSchemaRequest {})
            .map_err(|e| SeparError::spicedb_error(e.to_string()))?;
        
        match client.read_schema(request).await {
            Ok(_) => Ok(true),
            Err(e) => {
                debug!("SpiceDB health check failed: {}", e);
                Ok(false)
            }
        }
    }

    /// Write the authorization schema to SpiceDB
    #[instrument(skip(self, schema))]
    pub async fn write_schema(&self, schema: &str) -> Result<String> {
        info!("Writing schema to SpiceDB");
        let mut client = self.schema_client();
        
        let request = self.create_request(proto::WriteSchemaRequest {
            schema: schema.to_string(),
        }).map_err(|e| SeparError::spicedb_error(e.to_string()))?;

        let response = client.write_schema(request).await
            .map_err(|e| SeparError::spicedb_error(format!("Failed to write schema: {}", e)))?;

        let written_at = response.into_inner().written_at
            .map(|t| t.token)
            .unwrap_or_default();

        info!("Schema written successfully");
        Ok(written_at)
    }

    /// Read the current schema from SpiceDB
    #[instrument(skip(self))]
    pub async fn read_schema(&self) -> Result<String> {
        debug!("Reading schema from SpiceDB");
        let mut client = self.schema_client();
        
        let request = self.create_request(proto::ReadSchemaRequest {})
            .map_err(|e| SeparError::spicedb_error(e.to_string()))?;

        let response = client.read_schema(request).await
            .map_err(|e| SeparError::spicedb_error(format!("Failed to read schema: {}", e)))?;

        Ok(response.into_inner().schema_text)
    }

    /// Check a permission
    #[instrument(skip(self))]
    pub async fn check_permission(
        &self,
        resource_type: &str,
        resource_id: &str,
        permission: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<bool> {
        debug!(
            "Checking permission: {}:{}#{} for {}:{}",
            resource_type, resource_id, permission, subject_type, subject_id
        );

        let mut client = self.permissions_client();

        let request = self.create_request(proto::CheckPermissionRequest {
            resource: Some(proto::ObjectReference {
                object_type: resource_type.to_string(),
                object_id: resource_id.to_string(),
            }),
            permission: permission.to_string(),
            subject: Some(proto::SubjectReference {
                object: Some(proto::ObjectReference {
                    object_type: subject_type.to_string(),
                    object_id: subject_id.to_string(),
                }),
                optional_relation: String::new(),
            }),
            consistency: None,
            context: None,
            with_tracing: false,
        }).map_err(|e| SeparError::spicedb_error(e.to_string()))?;

        let response = client.check_permission(request).await
            .map_err(|e| SeparError::spicedb_error(format!("Permission check failed: {}", e)))?;

        // PERMISSIONSHIP_HAS_PERMISSION = 2
        let allowed = response.into_inner().permissionship == 2;
        debug!("Permission check result: {}", allowed);
        
        Ok(allowed)
    }

    /// Write a relationship
    #[instrument(skip(self))]
    pub async fn write_relationship(
        &self,
        resource_type: &str,
        resource_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<String> {
        debug!(
            "Writing relationship: {}:{}#{}@{}:{}",
            resource_type, resource_id, relation, subject_type, subject_id
        );

        let mut client = self.permissions_client();

        let request = self.create_request(proto::WriteRelationshipsRequest {
            updates: vec![proto::RelationshipUpdate {
                operation: 1, // OPERATION_TOUCH
                relationship: Some(proto::Relationship {
                    resource: Some(proto::ObjectReference {
                        object_type: resource_type.to_string(),
                        object_id: resource_id.to_string(),
                    }),
                    relation: relation.to_string(),
                    subject: Some(proto::SubjectReference {
                        object: Some(proto::ObjectReference {
                            object_type: subject_type.to_string(),
                            object_id: subject_id.to_string(),
                        }),
                        optional_relation: String::new(),
                    }),
                    optional_caveat: None,
                }),
            }],
            optional_preconditions: vec![],
        }).map_err(|e| SeparError::spicedb_error(e.to_string()))?;

        let response = client.write_relationships(request).await
            .map_err(|e| SeparError::spicedb_error(format!("Failed to write relationship: {}", e)))?;

        let token = response.into_inner().written_at
            .map(|t| t.token)
            .unwrap_or_default();

        info!("Relationship written successfully");
        Ok(token)
    }

    /// Delete a relationship
    #[instrument(skip(self))]
    pub async fn delete_relationship(
        &self,
        resource_type: &str,
        resource_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<String> {
        debug!(
            "Deleting relationship: {}:{}#{}@{}:{}",
            resource_type, resource_id, relation, subject_type, subject_id
        );

        let mut client = self.permissions_client();

        let request = self.create_request(proto::WriteRelationshipsRequest {
            updates: vec![proto::RelationshipUpdate {
                operation: 2, // OPERATION_DELETE
                relationship: Some(proto::Relationship {
                    resource: Some(proto::ObjectReference {
                        object_type: resource_type.to_string(),
                        object_id: resource_id.to_string(),
                    }),
                    relation: relation.to_string(),
                    subject: Some(proto::SubjectReference {
                        object: Some(proto::ObjectReference {
                            object_type: subject_type.to_string(),
                            object_id: subject_id.to_string(),
                        }),
                        optional_relation: String::new(),
                    }),
                    optional_caveat: None,
                }),
            }],
            optional_preconditions: vec![],
        }).map_err(|e| SeparError::spicedb_error(e.to_string()))?;

        let response = client.write_relationships(request).await
            .map_err(|e| SeparError::spicedb_error(format!("Failed to delete relationship: {}", e)))?;

        let token = response.into_inner().written_at
            .map(|t| t.token)
            .unwrap_or_default();

        info!("Relationship deleted successfully");
        Ok(token)
    }

    /// Lookup resources that a subject has permission on
    #[instrument(skip(self))]
    pub async fn lookup_resources(
        &self,
        resource_type: &str,
        permission: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Vec<String>> {
        debug!(
            "Looking up resources: {} with {} for {}:{}",
            resource_type, permission, subject_type, subject_id
        );

        let mut client = self.permissions_client();

        let request = self.create_request(proto::LookupResourcesRequest {
            resource_object_type: resource_type.to_string(),
            permission: permission.to_string(),
            subject: Some(proto::SubjectReference {
                object: Some(proto::ObjectReference {
                    object_type: subject_type.to_string(),
                    object_id: subject_id.to_string(),
                }),
                optional_relation: String::new(),
            }),
            consistency: None,
            context: None,
            optional_cursor: None,
            optional_limit: 0,
        }).map_err(|e| SeparError::spicedb_error(e.to_string()))?;

        let mut stream = client.lookup_resources(request).await
            .map_err(|e| SeparError::spicedb_error(format!("Lookup resources failed: {}", e)))?
            .into_inner();

        let mut resources = Vec::new();
        while let Some(response) = stream.message().await
            .map_err(|e| SeparError::spicedb_error(format!("Stream error: {}", e)))? {
            resources.push(response.resource_object_id);
        }

        debug!("Found {} resources", resources.len());
        Ok(resources)
    }

    /// Lookup subjects that have permission on a resource
    #[instrument(skip(self))]
    pub async fn lookup_subjects(
        &self,
        resource_type: &str,
        resource_id: &str,
        permission: &str,
        subject_type: &str,
    ) -> Result<Vec<String>> {
        debug!(
            "Looking up subjects: {} for {}:{}#{}",
            subject_type, resource_type, resource_id, permission
        );

        let mut client = self.permissions_client();

        let request = self.create_request(proto::LookupSubjectsRequest {
            resource: Some(proto::ObjectReference {
                object_type: resource_type.to_string(),
                object_id: resource_id.to_string(),
            }),
            permission: permission.to_string(),
            subject_object_type: subject_type.to_string(),
            optional_subject_relation: String::new(),
            consistency: None,
            context: None,
            optional_concrete_limit: 0,
            optional_cursor: None,
            wildcard_option: 0,
        }).map_err(|e| SeparError::spicedb_error(e.to_string()))?;

        let mut stream = client.lookup_subjects(request).await
            .map_err(|e| SeparError::spicedb_error(format!("Lookup subjects failed: {}", e)))?
            .into_inner();

        let mut subjects = Vec::new();
        while let Some(response) = stream.message().await
            .map_err(|e| SeparError::spicedb_error(format!("Stream error: {}", e)))? {
            if let Some(subject) = response.subject {
                subjects.push(subject.subject_object_id);
            }
        }

        debug!("Found {} subjects", subjects.len());
        Ok(subjects)
    }

    /// Read relationships matching a filter
    #[instrument(skip(self))]
    pub async fn read_relationships(
        &self,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
        relation: Option<&str>,
        subject_type: Option<&str>,
        subject_id: Option<&str>,
    ) -> Result<Vec<(String, String, String, String, String, Option<String>)>> {
        debug!(
            "Reading relationships: resource_type={:?}, resource_id={:?}, relation={:?}",
            resource_type, resource_id, relation
        );

        let mut client = self.permissions_client();

        // Build the relationship filter
        let relationship_filter = proto::RelationshipFilter {
            resource_type: resource_type.unwrap_or("").to_string(),
            optional_resource_id: resource_id.unwrap_or("").to_string(),
            optional_relation: relation.unwrap_or("").to_string(),
            optional_resource_id_prefix: String::new(),
            optional_subject_filter: subject_type.map(|st| proto::SubjectFilter {
                subject_type: st.to_string(),
                optional_subject_id: subject_id.unwrap_or("").to_string(),
                optional_relation: None,
            }),
        };

        let request = self.create_request(proto::ReadRelationshipsRequest {
            relationship_filter: Some(relationship_filter),
            consistency: None,
            optional_limit: 1000, // Limit to 1000 results
            optional_cursor: None,
        }).map_err(|e| SeparError::spicedb_error(e.to_string()))?;

        let mut stream = client.read_relationships(request).await
            .map_err(|e| SeparError::spicedb_error(format!("Read relationships failed: {}", e)))?
            .into_inner();

        let mut relationships = Vec::new();
        while let Some(response) = stream.message().await
            .map_err(|e| SeparError::spicedb_error(format!("Stream error: {}", e)))? {
            if let Some(rel) = response.relationship {
                let resource = rel.resource.as_ref();
                let subject = rel.subject.as_ref().and_then(|s| s.object.as_ref());
                let subject_relation = rel.subject.as_ref().map(|s| s.optional_relation.clone()).filter(|r| !r.is_empty());
                
                if let (Some(res), Some(sub)) = (resource, subject) {
                    relationships.push((
                        res.object_type.clone(),
                        res.object_id.clone(),
                        rel.relation.clone(),
                        sub.object_type.clone(),
                        sub.object_id.clone(),
                        subject_relation,
                    ));
                }
            }
        }

        debug!("Found {} relationships", relationships.len());
        Ok(relationships)
    }
}

impl std::fmt::Debug for SpiceDbClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiceDbClient")
            .field("has_token", &!self.token.is_empty())
            .finish()
    }
}
