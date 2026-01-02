//! SpiceDB client and authorization service for Separ

pub mod client;
pub mod schema;
pub mod service;

#[cfg(test)]
mod tests;

pub use client::{SpiceDbClient, SpiceDbConfig};
pub use schema::YEKTA_SCHEMA;
pub use service::SpiceDbAuthorizationService;

/// Generated protobuf types from SpiceDB
#[allow(clippy::all)]
pub mod proto {
    // Core types
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ObjectReference {
        #[prost(string, tag = "1")]
        pub object_type: String,
        #[prost(string, tag = "2")]
        pub object_id: String,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SubjectReference {
        #[prost(message, optional, tag = "1")]
        pub object: Option<ObjectReference>,
        #[prost(string, tag = "2")]
        pub optional_relation: String,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Relationship {
        #[prost(message, optional, tag = "1")]
        pub resource: Option<ObjectReference>,
        #[prost(string, tag = "2")]
        pub relation: String,
        #[prost(message, optional, tag = "3")]
        pub subject: Option<SubjectReference>,
        #[prost(message, optional, tag = "4")]
        pub optional_caveat: Option<ContextualizedCaveat>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ContextualizedCaveat {
        #[prost(string, tag = "1")]
        pub caveat_name: String,
        #[prost(message, optional, tag = "2")]
        pub context: Option<::prost_types::Struct>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ZedToken {
        #[prost(string, tag = "1")]
        pub token: String,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Consistency {
        #[prost(oneof = "consistency::Requirement", tags = "1, 2, 3, 4")]
        pub requirement: Option<consistency::Requirement>,
    }

    pub mod consistency {
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Requirement {
            #[prost(bool, tag = "1")]
            MinimizeLatency(bool),
            #[prost(message, tag = "2")]
            AtLeastAsFresh(super::ZedToken),
            #[prost(message, tag = "3")]
            AtExactSnapshot(super::ZedToken),
            #[prost(bool, tag = "4")]
            FullyConsistent(bool),
        }
    }

    // Schema service
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ReadSchemaRequest {}

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ReadSchemaResponse {
        #[prost(string, tag = "1")]
        pub schema_text: String,
        #[prost(message, optional, tag = "2")]
        pub read_at: Option<ZedToken>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct WriteSchemaRequest {
        #[prost(string, tag = "1")]
        pub schema: String,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct WriteSchemaResponse {
        #[prost(message, optional, tag = "1")]
        pub written_at: Option<ZedToken>,
    }

    // Permissions service
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CheckPermissionRequest {
        #[prost(message, optional, tag = "1")]
        pub consistency: Option<Consistency>,
        #[prost(message, optional, tag = "2")]
        pub resource: Option<ObjectReference>,
        #[prost(string, tag = "3")]
        pub permission: String,
        #[prost(message, optional, tag = "4")]
        pub subject: Option<SubjectReference>,
        #[prost(message, optional, tag = "5")]
        pub context: Option<::prost_types::Struct>,
        #[prost(bool, tag = "6")]
        pub with_tracing: bool,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CheckPermissionResponse {
        #[prost(message, optional, tag = "1")]
        pub checked_at: Option<ZedToken>,
        #[prost(enumeration = "CheckPermissionResponsePermissionship", tag = "2")]
        pub permissionship: i32,
        #[prost(message, optional, tag = "3")]
        pub partial_caveat_info: Option<PartialCaveatInfo>,
        #[prost(message, optional, tag = "4")]
        pub debug_trace: Option<DebugInformation>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum CheckPermissionResponsePermissionship {
        Unspecified = 0,
        NoPermission = 1,
        HasPermission = 2,
        ConditionalPermission = 3,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PartialCaveatInfo {
        #[prost(string, repeated, tag = "1")]
        pub missing_required_context: Vec<String>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DebugInformation {
        #[prost(message, optional, tag = "1")]
        pub check: Option<CheckDebugTrace>,
        #[prost(string, tag = "2")]
        pub schema_used: String,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CheckDebugTrace {}

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RelationshipUpdate {
        #[prost(enumeration = "relationship_update::Operation", tag = "1")]
        pub operation: i32,
        #[prost(message, optional, tag = "2")]
        pub relationship: Option<Relationship>,
    }

    pub mod relationship_update {
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum Operation {
            Unspecified = 0,
            Touch = 1,
            Create = 2,
            Delete = 3,
        }
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Precondition {
        #[prost(enumeration = "precondition::Operation", tag = "1")]
        pub operation: i32,
        #[prost(message, optional, tag = "2")]
        pub filter: Option<RelationshipFilter>,
    }

    pub mod precondition {
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum Operation {
            Unspecified = 0,
            MustNotMatch = 1,
            MustMatch = 2,
        }
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RelationshipFilter {
        #[prost(string, tag = "1")]
        pub resource_type: String,
        #[prost(string, tag = "2")]
        pub optional_resource_id: String,
        #[prost(string, tag = "3")]
        pub optional_resource_id_prefix: String,
        #[prost(string, tag = "4")]
        pub optional_relation: String,
        #[prost(message, optional, tag = "5")]
        pub optional_subject_filter: Option<SubjectFilter>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SubjectFilter {
        #[prost(string, tag = "1")]
        pub subject_type: String,
        #[prost(string, tag = "2")]
        pub optional_subject_id: String,
        #[prost(message, optional, tag = "3")]
        pub optional_relation: Option<subject_filter::RelationFilter>,
    }

    pub mod subject_filter {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct RelationFilter {
            #[prost(string, tag = "1")]
            pub relation: String,
        }
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct WriteRelationshipsRequest {
        #[prost(message, repeated, tag = "1")]
        pub updates: Vec<RelationshipUpdate>,
        #[prost(message, repeated, tag = "2")]
        pub optional_preconditions: Vec<Precondition>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct WriteRelationshipsResponse {
        #[prost(message, optional, tag = "1")]
        pub written_at: Option<ZedToken>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ReadRelationshipsRequest {
        #[prost(message, optional, tag = "1")]
        pub consistency: Option<Consistency>,
        #[prost(message, optional, tag = "2")]
        pub relationship_filter: Option<RelationshipFilter>,
        #[prost(uint32, tag = "3")]
        pub optional_limit: u32,
        #[prost(message, optional, tag = "4")]
        pub optional_cursor: Option<Cursor>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ReadRelationshipsResponse {
        #[prost(message, optional, tag = "1")]
        pub read_at: Option<ZedToken>,
        #[prost(message, optional, tag = "2")]
        pub relationship: Option<Relationship>,
        #[prost(message, optional, tag = "3")]
        pub after_result_cursor: Option<Cursor>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct LookupResourcesRequest {
        #[prost(message, optional, tag = "1")]
        pub consistency: Option<Consistency>,
        #[prost(string, tag = "2")]
        pub resource_object_type: String,
        #[prost(string, tag = "3")]
        pub permission: String,
        #[prost(message, optional, tag = "4")]
        pub subject: Option<SubjectReference>,
        #[prost(message, optional, tag = "5")]
        pub context: Option<::prost_types::Struct>,
        #[prost(uint32, tag = "6")]
        pub optional_limit: u32,
        #[prost(message, optional, tag = "7")]
        pub optional_cursor: Option<Cursor>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct LookupResourcesResponse {
        #[prost(message, optional, tag = "1")]
        pub looked_up_at: Option<ZedToken>,
        #[prost(string, tag = "2")]
        pub resource_object_id: String,
        #[prost(enumeration = "LookupPermissionship", tag = "3")]
        pub permissionship: i32,
        #[prost(message, optional, tag = "4")]
        pub partial_caveat_info: Option<PartialCaveatInfo>,
        #[prost(message, optional, tag = "5")]
        pub after_result_cursor: Option<Cursor>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct LookupSubjectsRequest {
        #[prost(message, optional, tag = "1")]
        pub consistency: Option<Consistency>,
        #[prost(message, optional, tag = "2")]
        pub resource: Option<ObjectReference>,
        #[prost(string, tag = "3")]
        pub permission: String,
        #[prost(string, tag = "4")]
        pub subject_object_type: String,
        #[prost(string, tag = "5")]
        pub optional_subject_relation: String,
        #[prost(message, optional, tag = "6")]
        pub context: Option<::prost_types::Struct>,
        #[prost(uint32, tag = "7")]
        pub optional_concrete_limit: u32,
        #[prost(message, optional, tag = "8")]
        pub optional_cursor: Option<Cursor>,
        #[prost(enumeration = "LookupSubjectsRequestWildcardOption", tag = "9")]
        pub wildcard_option: i32,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct LookupSubjectsResponse {
        #[prost(message, optional, tag = "1")]
        pub looked_up_at: Option<ZedToken>,
        #[prost(message, optional, tag = "2")]
        pub subject: Option<ResolvedSubject>,
        #[prost(string, repeated, tag = "3")]
        pub excluded_subjects: Vec<String>,
        #[prost(message, optional, tag = "4")]
        pub after_result_cursor: Option<Cursor>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ResolvedSubject {
        #[prost(string, tag = "1")]
        pub subject_object_id: String,
        #[prost(enumeration = "LookupPermissionship", tag = "2")]
        pub permissionship: i32,
        #[prost(message, optional, tag = "3")]
        pub partial_caveat_info: Option<PartialCaveatInfo>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Cursor {
        #[prost(string, tag = "1")]
        pub token: String,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum LookupPermissionship {
        Unspecified = 0,
        HasPermission = 1,
        ConditionalPermission = 2,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum LookupSubjectsRequestWildcardOption {
        Unspecified = 0,
        IncludeWildcards = 1,
        ExcludeWildcards = 2,
    }

    /// Schema service client
    pub mod schema_service_client {
        use tonic::codegen::*;

        #[derive(Debug, Clone)]
        pub struct SchemaServiceClient<T> {
            inner: tonic::client::Grpc<T>,
        }

        impl SchemaServiceClient<tonic::transport::Channel> {
            pub fn new(channel: tonic::transport::Channel) -> Self {
                let inner = tonic::client::Grpc::new(channel);
                Self { inner }
            }
        }

        impl<T> SchemaServiceClient<T>
        where
            T: tonic::client::GrpcService<tonic::body::BoxBody>,
            T::Error: Into<StdError>,
            T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
            <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
        {
            pub async fn read_schema(
                &mut self,
                request: impl tonic::IntoRequest<super::ReadSchemaRequest>,
            ) -> std::result::Result<tonic::Response<super::ReadSchemaResponse>, tonic::Status>
            {
                self.inner.ready().await.map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
                let codec = tonic::codec::ProstCodec::default();
                let path = http::uri::PathAndQuery::from_static(
                    "/authzed.api.v1.SchemaService/ReadSchema",
                );
                self.inner.unary(request.into_request(), path, codec).await
            }

            pub async fn write_schema(
                &mut self,
                request: impl tonic::IntoRequest<super::WriteSchemaRequest>,
            ) -> std::result::Result<tonic::Response<super::WriteSchemaResponse>, tonic::Status>
            {
                self.inner.ready().await.map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
                let codec = tonic::codec::ProstCodec::default();
                let path = http::uri::PathAndQuery::from_static(
                    "/authzed.api.v1.SchemaService/WriteSchema",
                );
                self.inner.unary(request.into_request(), path, codec).await
            }
        }
    }

    /// Permissions service client
    pub mod permissions_service_client {
        use tonic::codegen::*;

        #[derive(Debug, Clone)]
        pub struct PermissionsServiceClient<T> {
            inner: tonic::client::Grpc<T>,
        }

        impl PermissionsServiceClient<tonic::transport::Channel> {
            pub fn new(channel: tonic::transport::Channel) -> Self {
                let inner = tonic::client::Grpc::new(channel);
                Self { inner }
            }
        }

        impl<T> PermissionsServiceClient<T>
        where
            T: tonic::client::GrpcService<tonic::body::BoxBody>,
            T::Error: Into<StdError>,
            T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
            <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
        {
            pub async fn check_permission(
                &mut self,
                request: impl tonic::IntoRequest<super::CheckPermissionRequest>,
            ) -> std::result::Result<tonic::Response<super::CheckPermissionResponse>, tonic::Status>
            {
                self.inner.ready().await.map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
                let codec = tonic::codec::ProstCodec::default();
                let path = http::uri::PathAndQuery::from_static(
                    "/authzed.api.v1.PermissionsService/CheckPermission",
                );
                self.inner.unary(request.into_request(), path, codec).await
            }

            pub async fn write_relationships(
                &mut self,
                request: impl tonic::IntoRequest<super::WriteRelationshipsRequest>,
            ) -> std::result::Result<
                tonic::Response<super::WriteRelationshipsResponse>,
                tonic::Status,
            > {
                self.inner.ready().await.map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
                let codec = tonic::codec::ProstCodec::default();
                let path = http::uri::PathAndQuery::from_static(
                    "/authzed.api.v1.PermissionsService/WriteRelationships",
                );
                self.inner.unary(request.into_request(), path, codec).await
            }

            pub async fn lookup_resources(
                &mut self,
                request: impl tonic::IntoRequest<super::LookupResourcesRequest>,
            ) -> std::result::Result<
                tonic::Response<tonic::Streaming<super::LookupResourcesResponse>>,
                tonic::Status,
            > {
                self.inner.ready().await.map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
                let codec = tonic::codec::ProstCodec::default();
                let path = http::uri::PathAndQuery::from_static(
                    "/authzed.api.v1.PermissionsService/LookupResources",
                );
                self.inner
                    .server_streaming(request.into_request(), path, codec)
                    .await
            }

            pub async fn lookup_subjects(
                &mut self,
                request: impl tonic::IntoRequest<super::LookupSubjectsRequest>,
            ) -> std::result::Result<
                tonic::Response<tonic::Streaming<super::LookupSubjectsResponse>>,
                tonic::Status,
            > {
                self.inner.ready().await.map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
                let codec = tonic::codec::ProstCodec::default();
                let path = http::uri::PathAndQuery::from_static(
                    "/authzed.api.v1.PermissionsService/LookupSubjects",
                );
                self.inner
                    .server_streaming(request.into_request(), path, codec)
                    .await
            }

            pub async fn read_relationships(
                &mut self,
                request: impl tonic::IntoRequest<super::ReadRelationshipsRequest>,
            ) -> std::result::Result<
                tonic::Response<tonic::Streaming<super::ReadRelationshipsResponse>>,
                tonic::Status,
            > {
                self.inner.ready().await.map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
                let codec = tonic::codec::ProstCodec::default();
                let path = http::uri::PathAndQuery::from_static(
                    "/authzed.api.v1.PermissionsService/ReadRelationships",
                );
                self.inner
                    .server_streaming(request.into_request(), path, codec)
                    .await
            }
        }
    }
}
