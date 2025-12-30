# Separ - Multi-Tenant Authorization Platform

**Separ** (سپر - meaning "shield" in Persian) is a highly secure, multi-tenant authorization platform built on SpiceDB and Google Zanzibar principles.

## 🎯 Features

- **Multi-Tenant Architecture**: Support for 1000+ applications and services
- **SpiceDB Integration**: Google Zanzibar-style relationship-based access control
- **OAuth/SSO Support**: Microsoft Entra ID, Google, Okta, and custom providers
- **Federated Sync**: Sync customer IdPs with central authorization
- **PostgreSQL Backend**: Reliable metadata and audit storage
- **Rust Implementation**: Memory-safe, high-performance, low-latency

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            CUSTOMER COMPANIES                                    │
└─────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
│   Company A          │  │   Company B          │  │   Company C          │
│   ┌────────────┐     │  │   ┌────────────┐     │  │   ┌────────────┐     │
│   │ Their IdP  │     │  │   │ Their IdP  │     │  │   │ Their IdP  │     │
│   │ (Okta)     │     │  │   │ (Entra ID) │     │  │   │ (Google)   │     │
│   └─────┬──────┘     │  │   └─────┬──────┘     │  │   └─────┬──────┘     │
│         │            │  │         │            │  │         │            │
│   ┌─────▼──────┐     │  │   ┌─────▼──────┐     │  │   ┌─────▼──────┐     │
│   │ Their Apps │     │  │   │ Their Apps │     │  │   │ Their Apps │     │
│   │ - App 1    │     │  │   │ - App X    │     │  │   │ - App Y    │     │
│   │ - App 2    │     │  │   │ - App Z    │     │  │   │ - App W    │     │
│   └─────┬──────┘     │  │   └─────┬──────┘     │  │   └─────┬──────┘     │
└─────────┼────────────┘  └─────────┼────────────┘  └─────────┼────────────┘
          │                         │                         │
          │ SCIM/Webhook            │ SCIM/Webhook            │ SCIM/Webhook
          │ Sync Events             │ Sync Events             │ Sync Events
          ▼                         ▼                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         SEPAR AUTHORIZATION PLATFORM                             │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │                          Sync Gateway Layer                                 │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │ │
│  │  │ SCIM API    │  │ Webhook     │  │ Event       │  │ Batch       │       │ │
│  │  │ Endpoints   │  │ Receivers   │  │ Processors  │  │ Importers   │       │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘       │ │
│  └────────────────────────────────────┬───────────────────────────────────────┘ │
│                                       │                                          │
│  ┌────────────────────────────────────▼───────────────────────────────────────┐ │
│  │                      Central Authorization Service                          │ │
│  │  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐ │ │
│  │  │ Tenant Manager      │  │ Permission Checker  │  │ Relationship        │ │ │
│  │  │ - Company Registry  │  │ - Check API         │  │ Manager             │ │ │
│  │  │ - App Registry      │  │ - LookupSubjects    │  │ - Write Tuples      │ │ │
│  │  │ - User Mapping      │  │ - LookupResources   │  │ - Delete Tuples     │ │ │
│  │  └─────────────────────┘  └─────────────────────┘  └─────────────────────┘ │ │
│  └────────────────────────────────────┬───────────────────────────────────────┘ │
│                                       │                                          │
│  ┌────────────────────────────────────▼───────────────────────────────────────┐ │
│  │                            Data Layer                                       │ │
│  │  ┌─────────────────────────────────┐  ┌─────────────────────────────────┐  │ │
│  │  │         SpiceDB Cluster         │  │          PostgreSQL             │  │ │
│  │  │  - Relationships                │  │  - Tenant Metadata              │  │ │
│  │  │  - Permissions                  │  │  - Audit Logs                   │  │ │
│  │  │  - Schema                       │  │  - OAuth Configs                │  │ │
│  │  │  - Caveats                      │  │  - Sync State                   │  │ │
│  │  └─────────────────────────────────┘  └─────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 📦 Crates

| Crate | Description |
|-------|-------------|
| `separ-core` | Core types, traits, and domain models |
| `separ-spicedb` | SpiceDB client and schema management |
| `separ-db` | PostgreSQL models and migrations |
| `separ-sync` | Tenant sync service (SCIM, webhooks) |
| `separ-oauth` | OAuth/OIDC provider integration |
| `separ-api` | API handlers and middleware |
| `separ-server` | Main server binary |

## 🚀 Quick Start

### Prerequisites

- Rust 1.75+
- Docker & Docker Compose
- PostgreSQL 15+
- SpiceDB

### Development Setup

```bash
# Start infrastructure (PostgreSQL + SpiceDB)
docker-compose up -d

# Run database migrations
docker exec -i separ-postgres psql -U separ -d separ < crates/separ-db/migrations/20250101000001_initial_schema.sql

# Start the server
cargo run -p separ-server
```

The server will be available at `http://localhost:8080`.

### Environment Variables

Configuration is managed via `config/default.toml`. Key settings:

```env
DATABASE_URL=postgres://separ:separ@localhost:5433/separ
SPICEDB_ENDPOINT=http://localhost:50051
SPICEDB_TOKEN=supersecretkey
JWT_SECRET=your-jwt-secret
```

> **Note**: Docker Compose maps PostgreSQL to port **5433** to avoid conflicts with local installations.

## 🔐 SpiceDB Schema

The platform uses a hierarchical schema:

```zed
definition platform {
    relation admin: user
}

definition tenant {
    relation platform: platform
    relation owner: user
    relation admin: user
    relation member: user
    
    permission manage = owner + admin + platform->admin
    permission view = manage + member
}

definition workspace {
    relation tenant: tenant
    relation owner: user
    relation admin: user
    relation member: user
    
    permission manage = owner + admin + tenant->admin
    permission view = manage + member
}

definition application {
    relation workspace: workspace
    relation owner: user
    relation admin: user
    relation user: user
    
    permission manage = owner + admin + workspace->admin
    permission use = manage + user + workspace->member
}

definition resource {
    relation application: application
    relation owner: user
    relation editor: user
    relation viewer: user
    
    permission manage = owner + application->admin
    permission edit = manage + editor
    permission view = edit + viewer + application->user
}
```

## 📡 API Endpoints

### Health
- `GET /health` - Health check

### Tenant Management
- `POST /api/v1/tenants` - Create tenant
- `GET /api/v1/tenants` - List tenants
- `GET /api/v1/tenants/{id}` - Get tenant
- `PUT /api/v1/tenants/{id}` - Update tenant
- `DELETE /api/v1/tenants/{id}` - Delete tenant

### Authorization
- `POST /api/v1/authz/check` - Check permission
- `POST /api/v1/authz/relationships` - Write relationship
- `DELETE /api/v1/authz/relationships` - Delete relationships
- `POST /api/v1/authz/lookup/subjects` - Lookup subjects with permission
- `POST /api/v1/authz/lookup/resources` - Lookup resources user can access

### OAuth/SSO (Framework)
- `GET /api/v1/oauth/{provider}/login` - Initiate OAuth flow
- `GET /api/v1/oauth/{provider}/callback` - OAuth callback

### Sync (SCIM - Framework)
- `POST /api/v1/sync/webhook` - Handle identity provider webhooks

## 🧪 Quick Test

```bash
# Create a tenant
curl -X POST http://localhost:8080/api/v1/tenants \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Corp", "slug": "acme"}'

# Add owner permission
curl -X POST http://localhost:8080/api/v1/authz/relationships \
  -H "Content-Type: application/json" \
  -d '{"resource_type": "tenant", "resource_id": "<TENANT_ID>", "relation": "owner", "subject_type": "user", "subject_id": "alice"}'

# Check permission
curl -X POST http://localhost:8080/api/v1/authz/check \
  -H "Content-Type: application/json" \
  -d '{"resource_type": "tenant", "resource_id": "<TENANT_ID>", "permission": "manage", "subject_type": "user", "subject_id": "alice"}'
```

## 📄 License

Apache-2.0

