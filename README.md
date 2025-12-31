# Separ - Multi-Tenant Authorization Platform

<div align="center">

![Separ Logo](https://img.shields.io/badge/Separ-🛡️-blue?style=for-the-badge)

**سپر** (Separ - "Shield" in Persian)

A highly secure, multi-tenant authorization platform built on SpiceDB and Google Zanzibar principles.

[![CI](https://github.com/Angelerator/Separ/actions/workflows/ci.yml/badge.svg)](https://github.com/Angelerator/Separ/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)

[Features](#-features) • [Quick Start](#-quick-start) • [Architecture](#-architecture) • [API Reference](#-api-endpoints) • [Contributing](#-contributing)

</div>

---

## 🎯 Features

| Feature | Description |
|---------|-------------|
| **Multi-Tenant Architecture** | Support for 1000+ applications and services with complete isolation |
| **SpiceDB Integration** | Google Zanzibar-style relationship-based access control (ReBAC) |
| **OAuth/SSO Support** | Microsoft Entra ID, Google, Okta, and custom OIDC providers |
| **Federated Identity Sync** | Sync customer IdPs with central authorization via SCIM/webhooks |
| **PostgreSQL Backend** | Reliable metadata storage with full audit logging |
| **Rust Implementation** | Memory-safe, high-performance, low-latency authorization checks |
| **Modular Identity Providers** | Pluggable provider architecture for Azure AD, Okta, Google, LDAP |
| **Proxy Mode** | PostgreSQL wire protocol proxy for transparent authorization |

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
| `separ-identity` | Modular identity provider implementations |
| `separ-proxy` | PostgreSQL wire protocol proxy |
| `separ-api` | API handlers and middleware |
| `separ-server` | Main server binary |

## 🚀 Quick Start

### Prerequisites

- Rust 1.75+
- Docker & Docker Compose
- PostgreSQL 15+
- SpiceDB

### Option 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/Angelerator/Separ.git
cd Separ

# Start all services
docker-compose up -d

# Check health
curl http://localhost:8080/health
```

### Option 2: Development Setup

```bash
# Start infrastructure only
docker-compose up -d postgres spicedb

# Run database migrations
docker exec -i separ-postgres psql -U separ -d separ < crates/separ-db/migrations/20250101000001_initial_schema.sql

# Build and run the server
cargo run -p separ-server
```

The server will be available at `http://localhost:8080`.

### Configuration

Configuration is managed via `config/default.toml`:

```toml
[server]
host = "0.0.0.0"
port = 8080

[database]
url = "postgres://separ:separ@localhost:5433/separ"

[spicedb]
endpoint = "http://localhost:50051"
token = "supersecretkey"

[jwt]
secret = "your-jwt-secret-here"
```

> **Note**: Docker Compose maps PostgreSQL to port **5433** to avoid conflicts with local installations.

> ⚠️ **Security Warning**: The default credentials are for **development only**. In production:
> - Generate a strong SpiceDB preshared key (min 32 characters)
> - Use strong PostgreSQL credentials  
> - Set a secure `JWT_SECRET`
> - Enable TLS for all connections

## 🔐 SpiceDB Schema

The platform uses a hierarchical permission model:

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

### Health & Metrics

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |

### Tenant Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/tenants` | Create tenant |
| `GET` | `/api/v1/tenants` | List tenants |
| `GET` | `/api/v1/tenants/{id}` | Get tenant |
| `PUT` | `/api/v1/tenants/{id}` | Update tenant |
| `DELETE` | `/api/v1/tenants/{id}` | Delete tenant |

### Authorization

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/authz/check` | Check permission |
| `GET` | `/api/v1/authz/relationships` | Browse relationships (requires `resource_type`) |
| `POST` | `/api/v1/authz/relationships` | Write relationship |
| `DELETE` | `/api/v1/authz/relationships` | Delete relationships |
| `POST` | `/api/v1/authz/lookup/subjects` | Lookup subjects with permission |
| `POST` | `/api/v1/authz/lookup/resources` | Lookup accessible resources |

### OAuth/SSO

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/oauth/{provider}/login` | Initiate OAuth flow |
| `GET` | `/api/v1/oauth/{provider}/callback` | OAuth callback |

### Identity Sync

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/sync/webhook` | Handle IdP webhooks |
| `POST` | `/api/v1/identity/providers` | Register identity provider |
| `GET` | `/api/v1/identity/providers` | List identity providers |

## 🧪 Testing

### Run All Tests

```bash
# Unit tests
cargo test --workspace

# With integration tests (requires Docker services)
docker-compose up -d
cargo test --workspace -- --include-ignored
```

### Quick API Test

```bash
# Create a tenant
curl -X POST http://localhost:8080/api/v1/tenants \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Corp", "slug": "acme"}'

# Add owner permission
curl -X POST http://localhost:8080/api/v1/authz/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "resource_type": "tenant",
    "resource_id": "<TENANT_ID>",
    "relation": "owner",
    "subject_type": "user",
    "subject_id": "alice"
  }'

# Check permission
curl -X POST http://localhost:8080/api/v1/authz/check \
  -H "Content-Type: application/json" \
  -d '{
    "resource_type": "tenant",
    "resource_id": "<TENANT_ID>",
    "permission": "manage",
    "subject_type": "user",
    "subject_id": "alice"
  }'

# Browse relationships
curl "http://localhost:8080/api/v1/authz/relationships?resource_type=tenant" | jq .
```

## 🔍 Using Zed CLI

AuthZed's official CLI for managing SpiceDB:

```bash
# Install
brew install authzed/tap/zed

# Configure context
zed context set separ "localhost:50051" "supersecretkey" --insecure

# View schema
zed schema read --insecure

# Read relationships
zed relationship read tenant --insecure

# Check permission
zed permission check tenant:<TENANT_ID> manage user:alice --insecure
```

## 🚢 Deployment

### Docker

```bash
# Build image
docker build -t separ:latest .

# Run with environment variables
docker run -d \
  -p 8080:8080 \
  -e DATABASE_URL="postgres://user:pass@host/db" \
  -e SPICEDB_ENDPOINT="http://spicedb:50051" \
  -e SPICEDB_TOKEN="your-secure-token" \
  separ:latest
```

### Releasing

Releases are automated via GitHub Actions. To create a release:

```bash
# Tag a release
git tag v1.0.0
git push origin v1.0.0
```

This triggers:
- Cross-platform builds (Linux x86_64/musl, macOS x86_64/arm64)
- Docker multi-arch image push to GHCR
- GitHub Release with artifacts and checksums

## 🛡️ Security

- **Authentication**: JWT, API Keys, Service Tokens, mTLS
- **Authorization**: SpiceDB-based relationship authorization
- **Audit Logging**: Complete audit trail in PostgreSQL
- **Rate Limiting**: Configurable per-endpoint limits
- **TLS**: Full TLS support for all connections

### Reporting Vulnerabilities

Please report security vulnerabilities via GitHub Security Advisories.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

### Development Guidelines

- Run `cargo fmt` before committing
- Ensure `cargo clippy` passes without warnings
- Add tests for new functionality
- Update documentation as needed

## 📄 License

Apache-2.0 - See [LICENSE](LICENSE) for details.

---

<div align="center">
Made with ❤️ by <a href="https://github.com/Angelerator">Angelerator</a>
</div>
