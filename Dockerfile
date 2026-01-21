# Build stage
FROM rust:1.85-bookworm AS builder

WORKDIR /app

# Install dependencies for TLS and protobuf
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build release binary with TLS support
RUN cargo build --release --package separ-server

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies including CA certificates for TLS
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/separ /app/separ

# Copy config
COPY config/default.toml /app/config/default.toml

# Copy migrations
COPY crates/separ-db/migrations /app/migrations

# Create non-root user with UID 1000 to match Kubernetes securityContext
RUN groupadd -g 1000 separ && \
    useradd -u 1000 -g 1000 -s /bin/false separ && \
    chown -R separ:separ /app
USER 1000

# Expose port
EXPOSE 8080

# Environment variables for production
ENV RUST_LOG=info
ENV RUST_BACKTRACE=0

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run server
ENTRYPOINT ["/app/separ"]
