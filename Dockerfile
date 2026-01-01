# Build stage
FROM rust:1.84-bookworm AS builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build release binary
RUN cargo build --release --package separ-server

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/separ-server /app/separ

# Copy config
COPY config/default.toml /app/config/default.toml

# Copy migrations
COPY crates/separ-db/migrations /app/migrations

# Create non-root user
RUN useradd -r -s /bin/false separ && \
    chown -R separ:separ /app
USER separ

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health/live || exit 1

# Run server
ENTRYPOINT ["/app/separ"]
