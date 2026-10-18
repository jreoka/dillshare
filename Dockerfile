# Build stage
FROM rust:1.96-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/dillshare

# Copy the locked dependency graph for reproducible application builds.
COPY Cargo.toml Cargo.lock ./

# Build the dependency graph against a dummy entrypoint so the expensive layer
# is cached independently of application source changes.
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --locked
RUN rm -rf src target/release/deps/dillshare*

# Copy the actual source files
COPY src/ ./src/

# Compile the actual production binary
RUN cargo build --release --locked

# Runtime stage
FROM debian:bookworm-slim

# Runtime certificates and OpenSSL for AWS S3 communication.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin dillshare

WORKDIR /app

# Copy the compiled binary from builder stage
COPY --from=builder /usr/src/dillshare/target/release/dillshare /app/dillshare

# Run unprivileged: the server only binds an unprivileged port and needs no
# writable filesystem, so it never has a reason to run as root.
USER 10001

# Expose port
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/app/dillshare", "--healthcheck"]

# Set execution command
CMD ["/app/dillshare"]
