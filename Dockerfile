# Build stage
FROM rust:1.96-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/dillshare

# Copy the locked dependency graph for reproducible application builds.
COPY Cargo.toml Cargo.lock ./

# Create a dummy project to build dependencies first (helps caching layers)
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src/ target/release/deps/s3_share* target/release/deps/dillshare*

# Copy the actual source files
COPY src/ ./src/

# Compile the actual production binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime certificates and OpenSSL for AWS S3 communication
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from builder stage
COPY --from=builder /usr/src/dillshare/target/release/dillshare /app/dillshare

# Expose port
EXPOSE 8000

# Set execution command
CMD ["/app/dillshare"]
