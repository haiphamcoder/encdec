# Multi-stage Dockerfile for encdec
# Stage 1: Build environment
FROM rust:1.75-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy manifest files
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY tests ./tests

# Build the application
RUN cargo build --release

# Stage 2: Runtime environment
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false encdec

# Copy binary from builder stage
COPY --from=builder /app/target/release/encdec /usr/local/bin/encdec

# Set permissions
RUN chmod +x /usr/local/bin/encdec

# Switch to non-root user
USER encdec

# Set working directory
WORKDIR /app

# Expose port (if needed for future web interface)
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["encdec"]

# Default command
CMD ["--help"]
