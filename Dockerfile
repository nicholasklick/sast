# Dockerfile for SAST Builder

FROM rust:1.82-slim-bookworm AS builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy all project files
COPY . .

# Build release binary (skip benches and tests to speed up build)
RUN cargo build --release --bins

# The binary will be at /build/target/release/kodecd-sast
