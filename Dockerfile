# PledgeRecon — Official Docker Image (Goal 84)
# Multi-stage build for minimal final image size.
FROM rust:1.85-bookworm AS builder

WORKDIR /build
COPY . .

# Build with release optimizations.
RUN cargo build --release --bin pledgerecon

# Final stage — minimal runtime image.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/pledgerecon /usr/local/bin/pledgerecon

# Cache directory for advisory database.
ENV PLEDGERECON_CACHE_DIR=/cache
RUN mkdir -p /cache
VOLUME ["/cache"]

# Scan the /repo directory by default.
WORKDIR /repo
ENTRYPOINT ["pledgerecon"]
CMD ["scan", "."]
