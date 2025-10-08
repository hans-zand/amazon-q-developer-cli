FROM rust:1.87.0-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build --release --bin chat_cli

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -u 1000 -m quser \
    && mkdir -p /home/quser/.aws/amazonq

COPY --from=0 /app/target/release/chat_cli /usr/local/bin/q

USER quser

ENTRYPOINT ["q"]
