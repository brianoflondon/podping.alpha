##: Build stage
FROM rust:latest AS builder

USER root

RUN apt-get update && apt-get install -y apt-utils sqlite3 openssl git ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/podping.alpha
COPY . /opt/podping.alpha
WORKDIR /opt/podping.alpha/gossip-listener
RUN cargo build --release

##: Bundle stage
FROM debian:trixie-slim AS runner

USER root

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

RUN chown -R 1000:1000 /opt
RUN mkdir -p /data && chown -R 1000:1000 /data

USER 1000
RUN mkdir /opt/gossip-listener

WORKDIR /opt/gossip-listener
COPY --from=builder /opt/podping.alpha/gossip-listener/target/release/gossip-listener .

ENTRYPOINT ["/opt/gossip-listener/gossip-listener"]
