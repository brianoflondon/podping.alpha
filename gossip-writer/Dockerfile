##: Build stage
FROM rust:latest AS builder

USER root

RUN apt-get update && apt-get install -y apt-utils sqlite3 openssl capnproto libzmq3-dev git ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/podping.alpha
COPY . /opt/podping.alpha
WORKDIR /opt/podping.alpha/gossip-writer
RUN cargo build --release

##: Bundle stage
# Runner: use debian:trixie-slim to match the glibc from rust:latest
FROM debian:trixie-slim AS runner

USER root

RUN apt-get update && apt-get install -y apt-utils sqlite3 openssl libc6 ca-certificates && rm -rf /var/lib/apt/lists/*

RUN chown -R 1000:1000 /opt
RUN mkdir -p /data/gossip && chown -R 1000:1000 /data

USER 1000
RUN mkdir /opt/gossip-writer

WORKDIR /opt/gossip-writer
COPY --from=builder /opt/podping.alpha/gossip-writer/target/release/gossip-writer .

ENTRYPOINT ["/opt/gossip-writer/gossip-writer"]
