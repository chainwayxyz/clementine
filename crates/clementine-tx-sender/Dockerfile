FROM rust:1.88.0 as builder
WORKDIR /clementine
COPY . .
RUN cargo build --release --package clementine-tx-sender --bin clementine-tx-sender --features "citrea json-rpc"

FROM debian:trixie-slim

RUN useradd -u 1000 appuser

WORKDIR /app

COPY --from=builder --chown=appuser:appuser /clementine/target/release/clementine-tx-sender /app/clementine-tx-sender

USER appuser

CMD ["/app/clementine-tx-sender"]
