FROM rust:1.88.0 as builder
ARG TX_SENDER_FEATURES=citrea,standalone,json-rpc
WORKDIR /clementine
COPY . .
RUN cargo build --release --package clementine-tx-sender --bin clementine-tx-sender --features "${TX_SENDER_FEATURES}"

FROM debian:trixie-slim

RUN useradd -u 1000 appuser

WORKDIR /app

COPY --from=builder --chown=appuser:appuser /clementine/target/release/clementine-tx-sender /app/clementine-tx-sender

USER appuser

CMD ["/app/clementine-tx-sender"]