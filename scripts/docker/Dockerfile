# Compile Clementine
FROM rust:1.85.0
WORKDIR /clementine
COPY . .
RUN cargo +1.85.0 build --release --bin clementine-core

FROM debian:bookworm-slim
RUN \
  apt-get update \
  && apt -y install gettext-base libssl-dev wget \
  && apt clean \
  && apt install -y --no-install-recommends ca-certificates \
  && update-ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=0 /target/release/clementine-core /clementine-core

# Set up Clementine
ENTRYPOINT [ "/clementine-core" ]
EXPOSE 17000