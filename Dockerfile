FROM rust:1.78.0-bookworm
WORKDIR /clementine
COPY . .
RUN apt update && apt -y upgrade && apt -y install libclang-dev pkg-config protobuf-compiler curl cmake git

RUN SKIP_GUEST_BUILD=1 cargo build --release --bin server
