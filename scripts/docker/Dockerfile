# Set up OS
FROM ubuntu:22.04
RUN apt update && \
    apt -y install curl gcc cpp cmake clang llvm pkg-config libssl-dev && \
    apt -y autoremove && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# Set up Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain=1.85.0

# Compile Clementine
COPY . .
WORKDIR /clementine
RUN /root/.cargo/bin/cargo +1.85.0 build --release --bin clementine-core

# Set up Clementine
ENTRYPOINT [ "/target/release/clementine-core" ]
EXPOSE 17000