# Set up OS
FROM ubuntu:22.04
RUN apt update && \
    apt -y install curl gcc cpp cmake clang llvm && \
    apt -y autoremove && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# Set up Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain=1.79.0

# Compile Clementine
COPY . .
WORKDIR /clementine
RUN RISC0_SKIP_BUILD=1 /root/.cargo/bin/cargo +1.79.0 build --release --bin server

# Set up Clementine
ENTRYPOINT [ "/target/release/server" ]
EXPOSE 17000
