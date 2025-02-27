FROM risczero/risc0-guest-builder:r0.1.81.0 AS build

WORKDIR /src

# Copy the entire project structure
COPY risc0-circuits/work-only risc0-circuits/work-only

# Might be heavy in the future, but for now it's fine
COPY circuits-lib circuits-lib 
COPY Cargo.toml Cargo.toml

# Set compile-time environment variables
ENV CARGO_MANIFEST_PATH="risc0-circuits/work-only/guest/Cargo.toml"
ENV RUSTFLAGS="-C passes=loweratomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings"
ENV CARGO_TARGET_DIR="risc0-circuits/work-only/guest/target"
ENV CC_riscv32im_risc0_zkvm_elf="/root/.local/share/cargo-risczero/cpp/bin/riscv32-unknown-elf-gcc"
ENV CFLAGS_riscv32im_risc0_zkvm_elf="-march=rv32im -nostdlib"

# Set network environment variable
ARG BITCOIN_NETWORK=testnet4
ENV BITCOIN_NETWORK=${BITCOIN_NETWORK}

# Only run the build once with the environment variable set
RUN echo "Building for network: ${BITCOIN_NETWORK}" && \
    cargo +risc0 fetch --target riscv32im-risc0-zkvm-elf --manifest-path ${CARGO_MANIFEST_PATH} && \
    cargo +risc0 build --release --target riscv32im-risc0-zkvm-elf --manifest-path ${CARGO_MANIFEST_PATH}

FROM scratch AS export
ARG BITCOIN_NETWORK
COPY --from=build /src/risc0-circuits/work-only/guest/target/riscv32im-risc0-zkvm-elf/release ../target/riscv-guest/riscv32im-risc0-zkvm-elf/docker/work-only-guest
COPY --from=build /src/risc0-circuits/work-only/guest/target/riscv32im-risc0-zkvm-elf/release/work-only-guest risc0-circuits/elfs/${BITCOIN_NETWORK}-work-only-guest