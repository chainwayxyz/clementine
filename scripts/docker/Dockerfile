# Set up OS
FROM rust:1.85.0

# Compile Clementine
COPY . .
WORKDIR /clementine
RUN cargo +1.85.0 build --release --bin clementine-core

# Set up Clementine
ENTRYPOINT [ "/target/release/clementine-core" ]
EXPOSE 17000
