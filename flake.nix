{
  description = "Clementine - BitVM based trust-minimized two-way peg";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ] (system:
      let
        overlays = [ (import rust-overlay) (self: super: {
          risc0-sys = builtins.trace "Patching risc0-sys" (super.risc0-sys.overrideAttrs (oldAttrs: {
            buildPhase = ''
              runHook preBuild
              echo "fn main() {}" > build.rs
              runHook postBuild
            '';
          }));
        }) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Use Rust 1.88 as specified in rust-toolchain.toml
        rustToolchain = pkgs.rust-bin.stable."1.88.0".default.override {
          extensions = [ "rust-src" "rustfmt" "clippy" ];
        };

        # Common build inputs needed for Clementine
        nativeBuildInputs = with pkgs; [
          pkg-config
          protobuf
        ];

        buildInputs = with pkgs; [
          openssl
        ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
          pkgs.darwin.apple_sdk.frameworks.Security
          pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
          pkgs.darwin.apple_sdk.frameworks.CoreServices
          pkgs.darwin.apple_sdk.frameworks.Metal
          pkgs.libiconv
        ];

        # Build function for creating clementine-cli binaries
        buildClementineCli = { features ? [], pnameSuffix ? "" }:
          let
            cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
            version = cargoToml.workspace.package.version;
          in
          pkgs.rustPlatform.buildRustPackage {
            pname = "clementine-cli${pnameSuffix}";
            inherit version buildInputs;
            nativeBuildInputs = nativeBuildInputs ++ [ rustToolchain ];

            src = ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
              outputHashes = {
                "bitcoin-script-0.4.0" = "sha256-FJrKYvRQTebxddavboP91Z+mT0krKqiAJ+QxEOZyYJc=";
                "bitcoin-script-stack-0.0.1" = "sha256-8yOpPtxJs3J/9sYd42EurHxbCgbOWrg22KO7kM87Bs8=";
                "bitcoin-scriptexec-0.0.0" = "sha256-HeCSWjy0mD3X2ewxlt80Pw+/+GT02UmRnlnnPmo1xpE=";
                "bitcoincore-rpc-0.18.0" = "sha256-QYtvsul7MUFm/HUDAqiwxM4HoFyOcn31ERR8eu62LB4=";
                "bitcoincore-rpc-json-0.18.0" = "sha256-QYtvsul7MUFm/HUDAqiwxM4HoFyOcn31ERR8eu62LB4=";
                "bitvm-0.1.0" = "sha256-We3HFl/S/eA+yW/r/XRoSpCyjwYwaR9z2/oQMmZDIYU=";
                "citrea-e2e-0.1.0" = "sha256-fCWnDxxWWPInukS7oMgIpyAnkKRxayM2OHKpOCXJWGI=";
                "jmt-0.11.0" = "sha256-v7adz1va6DKQU0shOobbda5Ivutfre/dg08fLmi0nvI=";
                "script-macro-0.4.0" = "sha256-FJrKYvRQTebxddavboP91Z+mT0krKqiAJ+QxEOZyYJc=";
                "secp256k1-0.31.0" = "sha256-jTdc0423m9lS4NunLCMwLM6AdkerSc/ovTSyO91KXa0=";
                "secp256k1-sys-0.11.0" = "sha256-jTdc0423m9lS4NunLCMwLM6AdkerSc/ovTSyO91KXa0=";
                "sov-keys-0.7.3-rc.5" = "sha256-xVW1LeMXnTkBQiqLW1JrvYDspLGQdI6HBd69EyQ8TOs=";
                "sov-rollup-interface-0.7.3-rc.5" = "sha256-xVW1LeMXnTkBQiqLW1JrvYDspLGQdI6HBd69EyQ8TOs=";
              };
            };

            buildAndTestSubdir = "core";

            buildFeatures = if features != [] then features else [];

            # Common environment variables for reproducible builds
            CARGO_BUILD_INCREMENTAL = "false";
            SOURCE_DATE_EPOCH = "1";
            RUST_MIN_STACK = "33554432";
            RUSTFLAGS = "-C debuginfo=0 -C strip=symbols";

            # Skip RISC0 circuit builds - they're pre-compiled
            RISC0_SKIP_BUILD = "1";
            RISC0_SKIP_BUILD_KERNELS = "1";

            # SQLx offline mode (uses sqlx-data.json if present)
            SQLX_OFFLINE = "true";

            # Install phase to add checksums
            postInstall = ''
              # Generate SHA256 checksum
              cd $out/bin
              sha256sum clementine-cli > clementine-cli.sha256
            '';

            # Tests require external dependencies (Bitcoin node, PostgreSQL)
            doCheck = false;

            meta = with pkgs.lib; {
              description = "Clementine Bridge CLI - ${if features != [] then "with " + (pkgs.lib.concatStringsSep ", " features) else "without automation"}";
              homepage = "https://citrea.xyz";
              license = licenses.gpl3;
              maintainers = [ ];
              mainProgram = "clementine-cli";
            };
          };

      in
      {
        packages = {
          # Default package - without automation
          default = self.packages.${system}.clementine-cli;

          # Build without automation feature
          clementine-cli = buildClementineCli {
            features = [];
            pnameSuffix = "";
          };

          # Build with automation feature
          clementine-cli-automation = buildClementineCli {
            features = [ "automation" ];
            pnameSuffix = "-automation";
          };
        };

        # Development shell
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = nativeBuildInputs ++ [ rustToolchain ];
          inherit buildInputs;

          shellHook = ''
            echo "======================================"
            echo "Clementine Development Environment"
            echo "======================================"
            echo "Rust version: $(rustc --version)"
            echo "Cargo version: $(cargo --version)"
            echo ""
            echo "Build Commands:"
            echo "  cargo build --release                          # Build without automation"
            echo "  cargo build --release --features automation    # Build with automation"
            echo ""
            echo "Nix Build Commands:"
            echo "  nix build .#clementine-cli                     # Nix build without automation"
            echo "  nix build .#clementine-cli-automation          # Nix build with automation"
            echo "  nix build .#clementine-cli-x86_64-linux        # Platform-specific build"
            echo ""
            echo "Environment:"
            echo "  RUST_MIN_STACK: $RUST_MIN_STACK"
            echo "  RISC0_SKIP_BUILD: $RISC0_SKIP_BUILD"
            echo "======================================"
          '';

          RUST_BACKTRACE = "1";
          RUST_LOG = "info";
          RUST_MIN_STACK = "33554432";
          RISC0_SKIP_BUILD = "1";
        };

        # Formatter for nix files
        formatter = pkgs.nixpkgs-fmt;
      }
    );
}
