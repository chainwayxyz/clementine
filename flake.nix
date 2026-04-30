{
  description = "Reproducible build for Clementine binaries";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

    crane.url = "github:ipetkov/crane";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, crane, rust-overlay, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.stable."1.88.0".minimal.override {
          extensions = [ "rust-src" "clippy" "rustfmt" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            let
              rel = pkgs.lib.removePrefix "${toString ./.}/" (toString path);
            in
              (craneLib.filterCargoSources path type)
              || pkgs.lib.hasPrefix "bridge-circuit-host/bin-files/" rel
              || pkgs.lib.hasPrefix "circuits-lib/src/bridge_circuit/bin/" rel
              || pkgs.lib.hasPrefix "circuits-lib/test_data/" rel
              || pkgs.lib.hasPrefix "core/src/database/migrations/" rel
              || rel == "core/src/database/schema.sql"
              || rel == "core/src/database/pgmq.sql"
              || pkgs.lib.hasPrefix "core/src/rpc/" rel
              || pkgs.lib.hasPrefix "core/src/test/data/" rel
              || pkgs.lib.hasPrefix "risc0-circuits/elfs/" rel
              || rel == "README.md"
              || rel == "scripts/Bridge.json";
        };

        recursionZkr = pkgs.fetchurl {
          url = "https://risc0-artifacts.s3.us-west-2.amazonaws.com/zkr/744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849.zip";
          hash = "sha256-dEuZnwo1s8hnUzEcfvsqAFS+IXJwlc8QWvbufT9NiEk=";
        };

        commonArgs = {
          inherit src;
          pname = "clementine";
          version =
            let
              cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
            in
              cargoToml.workspace.package.version;

          strictDeps = true;

          nativeBuildInputs = with pkgs; [
            pkg-config
            cmake
            clang
            llvmPackages.libclang
            perl
            rustPlatform.bindgenHook
          ];

          buildInputs = with pkgs; [
            openssl
            zlib
            bzip2
            lz4
          ];

          # Reproducibility
          SOURCE_DATE_EPOCH = "0";
          LC_ALL = "C";
          TZ = "UTC";
          ZERO_AR_DATE = "1";
          CARGO_INCREMENTAL = "0";
          VERGEN_IDEMPOTENT = "1";
          # Avoid host-dependent jemalloc rtree sizing on machines with 5-level paging.
          JEMALLOC_SYS_WITH_LG_VADDR = "48";
          RECURSION_SRC_PATH = "${recursionZkr}";
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          # GCC 14 promoted -Wint-conversion to an error by default, which breaks
          # the bundled jemalloc in tikv-jemalloc-sys 0.6.0 (its strerror_r call
          # predates the XSI-compliant prototype). Demote it back to a warning;
          # doesn't affect codegen, so reproducibility is unchanged.
          NIX_CFLAGS_COMPILE = "-Wno-int-conversion";

          RUSTFLAGS = builtins.concatStringsSep " " [
            "--remap-path-prefix=${src}=/build/source"
            "--remap-path-prefix=/build=/build"
          ];

          cargoExtraArgs = "--locked --package clementine-core";

          preBuild = ''
            export HOME="$NIX_BUILD_TOP"
            export XDG_CACHE_HOME="$NIX_BUILD_TOP/.cache"
            mkdir -p "$XDG_CACHE_HOME"
            export RUSTFLAGS="$RUSTFLAGS --remap-path-prefix=$(pwd)=/build/source"
          '';
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        clementine = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          doCheck = false;

          postInstall = ''
            strip $out/bin/clementine-core
            strip $out/bin/clementine-cli
          '';

        });
      in
      {
        packages = {
          inherit clementine;
          default = self.packages.${system}.clementine;
        };

        devShells.default = craneLib.devShell {
          packages = with pkgs; [
            cargo-nextest
            rust-analyzer
          ];

          VERGEN_IDEMPOTENT = "1";
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        };
      }
    );
}
