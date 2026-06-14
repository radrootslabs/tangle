{
  description = "tangle development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-darwin"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      mkPkgs = system: import nixpkgs { inherit system; };
      mkScript =
        pkgs: name: text:
        pkgs.writeShellApplication {
          inherit name text;
          runtimeInputs = [
            pkgs.cargo-nextest
            pkgs.cargo-llvm-cov
            pkgs.llvmPackages.llvm
          ];
        };
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = mkPkgs system;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.cargo-nextest
              pkgs.cargo-llvm-cov
              pkgs.llvmPackages.llvm
            ];
          };
        }
      );

      apps = forAllSystems (
        system:
        let
          pkgs = mkPkgs system;
          check = mkScript pkgs "tangle-check" ''
            cargo fmt --all -- --check
            cargo test -p tangle --test source_comments
            cargo test -p tangle --test unsafe_code
            cargo check --workspace --all-targets
            cargo clippy --workspace --all-targets -- -D warnings
          '';
          test = mkScript pkgs "tangle-test" ''
            cargo test --workspace
            cargo nextest run --workspace
          '';
          coverage = mkScript pkgs "tangle-coverage" ''
            if ! cargo llvm-cov --version >/dev/null 2>&1; then
              printf '%s\n' 'cargo llvm-cov is required'
              exit 1
            fi
            LLVM_COV="$(command -v llvm-cov)"
            LLVM_PROFDATA="$(command -v llvm-profdata)"
            export LLVM_COV
            export LLVM_PROFDATA
            cargo llvm-cov clean --workspace
            cargo llvm-cov --workspace --all-targets --show-missing-lines --fail-under-lines 100 --fail-uncovered-lines 0
          '';
          ci = mkScript pkgs "tangle-ci" ''
            cargo fmt --all -- --check
            cargo test -p tangle --test source_comments
            cargo test -p tangle --test unsafe_code
            cargo check --workspace --all-targets
            cargo clippy --workspace --all-targets -- -D warnings
            cargo test --workspace
          '';
          releaseAcceptance = mkScript pkgs "tangle-release-acceptance" ''
            cargo fmt --all -- --check
            cargo test -p tangle --test source_comments
            cargo test -p tangle --test unsafe_code
            cargo check --workspace --all-targets
            cargo clippy --workspace --all-targets -- -D warnings
            cargo test --workspace
            cargo test -p tangle_runtime --test base_relay_v2
            cargo test -p tangle_groups
            cargo test -p tangle_store_pocket
            cargo test -p tangle_bench
            cargo run -p tangle_bench --bin tangle-benchmark-report
          '';
        in
        {
          check = {
            type = "app";
            program = "${check}/bin/tangle-check";
          };
          test = {
            type = "app";
            program = "${test}/bin/tangle-test";
          };
          coverage = {
            type = "app";
            program = "${coverage}/bin/tangle-coverage";
          };
          ci = {
            type = "app";
            program = "${ci}/bin/tangle-ci";
          };
          "release-acceptance" = {
            type = "app";
            program = "${releaseAcceptance}/bin/tangle-release-acceptance";
          };
        }
      );
    };
}
