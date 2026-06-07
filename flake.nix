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
      coverageEnvironment = ''
        LLVM_COV="$(command -v llvm-cov)"
        LLVM_PROFDATA="$(command -v llvm-profdata)"
        export LLVM_COV
        export LLVM_PROFDATA
      '';
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
            scripts/check.sh
          '';
          test = mkScript pkgs "tangle-test" ''
            scripts/test.sh
            cargo nextest run --workspace
          '';
          coverage = mkScript pkgs "tangle-coverage" ''
            ${coverageEnvironment}
            scripts/coverage.sh
          '';
          ci = mkScript pkgs "tangle-ci" ''
            ${coverageEnvironment}
            scripts/ci.sh
          '';
          releaseAcceptance = mkScript pkgs "tangle-release-acceptance" ''
            scripts/release_acceptance.sh
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
