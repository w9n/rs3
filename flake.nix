{
  description = "rs3 S3-compatible backup gateway";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f (import nixpkgs {
            inherit system;
          })
        );
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            cargo-audit
            cargo-deny
            cargo-nextest
            clippy
            docker-client
            kubernetes-helm
            just
            kind
            kopia
            kubectl
            mdbook
            openssl
            pkg-config
            python3Packages.mkdocs
            python3Packages.mkdocs-material
            rust-analyzer
            rustc
            rustfmt
            sccache
            taplo
            velero
          ];

          RUST_BACKTRACE = "1";
          RUSTFLAGS = "-D warnings";
        };
      });
    };
}
