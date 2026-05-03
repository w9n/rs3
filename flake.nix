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
            just
            mdbook
            openssl
            pkg-config
            rust-analyzer
            rustc
            rustfmt
            sccache
            taplo
          ];

          RUST_BACKTRACE = "1";
          RUSTFLAGS = "-D warnings";
        };
      });
    };
}
