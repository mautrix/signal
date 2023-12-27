{
  description = "mautrix-signal development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    (flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; };
      in {
        devShells.default = pkgs.mkShell {
          LIBCLANG_PATH = "${pkgs.llvmPackages_11.libclang.lib}/lib";

          buildInputs = with pkgs; [
            clang
            cmake
            gnumake
            protobuf
            rust-cbindgen
            rustup
            olm

            go_1_20
            go-tools
            gotools

            pre-commit
          ];
        };
      }));
}
