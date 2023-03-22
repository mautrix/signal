with import <nixpkgs> { };
let
in
mkShell rec {
  buildInputs = [
    clang
    cmake
    gnumake
    protobuf
    rust-cbindgen
    rustup

    go_1_19

    pre-commit
  ];

  LIBCLANG_PATH = "${pkgs.llvmPackages_11.libclang.lib}/lib";
}
