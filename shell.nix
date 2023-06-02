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
	olm

    go_1_20

    pre-commit
  ];

  LIBCLANG_PATH = "${pkgs.llvmPackages_11.libclang.lib}/lib";
}
