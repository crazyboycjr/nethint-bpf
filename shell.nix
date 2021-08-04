{ pkgs ? import <nixpkgs>  { } }:
with pkgs;
llvmPackages_12.stdenv.mkDerivation {
  name = "clang-12-nix-shell";
  buildInputs = [
    llvmPackages_12.libllvm
    llvmPackages_12.libclang
    rustup
    libxml2
  ];

  LIBCLANG_PATH = "${llvmPackages_12.libclang.lib}/lib";
}
