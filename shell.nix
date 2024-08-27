let
  rust-overlay = (import (builtins.fetchTarball "https://github.com/oxalica/rust-overlay/archive/master.tar.gz"));
  pkgs = import <nixpkgs> { overlays = [ rust-overlay ]; };
  rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
in
with pkgs;
mkShell {
  packages = [
    lld
    clang
    rust-toolchain
  ];
  buildInputs = [
    openssl
  ];
  # envs
  LD_LIBRARY_PATH = lib.makeLibraryPath [ openssl ];
}
