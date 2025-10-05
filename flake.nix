{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.nixpkgs-mozilla.url = "github:mozilla/nixpkgs-mozilla/master";
  outputs = { self, nixpkgs, nixpkgs-mozilla, ... } @ inputs:
    {
      devShells.x86_64-linux.default =
        let pkgs = import nixpkgs {
              system = "x86_64-linux";
              overlays = [ (import (nixpkgs-mozilla + "/rust-overlay.nix")) ];
            };
        in with pkgs; let
          # Work around the nixpkgs-mozilla equivalent of
          # https://github.com/NixOS/nixpkgs/issues/278508 and an
          # incompatibility between nixpkgs-mozilla and makeRustPlatform
          rustChannelOf = args: let
            orig = pkgs.rustChannelOf args;
            patchRustPkg = pkg: (pkg.overrideAttrs (oA: {
              buildCommand = builtins.replaceStrings
                [ "rustc,rustdoc" ]
                [ "rustc,rustdoc,clippy-driver,cargo-clippy" ]
                oA.buildCommand;
            })) // {
              targetPlatforms = [ "x86_64-linux" ];
              badTargetPlatforms = [ ];
            };
            overrideRustPkg = pkg: lib.makeOverridable (origArgs:
              patchRustPkg (pkg.override origArgs)
            ) {};
          in builtins.mapAttrs (_: overrideRustPkg) orig;

          customisedRustChannelOf = args:
            lib.flip builtins.mapAttrs (rustChannelOf args) (_: pkg: pkg.override {
              targets = [
                "x86_64-unknown-linux-gnu"
                "x86_64-pc-windows-msvc" "x86_64-unknown-none"
                "wasm32-wasip1" "wasm32-wasip2" "wasm32-unknown-unknown"
              ];
              extensions = [ "rust-src" ];
            });

          # Hyperlight needs a variety of toolchains, since we use Nightly
          # for rustfmt and old toolchains to verify MSRV
          toolchains = lib.mapAttrs (_: customisedRustChannelOf) {
            stable = {
              date = "2025-09-18";
              channel = "stable";
              sha256 = "sha256-SJwZ8g0zF2WrKDVmHrVG3pD2RGoQeo24MEXnNx5FyuI=";
            };
            nightly = {
              date = "2025-07-29";
              channel = "nightly";
              sha256 = "sha256-6D2b7glWC3jpbIGCq6Ta59lGCKN9sTexhgixH4Y7Nng=";
            };
            "1.88" = {
              date = "2025-06-26";
              channel = "stable";
              sha256 = "sha256-Qxt8XAuaUR2OMdKbN4u8dBJOhSHxS+uS06Wl9+flVEk=";
            };
          };

          rust-platform = makeRustPlatform {
            cargo = toolchains.stable.rust;
            rustc = toolchains.stable.rust;
          };

          # Hyperlight scripts use cargo in a bunch of ways that don't
          # make sense for Nix cargo, including the `rustup +toolchain`
          # syntax to use a specific toolchain and `cargo install`, so we
          # build wrappers for rustc and cargo that enable this.  The
          # scripts also use `rustup toolchain install` in some cases, in
          # order to work in CI, so we provide a fake rustup that does
          # nothing as well.
          rustup-like-wrapper = name: pkgs.writeShellScriptBin name
            (let
              clause = name: toolchain:
                "+${name}) base=\"${toolchain.rust}\"; shift 1; ;;";
              clauses = lib.strings.concatStringsSep "\n"
                (lib.mapAttrsToList clause toolchains);
            in ''
          base="${toolchains.stable.rust}"
          case "$1" in
            ${clauses}
            install) exit 0; ;;
          esac
          export PATH="$base/bin:$PATH"
          exec "$base/bin/${name}" "$@"
        '');
          fake-rustup = pkgs.symlinkJoin {
            name = "fake-rustup";
            paths = [
              (pkgs.writeShellScriptBin "rustup" "")
              (rustup-like-wrapper "rustc")
              (rustup-like-wrapper "cargo")
            ];
          };

          buildRustPackageClang = rust-platform.buildRustPackage.override { stdenv = clangStdenv; };
        in (buildRustPackageClang rec {
          pname = "hyperlight";
          version = "0.0.0";
          src = lib.cleanSource ./.;
          cargoHash = "sha256-hoeJEBdxaoyLlhQQ4X4Wk5X1QVtQ7RRQYaxkiGg8rWA=";

          nativeBuildInputs = [
            azure-cli
            just
            dotnet-sdk_9
            llvmPackages_18.llvm
            gh
            lld
            valgrind
            pkg-config
            ffmpeg
            mkvtoolnix
            wasm-tools
            jq
            jaq
            gdb
          ];
          buildInputs = [
            pango
            cairo
            openssl
          ];

          auditable = false;

          LIBCLANG_PATH = "${pkgs.llvmPackages_18.libclang.lib}/lib";
          # Use unwrapped clang for compiling guests
          HYPERLIGHT_GUEST_clang = "${clang.cc}/bin/clang";

          RUST_NIGHTLY = "${toolchains.nightly.rust}";
          # Set this through shellHook rather than nativeBuildInputs to be
          # really sure that it overrides the real cargo.
          postHook = ''
            export PATH="${fake-rustup}/bin:$PATH"
          '';
        }).overrideAttrs(oA: {
          hardeningDisable = [ "all" ];
        });
    };
}
