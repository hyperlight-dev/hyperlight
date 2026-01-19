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
              buildCommand = (builtins.replaceStrings
                [ "rustc,rustdoc" ]
                [ "rustc,rustdoc,clippy-driver,cargo-clippy" ]
                oA.buildCommand) + (let
                  wrapperPath = pkgs.path + "/pkgs/build-support/bintools-wrapper/ld-wrapper.sh";
                  baseOut = pkgs.clangStdenv.cc.bintools.out;
                  getStdenvAttrs = drv: (drv.overrideAttrs (oA: {
                    passthru.origAttrs = oA;
                  })).origAttrs;
                  baseEnv = (getStdenvAttrs pkgs.clangStdenv.cc.bintools).env;
                  baseSubstitutedWrapper = pkgs.replaceVars wrapperPath
                    {
                      inherit (baseEnv)
                        shell coreutils_bin suffixSalt mktemp rm;
                      use_response_file_by_default = "0";
                      prog = null;
                      out = null;
                    };
                in ''
                  # work around a bug in the overlay
                  ${oA.postInstall}

                  # copy over helper scripts that the wrapper needs
                  (cd "${baseOut}"; find . -type f \( -name '*.sh' -or -name '*.bash' \) -print0) | while read -d $'\0' script; do
                    mkdir -p "$out/$(dirname "$script")"
                    substitute "${baseOut}/$script" "$out/$script" --replace-quiet "${baseOut}" "$out"
                  done

                  # TODO: Work out how to make this work with cross builds
                  ldlld="$out/lib/rustlib/${pkgs.clangStdenv.targetPlatform.config}/bin/gcc-ld/ld.lld";
                  if [ -e "$ldlld" ]; then
                    export prog="$(readlink -f "$ldlld")"
                    rm "$ldlld"
                    substitute ${baseSubstitutedWrapper} "$ldlld" --subst-var "out" --subst-var "prog"
                    chmod +x "$ldlld"
                  fi
                '');
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
              date = "2025-12-11";
              channel = "stable";
              sha256 = "sha256-sqSWJDUxc+zaz1nBWMAJKTAGBuGWP25GCftIOlCEAtA=";
            };
            nightly = {
              date = "2026-01-19";
              channel = "nightly";
              sha256 = "sha256-Ye65U/qzilPLte800N5oxFOY96shgG8bST8dbrF6Qh0=";
            };
            "1.89" = {
              date = "2025-08-07";
              channel = "stable";
              sha256 = "sha256-+9FmLhAOezBZCOziO0Qct1NOrfpjNsXxc/8I0c7BdKE=";
            };
          };

          rust-platform = makeRustPlatform {
            cargo = toolchains.stable.rust;
            rustc = toolchains.stable.rust;
          };

          # Script snippet, used in the cargo/rustc wrappers below,
          # which creates a number of .cargo/config.toml files in
          # order to allow using Nix-fetched dependencies (this must
          # be done for the guests, as well as for the main
          # workspace).  Ideally, we would just use environment
          # variables or the --config option to Cargo, but
          # unfortunately that tends not to play well with subcommands
          # like `cargo clippy` and `cargo hyperlight` (see
          # https://github.com/rust-lang/cargo/issues/11031).
          materialiseDeps = deps: let
            sortedNames =  lib.lists.reverseList (builtins.attrNames deps);
            matchClause = path: ''  */${path}) root="''${manifest%${path}}" ;;'';
            matchClauses = lib.strings.concatStringsSep "\n"
              (builtins.map matchClause sortedNames);
            makeClause = manifest: vendor: let
              dir = builtins.dirOf manifest;
              gitExclude = builtins.toString (/. + "${dir}/.cargo");
            in ''
              mkdir -p $root/${dir}/.cargo
              cat >$root/${dir}/.cargo/config.toml <<EOF
              [source.crates-io]
              replace-with = "vendored-sources"

              [source.vendored-sources]
              directory = "${vendor}"
              EOF
              printf "# vendor dependency configuration generated by nix\n%s\n" "${gitExclude}" >> $root/.git/info/exclude
            '';
            makeClauses = lib.strings.concatStringsSep "\n"
              (lib.mapAttrsToList makeClause deps);
          in ''
            manifest=$(''${base}/bin/cargo locate-project --message-format plain --workspace)
            case "$manifest" in
              ${matchClauses}
            esac
            if [ -f ''${root}/flake.nix ]; then
              sed -i '/# vendor dependency configuration generated by nix/{N;d;}' $root/.git/info/exclude
              ${makeClauses}
            fi
          '';

          # Hyperlight scripts use cargo in a bunch of ways that don't
          # make sense for Nix cargo, including the `rustup +toolchain`
          # syntax to use a specific toolchain and `cargo install`, so we
          # build wrappers for rustc and cargo that enable this.  The
          # scripts also use `rustup toolchain install` in some cases, in
          # order to work in CI, so we provide a fake rustup that does
          # nothing as well.
          rustup-like-wrapper = name: deps: pkgs.writeShellScriptBin name
            (let
              clause = name: toolchain:
                "+${name}) base=\"${toolchain.rust}\"; shift 1; ;;";
              clauses = lib.strings.concatStringsSep "\n"
                (lib.mapAttrsToList clause toolchains);
            in ''
              base="${toolchains.stable.rust}"
              ${materialiseDeps deps}
              case "$1" in
                ${clauses}
                install) exit 0; ;;
              esac
              export PATH="$base/bin:$PATH"
              exec "$base/bin/${name}" "$@"
            '');
          fake-rustup = deps: pkgs.symlinkJoin {
            name = "fake-rustup";
            paths = [
              (pkgs.writeShellScriptBin "rustup" "")
              (rustup-like-wrapper "rustc" deps)
              (rustup-like-wrapper "cargo" deps)
            ];
          };

          buildRustPackageClang = rust-platform.buildRustPackage.override { stdenv = clangStdenv; };

          cargo-hyperlight = buildRustPackageClang rec {
            pname = "cargo-hyperlight";
            version = "0.1.5";
            src = fetchFromGitHub {
              owner = "hyperlight-dev";
              repo = "cargo-hyperlight";
              tag = "v${version}";
              hash = "sha256-xq4/c69N0wG/I8WOYVloo0J0JqoSIKiWWtECdSKrsxo=";
            };
            cargoHash = "sha256-muiMVrK1TydQiMitihfo7xYidqUIIQ+Hw3BIeo5rLFw=";
          };
          # when building a guest with cargo-hyperlight, we need to
          # include any crates.io dependencies of the standard library
          # (e.g. rustc-literal-escaper)
          stdlibLocks = lib.mapAttrsToList (_: toolchain:
            "${toolchain.rust}/lib/rustlib/src/rust/library/Cargo.lock"
          ) toolchains;
          stdlibDeps = builtins.map (lockFile:
            rust-platform.importCargoLock { inherit lockFile; }) stdlibLocks;
          withStdlibLock = lockFile:
            pkgs.symlinkJoin {
              name = "cargo-deps";
              paths = stdlibDeps ++ [
                (rust-platform.importCargoLock {
                  inherit lockFile;
                })
              ];
            };
          deps = finalRootVendor: {
            "Cargo.toml" = finalRootVendor;
            "src/tests/rust_guests/dummyguest/Cargo.toml" = withStdlibLock ./src/tests/rust_guests/dummyguest/Cargo.lock;
            "src/tests/rust_guests/simpleguest/Cargo.toml" = withStdlibLock ./src/tests/rust_guests/simpleguest/Cargo.lock;
            "src/tests/rust_guests/witguest/Cargo.toml" = withStdlibLock ./src/tests/rust_guests/witguest/Cargo.lock;
          };
        in (buildRustPackageClang (mkDerivationAttrs: {
          pname = "hyperlight";
          version = "0.0.0";
          src = lib.cleanSource ./.;
          cargoLock.lockFile = ./Cargo.lock;

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
            zlib
            cargo-hyperlight
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
            export PATH="${fake-rustup (deps mkDerivationAttrs.cargoDeps)}/bin:$PATH"
          '';
        })).overrideAttrs(oA: {
          hardeningDisable = [ "all" ];
        });
    };
}
