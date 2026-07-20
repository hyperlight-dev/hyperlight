{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.nixpkgs-mozilla.url = "github:mozilla/nixpkgs-mozilla/master";
  outputs = { self, nixpkgs, nixpkgs-mozilla, ... } @ inputs:
    rec {
      overlays.fix-rust = self: super: {
        # Work around the nixpkgs-mozilla equivalent of
        # https://github.com/NixOS/nixpkgs/issues/278508 and an
        # incompatibility between nixpkgs-mozilla and makeRustPlatform
        rustChannelOf = args: let
          orig = super.rustChannelOf args;
          patchRustPkg = pkg: (pkg.overrideAttrs (oA: {
            buildCommand = (builtins.replaceStrings
              [ "rustc,rustdoc" "librustc_driver-*.so" ]
              [ "rustc,rustdoc,clippy-driver,cargo-clippy,miri,cargo-miri" "librustc_driver-*.{so,dylib}" ]
              oA.buildCommand) + (let
                wrapperPath = self.path + "/pkgs/build-support/bintools-wrapper/ld-wrapper.sh";
                baseOut = self.clangStdenv.cc.bintools.out;
                getStdenvAttrs = drv: (drv.overrideAttrs (oA: {
                  passthru.origAttrs = oA;
                })).origAttrs;
                baseEnv = (getStdenvAttrs self.clangStdenv.cc.bintools).env;
                baseSubstitutedWrapper = self.replaceVars wrapperPath
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
                ldlld="$out/lib/rustlib/${self.clangStdenv.targetPlatform.config}/bin/gcc-ld/ld.lld";
                if [ -e "$ldlld" ]; then
                  export prog="$(readlink -f "$ldlld")"
                  rm "$ldlld"
                  substitute ${baseSubstitutedWrapper} "$ldlld" --subst-var "out" --subst-var "prog"
                  chmod +x "$ldlld"
                fi
              '');
            passthru = (oA.passthru or {}) // {
              toolchainVersionAttrs = args;
            };
          })) // {
            targetPlatforms = [ "aarch64-linux" "x86_64-linux" "aarch64-darwin" ];
            badTargetPlatforms = [ ];
          };
          overrideRustPkg = pkg: self.lib.makeOverridable (origArgs:
            patchRustPkg (pkg.override origArgs)
          ) {};
        in builtins.mapAttrs (_: overrideRustPkg) orig;
      };
      gcroots =
        let gcrootForShell = pkg: pkg // derivation (pkg.drvAttrs // {
              origArgs = pkg.drvAttrs.args;
              # assume the builder is bash for now (it always is for
              # stdenv, which is the only thing that we will encounter
              # in this flake).
              args = [ "-c" "declare > $out" ];
            });
        in {
          shells.x86_64-linux.default = gcrootForShell devShells.x86_64-linux.default;
          shells.aarch64-linux.default = gcrootForShell devShells.aarch64-linux.default;
        };
      devShells = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed (system: {
        default = let pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import (nixpkgs-mozilla + "/rust-overlay.nix")) overlays.fix-rust ];
        }; in with pkgs; let
          customisedRustChannelOf = args:
            lib.flip builtins.mapAttrs (rustChannelOf args) (_: pkg: pkg.override {
              targets = [
                "x86_64-unknown-linux-gnu"
                "x86_64-pc-windows-msvc" "x86_64-unknown-none"
                "wasm32-wasip1" "wasm32-wasip2" "wasm32-unknown-unknown"
                "aarch64-unknown-none" "aarch64-apple-darwin"
              ];
              extensions = [ "rust-src" ] ++ (if args.channel == "nightly" then [ "miri-preview" ] else []);
            });

          # Hyperlight needs a variety of toolchains, since we use Nightly
          # for rustfmt and old toolchains to verify MSRV
          toolchains = lib.mapAttrs (_: customisedRustChannelOf) {
            stable = {
              date = "2026-03-05";
              channel = "stable";
              sha256 = "sha256-qqF33vNuAdU5vua96VKVIwuc43j4EFeEXbjQ6+l4mO4=";
            };
            nightly = {
              date = "2026-02-27";
              channel = "nightly";
              sha256 = "sha256-5twI9QsrPl0ryOZ4POGYAivSeI08jgmWnv0wVvzbjcE=";
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

          manifests = {
            "Cargo.toml" = {
              outputHashes = {
                "piet-0.8.0" = "sha256-yHF0axor+uaGC0RYhw1JmjvFLVTYZkTx1XzDtuN2KIk=";
              };
            };
            "src/tests/rust_guests/Cargo.toml" = {
            };
          };
          manifestDeps = lib.mapAttrsToList (manifest: importArguments:
            let lockPath = builtins.replaceStrings [ "toml" ] [ "lock" ] manifest; in
            let lockFile = ./${lockPath}; in
            rust-platform.importCargoLock ({
              inherit lockFile;
            } // importArguments)) manifests;
          # when building a guest with cargo-hyperlight, or when
          # building a miri sysroot for the main workspace, we need to
          # include any crates.io dependencies of the standard library
          # (e.g. rustc-literal-escaper)
          stdlibLocks = lib.mapAttrsToList (_: toolchain:
            "${toolchain.rust}/lib/rustlib/src/rust/library/Cargo.lock"
          ) toolchains;
          stdlibDeps = builtins.map (lockFile:
            rust-platform.importCargoLock { inherit lockFile; }) stdlibLocks;
          deps = pkgs.symlinkJoin {
            name = "cargo-deps";
            paths = stdlibDeps ++ manifestDeps;
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
          materialiseDeps = let
            sortedManifests = lib.lists.sort (p: q: p > q) (lib.attrNames manifests);
            matchClause = path: ''  */${path}) root="''${manifest%${path}}" ;;'';
            matchClauses = lib.strings.concatStringsSep "\n"
              (builtins.map matchClause sortedManifests);
          in ''
            base_cargo() {
              PATH="$base/bin:$PATH" "$base/bin/cargo" "$@"
            }

            manifest=$(base_cargo locate-project --message-format plain --workspace)
            case "$manifest" in
              ${matchClauses}
            esac
            if [ -f ''${root}/flake.nix ]; then

              sed -i '/# vendor dependency configuration generated by nix/{N;N;N;N;N;d;}' $root/.cargo/config.toml
              cat >>$root/.cargo/config.toml <<EOF
            # vendor dependency configuration generated by nix
            [source.crates-io]
            replace-with = "vendored-sources"

            [source.vendored-sources]
            directory = "${deps}"
            EOF

              sed -i '/# vendor dependency configuration generated by nix/{N;d;}' $root/.git/info/exclude
              printf "# vendor dependency configuration generated by nix\n%s\n" "/.cargo" >> $root/.git/info/exclude
            fi

            # libgit2-sys copies a vendored git2 into the target/
            # directory somewhere. In certain, rare, cases,
            # libgit2-sys is rebuilt in the same incremental dep
            # directory as it was before, and then this copy fails,
            # because the files, copied from the nix store, already
            # exist and do not have w permission. Hack around this
            # issue by making any existing libgit2-sys vendored git2
            # files writable before a build can be run
            find "$(base_cargo metadata --format-version 1 | jq -r '.target_directory')" -path '*/build/libgit2-sys-*/out/include' -print0 | xargs -r -0 chmod u+w -R
          '';

          # Hyperlight scripts use cargo in a bunch of ways that don't
          # make sense for Nix cargo, including the `rustup +toolchain`
          # syntax to use a specific toolchain and `cargo install`, so we
          # build wrappers for rustc and cargo that enable this.  The
          # scripts also use `rustup toolchain install` in some cases, in
          # order to work in CI, so we provide a fake rustup that does
          # nothing as well.
          rustup-like-wrapper = name: pkgs.writeShellScriptBin name
            (let
              clause = name: toolchain: ''
                +${name}) base="${toolchain.rust}"; shift 1; ;;
                +${name}-${toolchain.rust.toolchainVersionAttrs.date}) base="${toolchain.rust}"; shift 1; ;;
              '';
              clauses = lib.strings.concatStringsSep "\n"
                (lib.mapAttrsToList clause toolchains);
            in ''
              base="${toolchains.stable.rust}"
              ${materialiseDeps}
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

          cargo-hyperlight = buildRustPackageClang rec {
            pname = "cargo-hyperlight";
            version = "0.1.14-pre";
            src = fetchFromGitHub {
              owner = "hyperlight-dev";
              repo = "cargo-hyperlight";
              rev = "33384c0c4ed9dea4f0525943809fc444c41a27df";
              hash = "sha256-A2/SNHCdPPzW86bd00IucZEyZHZWDqXVKPccZULcEu0=";
            };
            cargoHash = "sha256-ImWnNzXvDKokML0BDyyjifrZ1bnG6ymXt5vAMRIpwUY==";
            doCheck = false;
          };
        in (buildRustPackageClang (mkDerivationAttrs: {
          pname = "hyperlight";
          version = "0.0.0";
          src = lib.cleanSource ./.;
          cargoDeps = deps;

          nativeBuildInputs = [
            azure-cli
            just
            dotnet-sdk_9
            llvmPackages_18.llvm
            gh
            lld
            pkg-config
            ffmpeg
            mkvtoolnix
            wasm-tools
            jq
            jaq
            gdb
            zlib
            cargo-hyperlight
            typos
            flatbuffers
            cargo-fuzz
          ] ++ (if system == "x86_64-linux" || system == "aarch64-linux"
                then [ valgrind ]
                else []);
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
        })).overrideAttrs(oA: {
          hardeningDisable = [ "all" ];
        });
      });
    };
}
