# Hyperlight: Copilot instructions

Hyperlight is a lightweight Virtual Machine Manager (VMM) embedded within
applications to run untrusted code inside micro virtual machines with very low
latency and minimal overhead. Mostly Rust, with a few C files. `just` is the
task runner and is already installed.

## Build & test commands

Most recipes take an optional profile argument that defaults to debug. Append
`release` for a release build (e.g. `just build release`). You rarely need to
run both profiles for one change.

* `just build`: build the host and libraries.
* `just guests`: build the guest library and test guests (both profiles).
* `just test`: run all tests.
* `just fmt-apply`: format and apply fixes.
* `just clippy`: lint.
* `just clippyw`: cross-compile clippy for Windows. Run it on Linux when you
  edit Windows-specific code.
* `just test-like-ci`: full CI-equivalent run. Slow.

**Run `just guests` before `just test` when you've changed guest code.**
Tests use the prebuilt guest binaries, so rebuild them to pick up guest
changes. Not needed if you only touched host code.

## Definition of done

Before considering a change complete:
1. `just fmt-apply`.
2. `just clippy` passes.
3. `just test` passes. Run `just guests` first if you changed guest code.
   Tests are slow. Run the release profile too only when the change
   specifically warrants it.
4. New code has tests and rustdoc following existing patterns.
5. Docs updated if behavior documented in `README.md` or `docs/` changed.

## Code conventions

* Follow idiomatic Rust and match the surrounding code style.
* Do not add new crates or dependencies without discussing first.
* Maintain the existing structure and organization. Do not refactor beyond
  what the task requires.
* Do not commit large binary files.

## Writing

Applies to all writing: code comments, docstrings, docs, commit messages, PR
descriptions. Conciseness is the top rule. The rest serves it.

Be concise.
* Use the fewest words that make the point. No filler.
* Say each point once. Never restate the same idea in other words.
* Cut anything the reader can see in the code or context.
* Short plain sentences, one clause each. Common everyday words.

Mechanics.
* No em dashes or hyphens as prose connectors. Use periods or commas.
* No semicolons. Use periods.
* Prefer `*` over `-` for bullets.

Say what IS, not what changed or what it isn't.
* Write what the thing IS and WHY. The reader has no knowledge of the diff
  that introduced it. Git history is where to learn what changed.
* Avoid contrastive language ("no longer", "previously", "instead of",
  "used to", "now", "just").
* Avoid diff narration ("moved from", "extracted from", "X drops here").
* No PR or review references unless permanently relevant.

Comment only when needed.
* Skip comments the code or a descriptive name already makes clear.
* A docstring that restates the function or test name is noise. Drop it.
* Keep comments that explain a non-obvious mechanism or a real WHY.
* Default 1-2 sentences for a docstring, 1 short line for an inline comment.
  If it does not fit, the code probably needs to be simpler.

## Git & commits

* Sign commits (`commit.gpgsign=true`) and add `--signoff` for DCO.
* Keep commits small, focused, and in logical order.
* Rebase your branch on `main`. No merge commits.
* Label PRs per `docs/github-labels.md`.

## Reviewing code

When reviewing a diff (your own or a PR), weight these for Hyperlight:
* Correctness: edge cases, error paths, broken invariants.
* Security boundary: the VMM/guest split, paging, and syscall surface. Treat
  all guest input as untrusted and watch for sandbox-escape risk.
* Unsafe: every `unsafe` block needs an accurate `// SAFETY:` comment and
  every `unsafe fn` a `# Safety` rustdoc precondition. Check soundness: the
  block must uphold the invariants it claims. A fn is `unsafe fn` only when a
  caller must uphold a precondition for memory safety. Flag both missing and
  gratuitous `unsafe`.
* Necessity: challenge each added abstraction, field, variant, parameter, branch.
  If nothing exercises it, say so, and prefer the simpler form.
* Design: judge the seams and boundaries the change draws (module/crate
  splits, what gets serialized, public vs private, where state lives). Prefer
  fitting an existing pattern over a parallel second way.
* Performance: review every change for cost. Look for work that can be
  dropped or made cheaper, including hot-path allocations, unnecessary copies,
  lock contention, syscalls, hypercalls.
* Idioms: do not reinvent what std or an existing dependency already provides.
* Changelog: user-facing changes need a `CHANGELOG.md` entry. Internal-only
  changes do not.
* External APIs (Win32, POSIX, KVM/mshv/WHP): verify calls against the
  authoritative docs rather than from memory.

## Agent behavior

* When the user asks a question, analyze and answer only. Do not edit code
  until explicitly asked.

## Repository structure

* `src/hyperlight_common/`: code shared between host and guest.
* `src/hyperlight_guest/`: hyperlight-guest library.
* `src/hyperlight_guest_bin/`: hyperlight-guest-bin library.
* `src/hyperlight_guest_capi/`: guest C library.
* `src/hyperlight_host/`: hyperlight-host library.
* `src/hyperlight_testing/`: shared test code.
* `schema/`: flatbuffer schemas.
* `tests/`: test guest code in C and Rust.
* `dev/`: development scripts and tools.
* `fuzz/`: fuzzing tests.
* `Justfile`: build/test/run tasks.

## Troubleshooting

* **"No Hypervisor was found for Sandbox"** on Linux: check for a `kvm` or
  `mshv` device in `/dev`, and that you have rw access to it. Output the
  results of both checks for diagnostics.
