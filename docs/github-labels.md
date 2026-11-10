# GitHub labels

This guide describes the proposed scheme in
[HIP 0005](../proposals/0005-structured-labels/README.md).
The HIP covers rationale and migration. Existing automation still uses legacy
names. Label renames and automation updates need a coordinated rollout.
Until then, use the names required by the current workflows.

## Choosing labels

Each prefix answers a different question. Combine labels to describe an issue
or PR. Area labels vary by project. Most other labels are shared across the org.

| Prefix | Meaning       | Describes                                         |
| ------ | ------------- | ------------------------------------------------- |
| `A-`   | Area          | The part of the project affected                  |
| `C-`   | Category      | The type of issue or change                       |
| `E-`   | Participation | A good first issue or a request for help          |
| `F-`   | Feature       | A feature or initiative being tracked             |
| `O-`   | Platform      | CPU architecture, operating system, or hypervisor |
| `P-`   | Priority      | Urgency or release importance                     |
| `S-`   | Status        | Workflow state or outstanding action              |

For example:

* An API bug fix gets `A-api` and `C-bug`.
* A documentation fix gets `A-docs` and `C-bug`. Documentation improvements get
  `A-docs` and `C-enhancement`.
* An MSHV bug on Linux awaiting triage gets `O-mshv`, `O-linux`, `C-bug`, and
  `S-needs-triage`.

## Categories

| Label           | Use for                                                                                            |
| --------------- | -------------------------------------------------------------------------------------------------- |
| `C-bug`         | Bug reports and fixes                                                                              |
| `C-deps`        | PRs that update dependencies or related components                                                 |
| `C-enhancement` | New features or backward-compatible improvements, including documentation and tests                |
| `C-refactor`    | Restructuring or removing code without adding functionality, including changes to user-facing APIs |
| `C-question`    | Questions or requests for information                                                              |

Before merging a PR, assign one change category: `C-bug`, `C-deps`,
`C-enhancement`, or `C-refactor`. During migration, the
[PR label check](../.github/workflows/PRLabelChecker.yml) requires exactly one
`kind/*` label.

## Areas

Area labels are optional. Add those that help identify the affected parts of
the project.

| Label                      | Use for                                                 |
| -------------------------- | ------------------------------------------------------- |
| `A-api`                    | APIs and public interfaces                              |
| `A-ci`                     | CI workflows and GitHub Actions                         |
| `A-ci-periodics`           | Failures from scheduled CI jobs                         |
| `A-ci-periodics-aarch64`   | Daily aarch64 CI failures                               |
| `A-ci-periodics-mshv-6.18` | Weekly MSHV 6.18 CI failures                            |
| `A-ci-periodics-nightly`   | Nightly Rust CI failures                                |
| `A-deps`                   | Dependencies or related components as the affected area |
| `A-docs`                   | Documentation                                           |
| `A-fuzzing`                | Fuzzing                                                 |
| `A-infra`                  | Infrastructure                                          |
| `A-perf`                   | Performance                                             |
| `A-security`               | Security                                                |
| `A-testing`                | Tests and testing infrastructure                        |

`A-deps` identifies an area. `C-deps` identifies a dependency update. A dependency
update needs `C-deps`, with an area label only when it helps describe the change.

The [CI failure notifier](../dev/notify-ci-failure.sh) creates or updates an open
issue using the first supplied label as its grouping key. The
[daily aarch64](../.github/workflows/DailyArm64.yml),
[weekly MSHV 6.18](../.github/workflows/WeeklyMshv618.yml), and
[nightly Rust](../.github/workflows/RustNightly.yml) workflows each use a dedicated
key. This keeps their failures on separate release-blocking issues, even when
they also carry the general periodic-CI label. These workflows still use
`area/ci-periodics*` names.

## Participation and features

| Label           | Use for                                         |
| --------------- | ----------------------------------------------- |
| `E-easy`        | Good first issues suitable for new contributors |
| `E-help-wanted` | Requests for help                               |
| `F-guest-cow`   | Work on guest copy-on-write support             |

`E-easy` is the only difficulty label in this scheme. There are no size labels.

## Platforms

Use platform labels when an item is specific to an architecture, host OS, or
hypervisor. Combine them where relevant.

| Label       | Use for                                  |
| ----------- | ---------------------------------------- |
| `O-x86_64`  | x86-64 processors                        |
| `O-aarch64` | 64-bit Arm processors                    |
| `O-kvm`     | Linux KVM backend                        |
| `O-mshv`    | Linux MSHV backend for Microsoft Hyper-V |
| `O-whp`     | Windows Hypervisor Platform backend      |
| `O-hvf`     | macOS Hypervisor Framework backend       |
| `O-linux`   | Linux host support                       |
| `O-windows` | Windows host support                     |
| `O-macos`   | macOS host support                       |

## Status

Status labels are composable. For example, a PR can need review and be nominated
for discussion at the next meeting.

| Label                  | Use when                                                     |
| ---------------------- | ------------------------------------------------------------ |
| `S-needs-triage`       | An item needs initial assessment                             |
| `S-needs-review`       | A PR is ready for review or re-review                        |
| `S-waiting-on-author`  | The author needs to provide information or make changes      |
| `S-needs-repro`        | A reproduction is needed to confirm a bug                    |
| `S-confirmed`          | A bug is verified or an enhancement is considered reasonable |
| `S-blocked`            | Another issue or external factor blocks progress             |
| `S-nominated`          | An item is nominated for discussion at the next meeting      |
| `S-needs-announcement` | An item should be announced in the next release              |
| `S-needs-goldens`      | A PR needs snapshot golden regeneration                      |

`S-confirmed` does not promise implementation or a timeline.
`S-needs-repro` describes what is missing. Add `S-waiting-on-author` when the
author needs to supply it. Requests for author information documented under
`lifecycle/needs-info` use `S-waiting-on-author`.

### Review readiness

Add `S-needs-review` when opening a review-ready PR, or after addressing requested
changes and re-requesting review.

The existing [`collect`](../.github/workflows/ready-for-review-label.yml) and
[`manage`](../.github/workflows/ready-for-review-manage.yml) workflows remove
`ready-for-review` automatically when any of these conditions apply:

* The PR is closed or merged.
* The PR is converted to a draft.
* The PR has two or more approvals.
* The PR has two or more change requests.

Only reviews of the current head commit count toward these thresholds.
Authors add the label. Automation handles removal. The rollout must preserve
these rules for `S-needs-review`. Until the workflows are migrated, add
`ready-for-review` to use this automation.

### Snapshot goldens

`S-needs-goldens` requests regeneration for a PR that intentionally changes the
snapshot format and bumps `GOLDENS_VERSION`. The verify job generates goldens
from the branch and checks them with the branch loader. This allows verification
before the new golden set is published.

The [PR workflow](../.github/workflows/ValidatePullRequest.yml) still checks
`regen-goldens` to select this mode. See
[snapshot versioning](snapshot-versioning.md) for the golden update process.

## Release priority

`P-release-blocker` marks issues that must be resolved before the next release.
Any open issue with the release-blocking label prevents release creation.
The [release check](../dev/check-release-blockers.sh) still queries
`release-blocker` until migration.

## Issue types and closure

Issues also use GitHub issue types. These are separate from labels:

* **bug** reports an unexpected problem or incorrect behavior.
* **design** covers design considerations or decisions.
* **enhancement** suggests a feature, improvement, or idea.

Use GitHub's closure reasons to record resolution:

* Close resolved issues as **completed**.
* Link duplicates to the original issue and close them as **not planned**.
* Explain findings that are not bugs and close them as **not planned**.
* Explain decisions not to pursue an issue and close it as **not planned**.
