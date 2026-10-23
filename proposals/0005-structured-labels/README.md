# HIP 0005 - Structured labels

## Elevator pitch

We propose a standard labeling scheme for issues and PRs on GitHub, largely
modeled after Rust’s labeling system. This will make it easier to plan meetings,
raise items for discussion, as well as make it easier to switch between
repositories.

## Status quo

Hyperlight currently uses different labeling schemes across projects. Despite
our best efforts, even the main Hyperlight project contains duplicate labels and
labels that don’t follow its primary labeling scheme. Although Hyperlight does
not use a monorepo, we still plan and coordinate development across all
repositories. Without a shared labeling vocabulary, it’s harder to coordinate
processes like triage and issue nomination.

Currently the main Hyperlight project uses the following labels prefixes:

- `area/`
- `kind/`
- `lifecycle/`
- `size/`

In addition to these, there are 10 labels that don’t follow a framework, as well
as three pairs of seemingly duplicate labels.

## What we propose to do about it

I’m proposing three changes to issue labels:

- All labels must fit within a structured labeling framework
- All repositories must follow this framework
- All labels should start with single-letter prefixes

Under the proposed scheme, `lifecycle/blocked-on-author` would be renamed to
`S-waiting-on-author` (“status: waiting on author”). For a full overview of all
labels and their proposed names, see the section on implementation details.

## Shiny future

One of the most impressive things about how the Rust language team is run is its
ability to prioritize work and get back to people quickly. We want Hyperlight to
be used more, which means the project needs to be trusted—and that people need
to trust us and our processes. The Rust language team used to have a problem
with responsiveness, but it turned that around by improving its processes. For
at least the past year, it feels like nothing pressing has gotten stuck in
limbo.

That’s not to say Hyperlight is doing poorly, but we could do better. In
particular, it would be nice if creating triage agendas and prioritizing work
items were easier. That requires organizing the existing work more effectively.
Since we do not have a monorepo, it also means creating consistency across
repositories.

I’d love it if generating the agenda for the weekly meetings were as simple as
running a script to see which issues have been nominated, whether any items have
been filed specifically for the agenda, and whether any items need attention.

## Implementation details and plan

### Categories

- **`A-` — Area:** The part of the project affected.
- **`C-` — Category:** The type of issue or change.
- **`E-` — Participation:** Difficulty, experience required, or requests for help.
- **`F-` — Feature:** A specific feature or initiative being tracked.
- **`O-` — Platform:** CPU architecture, operating system, and hypervisor.
- **`P-` — Priority:** Urgency or release importance.
- **`S-` — Status:** Workflow state, resolution, or outstanding action.

### Label conversion

| Label                         | Proposed replacement       |
| ----------------------------- | -------------------------- |
| `area/API`                    | `A-api`                    |
| `area/ci-periodics`           | `A-ci-periodics`           |
| `area/ci-periodics-aarch64`   | `A-ci-periodics-aarch64`   |
| `area/ci-periodics-mshv-6.18` | `A-ci-periodics-mshv-6.18` |
| `area/ci-periodics-nightly`   | `A-ci-periodics-nightly`   |
| `area/dependencies`           | `A-deps`                   |
| `area/documentation`          | `A-docs`                   |
| `area/fuzzing`                | `A-fuzzing`                |
| `area/infrastructure`         | `A-infra`                  |
| `area/performance`            | `A-perf`                   |
| `area/security`               | `A-security`               |
| `area/testing`                | `A-testing`                |
| `github_actions`              | `A-ci`                     |
| `good first issue`            | `E-easy`                   |
| `Guest-COW`                   | `F-guest-cow`              |
| `help-wanted`                 | `E-help-wanted`            |
| `kind/bugfix`                 | `C-bug`                    |
| `kind/dependencies`           | `C-deps`                   |
| `kind/documentation`          | `C-docs`                   |
| `kind/enhancement`            | `C-enhancement`            |
| `kind/refactor`               | `C-refactor`               |
| `lifecycle/blocked`           | `S-blocked`                |
| `lifecycle/blocked-on-author` | `S-waiting-on-author`      |
| `lifecycle/confirmed`         | `S-confirmed`              |
| `lifecycle/duplicate`         | (1)                        |
| `lifecycle/fixed`             | `S-fixed`                  |
| `lifecycle/needs-review`      | `S-needs-triage`           |
| `lifecycle/not-a-bug`         | (2)                        |
| `lifecycle/wont-fix`          | (3)                        |
| `question`                    | `C-question`               |
| `ready-for-review`            | `S-waiting-on-review`      |
| `regen-goldens`               | `S-needs-golden-regen`     |
| `release-blocker`             | `P-release-blocker`        |
| `size/l`                      | `E-hard`                   |
| `size/m`                      | `E-medium`                 |
| `size/s`                      | `E-easy`                   |
| `size/xl`                     | `E-hard`                   |
| `size/xs`                     | `E-easy`                   |

- 1: Link issue and close as not planned
- 2: Explain the finding and close as not planned
- 3: Close as not planned

## New labels

| Proposed label  | Description                                  |
| --------------- | -------------------------------------------- |
| `O-x86_64`      | Specific to x86-64 processors                |
| `O-aarch64`     | Specific to 64-bit Arm processors            |
| `O-kvm`         | Linux KVM backend                            |
| `O-mshv`        | Linux MSHV backend for Microsoft Hyper-V     |
| `O-whp`         | Windows Hypervisor Platform backend          |
| `O-hvf`         | macOS Hypervisor Framework backend           |
| `O-linux`       | Linux host support                           |
| `O-windows`     | Windows host support                         |
| `O-macos`       | macOS host support                           |
| `S-to-announce` | To announce in the next release              |
| `S-needs-repro` | Needs a repro to confirm the bug             |
| `S-nominated`   | Nominated for discussion in the next meeting |

## Frequently asked questions

### Why use single-letter prefixes?

I think this is a bit of a [Stroustrup’s
rule](https://buttondown.com/hillelwayne/archive/stroustrups-rule/): new
features want loud, explicit notation - established features want a terse
notation. A labeling system is not a programming language, but it’s still a
system we interact with. Short, terse labels are nice when we use something a
lot - and I plan for us to use this a lot.

### Can an issue have multiple labels?

Yes! In fact, they almost always should! For example, a bug about MSHV support
on Linux should be tagged `O-mshv`, `O-linux`, `C-bug`, and
`S-waiting-on-triage`.

### This seems complicated, do we really need it?

There are two kinds of systems: ones which we design, and once which are accrue
over time. Most of what we’re proposing in this HIP is an iteration on things
we’re already tracking, very little is completely new. All this HIP really does
is spell out the system in whole.

### Can we automate parts of this?

In the Rust project, Rustbot automatically tags issues with
`S-waiting-on-review` and `S-waiting-on-author` depending on who has last
responded. This makes it easier to e.g. scan for items which are blocked on us
and we should get back to.

There is also the `S-needs-triage` label we’re proposing, which could be
automatically added whenever a new item is created. This would be easy to pick
up for agendas to discuss as part of triage.

### Why is “participation” labeled with “E-”

“Priority” is labeled “P-”, meaning participation needs a different prefix. Rust
uses “E-” which seems as good as any other.
