# **Pull Requests (PRs)**

This guide describes the proposed scheme in [HIP 0005](../proposals/0005-structured-labels/README.md). Existing automation still uses legacy names. Keep using those names until labels and automation are migrated together.

We use GitHub labels to categorize PRs. Before a PR can be merged, it must be assigned one of the following **C-** labels:

* **C-bug**: For PRs that fix bugs.
* **C-deps**: For PRs that update dependencies or related components.
* **C-enhancement**: For PRs that introduce new features or improve existing functionality. This label also applies to improvements in documentation, testing, and similar areas. Any changes must be backward-compatible.
* **C-refactor**: For PRs that restructure or remove code without adding new functionality. This label also applies to changes that affect user-facing APIs.

The [PR label check](../.github/workflows/PRLabelChecker.yml) still requires exactly one `kind/*` label until migration.

## Review readiness

We use the **S-needs-review** label to signal that a PR is waiting for a (re-)review:

* **Add** `S-needs-review` when you open a PR that is ready for review, or when a PR is ready for re-review (for example, once you have addressed requested changes and re-requested review).
* The review automation (the [`collect`](../.github/workflows/ready-for-review-label.yml) and [`manage`](../.github/workflows/ready-for-review-manage.yml) workflows) must preserve automatic removal once the PR is no longer awaiting that review, specifically when any of the following become true:
  * the PR is closed or merged,
  * the PR is converted to a draft,
  * the PR has two or more approvals, or
  * the PR has two or more change requests.

Only reviews of the current head commit count. Authors add the label, and automation handles removal. Until migration, this automation requires `ready-for-review`.

---

# **Issues**

Issues are categorized using the following three **GitHub types** (not GitHub labels):

* **bug**: Reports an unexpected problem or incorrect behavior.
* **design**: Relates to design considerations or decisions.
* **enhancement**: Suggests a new feature, improvement, or idea.

To track the status of issues, we also use GitHub labels:

* **S-needs-triage**: A temporary label indicating that the issue has not yet been assessed.
* **S-confirmed**: Confirms the issue's validity:
  * If the issue type is **bug**, the bug has been verified.
  * If the issue type is **enhancement**, the proposal is considered reasonable but does not guarantee implementation.
  * This label does not indicate when or if the fix or enhancement will be implemented.
* **S-waiting-on-author**: The author needs to provide information or make changes. This includes requests previously labeled `lifecycle/needs-info`.
* **S-needs-repro**: A reproduction is needed to confirm a bug.
* **S-blocked**: The issue is blocked by another issue or external factor.

Use GitHub's closure reasons to indicate resolution:

* Link duplicate issues to the original and close as **not planned**.
* Close resolved issues as **completed**.
* Explain findings that are not bugs and close as **not planned**.
* Explain decisions not to fix an issue and close as **not planned**.

In addition to status labels, we use the following labels to further categorize issues:

* **E-easy**: The issue is suitable for new contributors or those looking for a simple task to start with.
* **E-help-wanted**: The issue is a request for help or assistance.
* **C-question**: The issue is a question or request for information.
* **P-release-blocker**: Critical issues that must be resolved before the next release can be made. Any open issue with the release-blocking label prevents release creation. The [release check](../dev/check-release-blockers.sh) still queries `release-blocker` until migration.

---

# **Issues & PRs**

Labels use seven prefixes: **A-** for area, **C-** for category, **E-** for participation, **F-** for feature, **O-** for platform, **P-** for priority, and **S-** for status. Area labels vary by project. Most other labels are shared across the org.

In addition to **C-** labels, we use optional **A-** labels to specify the focus of a PR or issue. These labels are purely for categorization, and are not mandatory.

* **A-api**: Related to the API or public interface.
* **A-ci**: Related to CI workflows and GitHub Actions.
* **A-ci-periodics**: Applied to issues that track failures from scheduled (periodic) CI jobs. These issues are opened automatically by the CI failure notifier (`dev/notify-ci-failure.sh`).
* **A-ci-periodics-aarch64**: De-duplication label for failures from the daily aarch64 workflow (`.github/workflows/DailyArm64.yml`). It keeps those failures on their own dedicated, release-blocking issue.
* **A-ci-periodics-mshv-6.18**: De-duplication label for failures from the weekly MSHV 6.18 workflow (`.github/workflows/WeeklyMshv618.yml`). It keeps those failures on their own release-blocking issue.
* **A-ci-periodics-nightly**: De-duplication label for failures from the nightly Rust workflow (`.github/workflows/RustNightly.yml`). It keeps those failures on their own release-blocking issue.
* **A-deps**: Concerns dependencies or related components. This identifies the affected area. **C-deps** identifies a dependency update PR.
* **A-docs**: Related to documentation updates or improvements. Use with **C-bug** for fixes or **C-enhancement** for improvements.
* **A-fuzzing**: Related to fuzzing.
* **A-infra**: Concerns infrastructure rather than core functionality.
* **A-perf**: Addresses performance.
* **A-security**: Involves security-related changes or fixes.
* **A-testing**: Related to tests or testing infrastructure.

The CI failure notifier still uses `area/ci-periodics*` names until migration.

Platform labels identify architectures (**O-x86_64**, **O-aarch64**), host operating systems (**O-linux**, **O-windows**, **O-macos**), and hypervisor backends (**O-kvm**, **O-mshv**, **O-whp**, **O-hvf**). Combine them where relevant. **F-guest-cow** tracks guest copy-on-write support.

## Workflow labels

Status labels can be combined. For example, a PR can have both **S-needs-review** and **S-nominated**.

* **S-nominated**: Nominated for discussion in the next meeting.
* **S-needs-announcement**: To announce in the next release.
* **S-needs-goldens**: Requests snapshot golden regeneration. A PR that intentionally changes the snapshot format and bumps `GOLDENS_VERSION` carries this label so the verify job generates the goldens from the branch and runs them back through the branch loader. This allows verification before the new golden set is published. The [PR workflow](../.github/workflows/ValidatePullRequest.yml) still requires `regen-goldens` for this mode until migration. See [snapshot-versioning.md](snapshot-versioning.md).

## Notes

The scheme has no size labels or difficulty scale beyond **E-easy**. The labels and categories are subject to change based on the evolving needs of the project and community feedback.
