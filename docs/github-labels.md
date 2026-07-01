# **Pull Requests (PRs)**

We use GitHub labels to categorize PRs. Before a PR can be merged, it must be assigned one of the following **kind/** labels:

- **kind/bugfix** - For PRs that fix bugs.
- **kind/dependencies** - For PRs that update dependencies or related components.
- **kind/enhancement** - For PRs that introduce new features or improve existing functionality. This label also applies to improvements in documentation, testing, and similar areas. Any changes must be backward-compatible.
- **kind/refactor** - For PRs that restructure or remove code without adding new functionality. This label also applies to changes that affect user-facing APIs.

## Review readiness

We use the **ready-for-review** label to signal that a PR is waiting for a (re-)review:

- **Add** `ready-for-review` when you open a PR that is ready for review, or when a PR is ready for re-review (for example, once you have addressed requested changes and re-requested review).
- The label is **removed automatically** by the [`Ready-for-review label`](../.github/workflows/ready-for-review-label.yml) workflow once the PR is no longer awaiting that review, specifically when any of the following become true:
  - the PR is closed or merged,
  - the PR is converted to a draft,
  - the PR has two or more approvals, or
  - the PR has two or more change requests.

You only ever need to add the label; removal is fully automated.

---

# **Issues**

Issues are categorized using the following three **GitHub types** (not GitHub labels):

- **bug** - Reports an unexpected problem or incorrect behavior.
- **design** - Relates to design considerations or decisions.
- **enhancement** - Suggests a new feature, improvement, or idea.

To track the lifecycle of issues, we also use GitHub labels:

- **lifecycle/needs-review** - A temporary label indicating that the issue has not yet been reviewed.
- **lifecycle/confirmed** - Confirms the issue’s validity:
  - If the issue type is **bug**, the bug has been verified.
  - If the issue type is **enhancement**, the proposal is considered reasonable but does not guarantee implementation.
  - This label does not indicate when or if the fix or enhancement will be implemented.
- **lifecycle/needs-info** - The issue requires additional information from the original poster (OP).
- **lifecycle/blocked** - The issue is blocked by another issue or external factor.

The following labels should be applied to issues prior to closing, indicating the resolution status of the issue:

- **lifecycle/duplicate** - The issue is a duplicate of another issue.
- **lifecycle/fixed** - The issue has been resolved.
- **lifecycle/not-a-bug** - The issue is not considered a bug, and no further action is needed.
- **lifecycle/wont-fix** - The issue will not be fixed.

In addition to lifecycle labels, we use the following labels to further categorize issues:

- **good-first-issue** - The issue is suitable for new contributors or those looking for a simple task to start with.
- **help-wanted** - The issue is a request for help or assistance.
- **question** - The issue is a question or request for information.
- **release-blocker** - Critical issues that must be resolved before the next release can be made. The presence of this label on any open issue will prevent releases being created by the release workflow

---

# **Issues & PRs**

In addition to **kind/*** labels, we use optional **area/*** labels to specify the focus of a PR or issue. These labels are purely for categorization, and are not mandatory.

- **area/API** - Related to the API or public interface.
- **area/ci-periodics** - Applied to issues that track failures from scheduled (periodic) CI jobs. These issues are opened automatically by the CI failure notifier (`dev/notify-ci-failure.sh`).
- **area/ci-periodics-aarch64** - De-duplication label for failures from the daily aarch64 workflow (`.github/workflows/DailyArm64.yml`). It keeps those failures on their own dedicated, release-blocking issue instead of sharing the general `area/ci-periodics` issue.
- **area/dependencies** - Concerns dependencies or related components. This label is different from **kind/dependencies**, which should only used for PRs.
- **area/documentation** - Related to documentation updates or improvements.
- **area/infrastructure** - Concerns infrastructure rather than core functionality.
- **area/performance** - Addresses performance.
- **area/security** - Involves security-related changes or fixes.
- **area/testing** - Related to tests or testing infrastructure.

## Workflow labels

Some labels change CI behaviour on a PR rather than categorizing it:

- **regen-goldens** - Switches the snapshot golden verify job into regenerate mode. A PR that intentionally changes the snapshot format and bumps `GOLDENS_VERSION` carries this label so the verify job generates the goldens from the branch and runs them back through the branch loader, rather than pulling a published tag set that does not exist yet. See [snapshot-versioning.md](snapshot-versioning.md).


## Notes
This document is a work in progress and may be updated as needed. The labels and categories are subject to change based on the evolving needs of the project and community feedback.
