# **Pull Requests (PRs)**

We use GitHub labels to categorize PRs. Before a PR can be merged, it must be assigned one of the following **kind/** labels:

- **kind/enhancement** - For PRs that introduce new features or improve existing functionality. This label also applies to improvements in documentation, testing, and similar areas. Any changes must be backward-compatible.
- **kind/bugfix** - For PRs that fix bugs.
- **kind/refactor** - For PRs that restructure or remove code without adding new functionality. This label also applies to changes that affect user-facing APIs.
- **kind/dependencies** - For PRs that update dependencies or related components.

---

# **Issues**

Issues are categorized using the following three **GitHub types** (not GitHub labels):

- **bug** - Reports an unexpected problem or incorrect behavior.
- **enhancement** - Suggests a new feature, improvement, or idea.
- **design** - Relates to design considerations or decisions.

To track the lifecycle of issues, we also use GitHub labels:

- **lifecycle/needs-review** - A temporary label indicating that the issue has not yet been reviewed.
- **lifecycle/confirmed** - Confirms the issue’s validity:
  - If the issue type is **bug**, the bug has been verified.
  - If the issue type is **enhancement**, the proposal is considered reasonable but does not guarantee implementation.
  - This label does not indicate when or if the fix or enhancement will be implemented.
- **lifecycle/needs-info** - The issue requires additional information from the original poster (OP).
- **lifecycle/blocked** - The issue is blocked by another issue or external factor.

The following labels should be applied to issues prior to closing, indicating the resolution status of the issue:

- **lifecycle/fixed** - The issue has been resolved.
- **lifecycle/duplicate** - The issue is a duplicate of another issue.
- **lifecycle/not-a-bug** - The issue is not considered a bug, and no further action is needed.
- **lifecycle/wont-fix** - The issue will not be fixed.

In addition to lifecycle labels, we use the following labels to further categorize issues:

- **question** - The issue is a question or request for information.
- **help-wanted** - The issue is a request for help or assistance.
- **good-first-issue** - The issue is suitable for new contributors or those looking for a simple task to start with.

---

# **Issues & PRs**

In addition to **kind/*** labels, we use optional **area/*** labels to specify the focus of a PR or issue. These labels are purely for categorization, and are not mandatory.

- **area/documentation** - Related to documentation updates or improvements.
- **area/API** - Related to the API or public interface.
- **area/infrastructure** - Concerns infrastructure rather than core functionality.
- **area/performance** - Addresses performance.
- **area/security** - Involves security-related changes or fixes.
- **area/testing** - Related to tests or testing infrastructure.


## Notes
This document is a work in progress and may be updated as needed. The labels and categories are subject to change based on the evolving needs of the project and community feedback.