# **PRs**  

To categorize PRs, we use GitHub labels. Before a PR can be merged, it must be assigned one of the following **kind/** labels, as these labels are used to generate automatic release notes:  

- **kind/enhancement** - For PRs that add new features or improve existing functionality. This label should also be applied to PRs that improve documentation and testing, for example.
- **kind/bugfix** - For PRs that resolve bugs.  
- **kind/refactor** - For PRs that improve code without changing its behavior.
- **kind/dependencies** - For PRs that update dependencies or related components.

## PR release notes 

GitHub release notes are automatically generated from PRs based on the assigned **kind/** labels, along with the PR title. To exclude PRs from release notes, add the **release-notes/ignore** label. 

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
  - If the issue type is **enhancement**, the proposal has been deemed ready for implementation.  
  - This label does not indicate when the fix or enhancement will be implemented.
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

In addition to **kind/*** labels, we use optional **area/*** labels to specify the focus of a PR or issue. These labels are purely for categorization, are not mandatory, and are not used for release notes.  

- **area/documentation** – Related to documentation updates or improvements.  
- **area/API** – Related to the API or public interface.
- **area/infrastructure** – Concerns infrastructure rather than core functionality.  
- **area/performance** – Addresses performance.  
- **area/security** – Involves security-related changes or fixes.  
- **area/testing** – Related to tests or testing infrastructure.  