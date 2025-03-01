# **PRs**  

To categorize PRs, we use GitHub labels. Before a PR can be merged, it must be assigned one of the following four labels, as these labels are used to generate automatic release notes:  

- **kind/enhancement** – For PRs that add new features or improve existing functionality.  
- **kind/breaking-change** – For PRs that introduce changes that alter existing behavior.  
- **kind/bugfix** – For PRs that resolve bugs.  
- **kind/ignore** – For PRs that do not fit into the above categories and should be excluded from release notes, such as documentation updates, CI/CD tweaks, or minor test adjustments.  

---

# **Issues**  

Issues are categorized using the following three **GitHub types** (not GitHub labels):  

- **bug** – Reports an unexpected problem or incorrect behavior.  
- **enhancement** – Suggests a new feature, improvement, or idea.  
- **design** – Relates to design considerations or decisions.  

To track the lifecycle of issues, we also use GitHub labels:  

- **lifecycle/needs-review** – A temporary label indicating that the issue has not yet been reviewed.  
- **lifecycle/confirmed** – Confirms the issue’s validity:  
  - If the issue type is **bug**, the bug has been verified.  
  - If the issue type is **enhancement**, the proposal has been deemed ready for implementation.  
  - This label does not indicate when the fix or enhancement will be implemented. Unconfirmed issues are typically closed with an explanatory comment.  
- **lifecycle/needs-info** – The issue requires additional information from the original poster (OP).
- **lifecycle/blocked** - The issue is blocked by another issue or external factor.

---

# **Issues & PRs**  

In addition to **kind/*** labels, we use optional **area/*** labels to specify the focus of a PR or issue. These labels are purely for categorization, are not mandatory, and are not used for release notes.  

- **area/dependencies** – Relates to dependency management and updates.  
- **area/documentation** – Related to documentation updates or improvements.  
- **area/infrastructure** – Concerns infrastructure rather than core functionality.  
- **area/performance** – Addresses performance.  
- **area/security** – Involves security-related changes or fixes.  
- **area/testing** – Related to tests or testing infrastructure.  