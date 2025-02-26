# Contribution Guidelines

This project welcomes contributions. Most contributions require you to signoff on your commits via
the Developer Certificate of Origin (DCO). When you submit a pull request, a DCO-bot will automatically determine
whether you need to provide signoff for your commit. Please follow the instructions provided by DCO-bot, as pull
requests cannot be merged until the author(s) have provided signoff to fulfill the DCO requirement.
You may find more information on the DCO requirements [below](#developer-certificate-of-origin-signing-your-work).

## Issues

This section describes the guidelines for submitting issues

### Issue Types

There are 2 types of issues:

- Bug: You've found a bug with the code, and want to report it, or create an issue to track the bug.
- Proposal: Used for items that propose a new idea or functionality. This allows feedback from others before code is written.

## Contributing to Hyperlight

This section describes the guidelines for contributing code / docs to Hyperlight.

### Opening a New Pull Request

All contributions come through pull requests.

To submit a proposed change, we recommend following this workflow:

1. Make sure there's an issue (bug or proposal) raised, which sets the expectations for the contribution you are about to make.
2. Fork the relevant repo and create a new branch
3. Create your change
    - Code changes require tests
    - Make sure to run the linters to check and format the code
4. Update relevant documentation for the change
5. Commit with [DCO sign-off](#developer-certificate-of-origin-signing-your-work) and open a PR
6. Wait for the CI process to finish and make sure all checks are green
7. A maintainer of the project will be assigned, and you can expect a review within a few days

#### Use work-in-progress PRs for early feedback

A good way to communicate before investing too much time is to create a "Work-in-progress" PR and share it with your reviewers. The standard way of doing this is to add a "[WIP]" prefix in your PR's title and open the pull request as a draft.

### Pull Request Lifecycle

Hyperlight leverages a [PROW](https://docs.prow.k8s.io/) deployment to manage the lifecycle of pull requests.
This section describes requirements needed for the system to successfully merge pull requests and also commands that can be used to interact with the system.

#### Merge Requirements

[Tide](https://docs.prow.k8s.io/docs/components/core/tide/) is a component of the PROW deployment that enforces merge requirements on pull requests and handles mering of eligible pull requests.

The following **requirements** must be met before a pull request can be merged:

- The following labels must be present on the pull request:
  - `lgtm`: 'Looks good to me' approval from at least one reviewer.
  - `approved`: 'Approved' approval from at least one maintainer.
- The following labels must *not* be present on the pull request:
  - `do-not-merge/hold`: 'Do not merge' label indicating a review has requested the pull request not be merged.
  - `do-not-merge/work-in-progress`: 'Do not merge' label indicating the pull request is not ready to be merged.
  - `needs-rebase`: A label indicating the pull request needs to be rebased to avoid conflicts.

#### Interacting With Pull Requests

- 'Looks Good To Me' (LGTM) approval can be given by adding a comment with `/lgtm` to the pull request.
  LGTM approval can be given GitHub org members (excluding the author of the pull request).
  `/lgtm cancel` can be used to revoke the LGTM approval.
- 'Approved' approval can be given by adding a comment with `/approve` to the pull request.
  Pull Request approval is reserved for code owners declared in the `OWNERS` file.
  Note: pushing new changes to a pull request will not cancel the approval.
  `/approve cancel` can be used to revoke the approval.
- 'Do Not Merge' labels are used to prevent pull requests from merging.
  `/hold {reason}` can be added to comments to add the `do-not-merge/hold` label.
  `/hold cancel` can be used to remove the `do-not-merge/hold` label.
- 'tide' labels can be used to change how the pull request will be merged.
  `/label tide/merge-method-merge` will merge the pull request using the 'merge' (default) method.
  `/label tide/merge-method-squash` will merge the pull request using the 'squash' method.
  `/label tide/merge-method-rebase` will merge the pull request using the 'rebase' method.
  `/remove-label tide/merge-method-{method}` will remove the merge method label.

### Developer Certificate of Origin: Signing your work

#### Every commit needs to be signed

The Developer Certificate of Origin (DCO) is a lightweight way for contributors to certify that they wrote or otherwise have the right to submit the code they are contributing to the project. Here is the full text of the [DCO](https://developercertificate.org/), reformatted for readability:

```text
By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I have the right to submit it under the open source license indicated in the file; or

    (b) The contribution is based upon previous work that, to the best of my knowledge, is covered under an appropriate open source license and I have the right under that license to submit that work with modifications, whether created in whole or in part by me, under the same open source license (unless I am permitted to submit under a different license), as indicated in the file; or

    (c) The contribution was provided directly to me by some other person who certified (a), (b) or (c) and I have not modified it.

    (d) I understand and agree that this project and the contribution are public and that a record of the contribution (including all personal information I submit with it, including my sign-off) is maintained indefinitely and may be redistributed consistent with this project or the open source license(s) involved.
```

Contributors sign-off that they adhere to these requirements by adding a `Signed-off-by` line to commit messages.

```text
This is my commit message

Signed-off-by: Random J Developer <random@developer.example.org>
```

Git even has a `-s` command line option to append this automatically to your commit message:

```sh
git commit -s -m 'This is my commit message'
```

Each Pull Request is checked  whether or not commits in a Pull Request do contain a valid Signed-off-by line.

#### I didn't sign my commit, now what?!

No worries - You can easily replay your changes, sign them and force push them!

```sh
git checkout <branch-name>
git commit --amend --no-edit --signoff
git push --force-with-lease <remote-name> <branch-name>
```

*Credit: This doc was cribbed from Dapr.*

### Rust Analyzer

If you are using the [Rust Analyzer](https://rust-analyzer.github.io/manual.html) then you may need to set the configuration option `rust-analyzer.rustfmt.extraArgs` to `["+nightly"]` to ensure that formatting works correctly as this project has a [`rustfmt.toml`](./rustfmt.toml) file that uses nightly features.
