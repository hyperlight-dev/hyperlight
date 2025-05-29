# Contribution Guidelines

This project welcomes contributions. Most contributions require you to signoff on your commits via
the Developer Certificate of Origin (DCO). When you submit a pull request, a DCO-bot will automatically determine
whether you need to provide signoff for your commit. Please follow the instructions provided by DCO-bot, as pull
requests cannot be merged until the author(s) have provided signoff to fulfill the DCO requirement.
You may find more information on the DCO requirements [below](#developer-certificate-of-origin-and-gpg-signing).

## Issues

This section describes the guidelines for submitting issues

### Issue Types

There are 2 types of issues:

- Bug: You've found a bug with the code, and want to report it, or create an issue to track the bug.
- Proposal: Used for items that propose a new idea or functionality. This allows feedback from others before code is written.

## Contributing to Hyperlight

This section describes the guidelines for contributing code / docs to Hyperlight.

### Pull Requests

All contributions come through pull requests. To submit a proposed change, we recommend following this workflow:

1. Make sure there's an issue (bug or proposal) raised, which sets the expectations for the contribution you are about to make.
2. Fork the relevant repo and create a new branch
3. Create your change
    - Code changes require tests
    - Make sure to run the linters to check and format the code
4. Update relevant documentation for the change
5. Commit with [DCO sign-off](#developer-certificate-of-origin-and-gpg-signing) and open a PR
6. Wait for the CI process to finish and make sure all checks are green
7. A maintainer of the project will be assigned, and you can expect a review within a few days

#### Use work-in-progress PRs for early feedback

A good way to communicate before investing too much time is to create a "Work-in-progress" PR and share it with your reviewers. The standard way of doing this is to add a "[WIP]" prefix in your PR's title and open the pull request as a draft.

### Developer Certificate of Origin and GPG Signing

#### Every commit needs to be signed

This project requires two types of signatures on all commits:

1. **Developer Certificate of Origin (DCO) Sign-off**: A text attestation that you have the right to submit the code
2. **GPG Signature**: A cryptographic signature verifying your identity

**For DCO Sign-offs:**

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

**For GPG Signatures:**

GPG signatures verify the identity of the committer. For detailed setup instructions, see GitHub's documentation on [signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

Quick setup:

```sh
git config --global user.signingkey YOUR_KEY_ID
git config --global commit.gpgsign true
```

**For both DCO sign-off and GPG signature in one command:**

```sh
git commit -S -s -m 'This is my signed and signed-off commit message'
```

For detailed instructions on setting up GPG signing, see [GitHub's documentation on signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

Each Pull Request is checked to ensure all commits contain valid DCO sign-offs and GPG signatures.

#### I didn't sign my commit, now what?

No worries - You can easily replay your changes, sign them and force push them!

**For adding both DCO sign-off and GPG signature:**

```sh
git checkout <branch-name>
git commit --amend --no-edit -S -s
git push --force-with-lease <remote-name> <branch-name>
```

For more detailed instructions on setting up GPG signing, see [GitHub's documentation on signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

*Credit: This doc was cribbed from Dapr.*

### Rust Analyzer

If you are using the [Rust Analyzer](https://rust-analyzer.github.io/manual.html) then you may need to set the configuration option `rust-analyzer.rustfmt.extraArgs` to `["+nightly"]` to ensure that formatting works correctly as this project has a [`rustfmt.toml`](./rustfmt.toml) file that uses nightly features.
