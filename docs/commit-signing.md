# Commit Signing Requirements

This document explains the commit signing requirements for this project.

## Required Signatures

All commits to this repository must have two types of signatures:

1. **DCO Sign-off**: A `Signed-off-by` line in the commit message
2. **GPG Signature**: A cryptographic signature verifying the committer's identity

## DCO Sign-off

Add a DCO sign-off to your commits using the `-s` flag:

```sh
git commit -s -m "Your commit message"
```

For automatic sign-offs on all commits:

```sh
git config --global commit.signoff true
```

## GPG Signing

For detailed instructions on setting up GPG signing, see [GitHub's documentation on signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

To enable automatic GPG signing:

```sh
git config --global user.signingkey YOUR_KEY_ID
git config --global commit.gpgsign true
```

## Both Signatures Together

To create a commit with both DCO sign-off and GPG signature:

```sh
git commit -S -s -m "Your commit message"
```

## Fixing Missing Signatures

To add both signatures to your last commit:

```sh
git commit --amend --no-edit -S -s
```

For multiple commits, use:

```sh
git rebase --signoff HEAD~n  # Adds DCO sign-offs
```

Then manually add GPG signatures as needed during an interactive rebase.