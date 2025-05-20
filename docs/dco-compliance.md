# DCO Compliance

This document explains how to ensure your commits comply with the Developer Certificate of Origin (DCO) requirements for this project.

## What is the DCO?

The Developer Certificate of Origin (DCO) is a lightweight way for contributors to certify that they wrote or otherwise have the right to submit the code they are contributing to the project. See the full text in the [CONTRIBUTING.md](../CONTRIBUTING.md#developer-certificate-of-origin-signing-your-work) file.

## Adding DCO Sign-offs to Commits

All commits must include a `Signed-off-by` line in the commit message. This line certifies that you have the right to submit your contribution under the project's license.

### Using the -s Flag

The simplest way to add a sign-off to your commits is to use the `-s` flag with the `git commit` command:

```sh
git commit -s -m "Your commit message"
```

This will automatically add a `Signed-off-by` line with your name and email to the commit message.

### Configuring Git for Automatic Sign-offs

You can configure Git to automatically add sign-offs to all your commits:

```sh
git config --global commit.signoff true
```

Alternatively, you can create a Git alias for creating signed-off commits:

```sh
git config --global alias.cs 'commit -s'
```

Then use `git cs` instead of `git commit` to create commits with sign-offs.

### Adding Sign-offs to Existing Commits

If you forgot to sign off your commits, you can amend them:

```sh
git commit --amend --no-edit --signoff
```

For multiple commits, you can use git rebase:

```sh
git rebase --signoff HEAD~n
```

Replace `n` with the number of commits you want to sign off.

## Verification

The project uses automated checks to verify that all commits include the required DCO sign-off. If you receive a DCO failure notification, please follow the instructions above to add the required sign-offs.