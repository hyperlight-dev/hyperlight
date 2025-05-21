# Commit Signing Requirements

This document explains how to ensure your commits comply with both the Developer Certificate of Origin (DCO) requirements and GPG signing requirements for this project.

## What is the DCO?

The Developer Certificate of Origin (DCO) is a lightweight way for contributors to certify that they wrote or otherwise have the right to submit the code they are contributing to the project. See the full text in the [CONTRIBUTING.md](../CONTRIBUTING.md#developer-certificate-of-origin-signing-your-work) file.

## Two Required Signature Types

All commits to this repository must have two types of signatures:

1. **DCO Sign-off**: A `Signed-off-by` line in the commit message
2. **GPG Signature**: A cryptographic signature verifying the committer's identity

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

## GPG Signing Your Commits

In addition to DCO sign-offs, all commits must be GPG signed to verify your identity.

### Setting Up GPG

1. If you don't have a GPG key, generate one:

   ```sh
   gpg --full-generate-key
   ```
   
   Choose RSA and RSA, 4096 bits, and an expiration date of your preference.

2. List your keys to get the ID:

   ```sh
   gpg --list-secret-keys --keyid-format=long
   ```
   
   Look for the line starting with "sec" and note the key ID after the "/".

3. Configure Git to use your GPG key:

   ```sh
   git config --global user.signingkey YOUR_KEY_ID
   ```
   
   Replace YOUR_KEY_ID with your actual GPG key ID.

4. Configure Git to sign commits automatically:

   ```sh
   git config --global commit.gpgsign true
   ```

### Creating GPG Signed Commits

With automatic signing enabled, normal commit commands will create signed commits. You can also explicitly sign with:

```sh
git commit -S -m "Your commit message"
```

To create a commit with both GPG signature and DCO sign-off:

```sh
git commit -S -s -m "Your commit message"
```

### Adding Your GPG Key to GitHub

1. Export your public key:

   ```sh
   gpg --armor --export YOUR_KEY_ID
   ```

2. Copy the output and add it to your GitHub account under Settings > SSH and GPG keys.

## Adding Both Signatures to Existing Commits

If you forgot to sign your commits, you can fix them:

### For the Last Commit

```sh
git commit --amend --no-edit -S -s
```

### For Multiple Commits

For adding both DCO sign-offs and GPG signatures to a range of commits, use interactive rebase:

1. Start the rebase:

   ```sh
   git rebase -i HEAD~n
   ```
   
   Replace `n` with the number of commits you want to sign.

2. In the editor, change `pick` to `edit` for each commit.

3. For each commit that opens during the rebase:

   ```sh
   git commit --amend --no-edit -S -s
   git rebase --continue
   ```

Alternatively, for adding just DCO sign-offs to multiple commits:

```sh
git rebase --signoff HEAD~n
```

## Verification

The project uses automated checks to verify that all commits include both the required DCO sign-off and GPG signature. If you receive a signature verification failure notification, please follow the instructions above to add the required signatures.

## Troubleshooting

### GPG Signing Issues

If you encounter issues with GPG signing:

- Ensure your GPG key is properly generated and configured with Git
- Set the `GPG_TTY` environment variable: `export GPG_TTY=$(tty)`
- For Git GUI tools, you may need to configure GPG agent
- On Windows, you might need to specify the full path to gpg.exe

### DCO Sign-off Issues

If you encounter issues with DCO sign-offs:

- Ensure your Git user name and email are correctly configured
- Check that the commit author email matches your configured email
- For commits created through GitHub's web interface, you'll need to add the sign-off manually in the commit message