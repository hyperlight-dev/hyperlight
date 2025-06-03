# Releasing a new Hyperlight version to Cargo

This document details the process of releasing a new version of Hyperlight to [crates.io](https://crates.io). It's intended to be used as a checklist for the developer doing the release. The checklist is represented in the below sections.

## Update Cargo.toml Versions

Currently, we need to manually update the workspace `Cargo.toml` version number to match to whatever release we are making. This will affect the version of all the crates in the workspace.

> Note: we'll use `v0.4.0` as the version for the above and all subsequent instructions. You should replace this with the version you're releasing. Make sure your version follows [SemVer](https://semver.org) conventions as closely as possible, and is prefixed with a `v` character. *In particular do not use a patch version unless you are patching an issue in a release branch, releases from main should always be minor or major versions*.

Create a PR with this change and merge it into the main branch.

## Update `CHANGELOG.md`

The `CHANGELOG.md` file is a critical document used to track changes made to Hyperlight. It serves as the foundation for generating release notes, so it's essential to keep it up to date with each release. While not every change needs to be added to this file (since a complete changelog of all PRs will be automatically generated), it's crucial to include all significant updates.

### Steps to Update `CHANGELOG.md`:

- **Manually update the `CHANGELOG.md`** with important changes since the latest release. Ideally, contributors should update this file as part of their PR, but this may not always happen.
  
- **Rename the `[Prerelease] - Unreleased` section** to reflect the new version number (if not already done). Ensure that it links to the GitHub comparison between the current and previous versions. For example, `v0.2.0` should link to `https://github.com/hyperlight-dev/hyperlight/compare/v0.1.0...v0.2.0` (see the footer of `CHANGELOG.md`).

- **Add a new `[Prerelease]` section** at the top of the file. This section should initially be empty and will track changes for the next release.

- **Preview the automatically generated release notes** locally using the command:  
  `just create-release-notes v0.4.0 > notes.md`. Review the notes to ensure everything looks accurate.

- **Create a PR** with the updated `CHANGELOG.md` and merge it into the main branch once all changes are confirmed.

## Create a tag

When both above PRs has merged into `main` branch you should create a tag. ***Make sure you have pulled the recently updated `main` branch***, and do the following on the `main` branch:

```bash
git tag -a v0.4.0 -m "A brief description of the release"
git push origin v0.4.0 # if you've named your git remote for the hyperlight-dev/hyperlight repo differently, change 'origin' to your remote name
```

If you are creating a patch release see the instructions [here](#patching-a-release).

## Create a release branch (no manual steps)

After you push your new tag in the previous section, the ["Create a Release Branch"](https://github.com/hyperlight-dev/hyperlight/actions/workflows/CreateReleaseBranch.yml) CI job will automatically run. When this job completes, a new `release/v0.4.0` branch will be automatically created for you.

## Create a new GitHub release

After the previous CI job runs to create the new release branch, go to the ["Create a Release"](https://github.com/hyperlight-dev/hyperlight/actions/workflows/CreateRelease.yml). GitHub actions workflow and do the following:

1. Click the "Run workflow" button near the top right
2. In the Use workflow from dropdown, select the `release/v0.4.0` branch
3. Click the green **Run workflow** button

> Note: In case you see a "Create a Release" job already running before starting this step, that is because the "Create a Release" workflow also automatically runs on push to `main` branch to create a pre-release. You must still do the steps outlined above.

When this job is done, a new [GitHub release](https://github.com/hyperlight-dev/hyperlight/releases) will be created for you. This job also publishes the following rust packages to the crates.io:
- `hyperlight-common`
- `hyperlight-guest`
- `hyperlight-guest-bin`
- `hyperlight-host`

## Patching a release
> Note: for this example we'll assume `v0.4.0` is already released, and you want to release a `v0.4.1` patch for it.

1. Make sure the patch/patches you want include are already merged to `main` branch.
2. Make sure `CHANGELOG.md` is updated with the changes you want to include in the patch release (see instructions above) and is merged to `main` branch.
3. Make sure the `Cargo.toml` versions are updated to the new patch version (e.g. `v0.4.1`), and is merged to `main` branch.
4. Manually create a new branch **from the `release/v0.4.0` branch** and name it `release/v0.4.1`. Important: do not create the branch from `main` branch.
5. Cherry-pick the commits from `main` that you want to include in the patch (and resolve any conflicts). You must include the commit that updated the `CHANGELOG.md` and the commit that updated the `Cargo.toml` versions.
6. Create a tag for the patch release, e.g. `v0.4.1`, similar to the steps above. Push the tag. A job will start to try to make a new release branch for you, but it will fail because the `release/v0.4.1` branch already exists. This is expected, so don't worry about it.
7. Follow the steps above to create a new GitHub release, but this time select the `release/v0.4.1` branch in the "Use workflow from" dropdown. This will create a new GitHub release for you, and publish the updated packages to crates.io.

