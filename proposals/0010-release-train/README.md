# HIP 0010 - Release Train

## Summary

We propose releasing a new version of Hyperlight and the Hyperlight guests at the start of each month, with a branching one week before that.

## Status quo

Historically Hyperlight has not been the most consistent when it comes to releases, opting to release based on when work felt ready rather than on a predictable schedule. This has created some problems:

- Customers cannot anticipate when new releases will be made and so can’t plan to update ahead of time.
- Writing release announcements is a time-intensive process that benefits from review and editing. Without branching prior to release, this needs to be rushed every single time.
- Irregular and unscheduled releases make it easy to wait for “one more feature” to land, increasing the risk of not shipping work for extended periods.
- Hyperlight and its guests release at different intervals. Once Hyperlight is released it often takes a week or longer for Hyperlight-Wasm, Hyperlight-Unikraft, and others to be updated and released too.
- We currently do not publish any release notes for any of the Hyperlight guests, meaning this work goes largely unseen by both users and potential stakeholders.

## Shiny future

Hyperlight and its guests release once a month, on the second Wednesday of the month. As part of the release we publish post on our blog describing everything new in Hyperlight and its guests.

## Implementation details and plan

The release process is as follows:

1. On the first Wednesday of each month we create a staging branch for Hyperlight that we will use to release from.
2. As part of creating the branch we work to resolve any blocking concerns on main and back port them to the branch.
3. Hyperlight guests then begin the work of updating to the upcoming Hyperlight release, which they have a week to complete.
4. In the meantime we begin writing a release post for Hyperlight and the guests.
5. On release day we tag the Hyperlight staging branch and publish the release from it.
6. We then repeat the same process for the guests, substituting the staged Hyperlight release branch with the actual release in the dependency manifest.
7. Finally we publish the release post containing all changes.

## Frequently asked questions

### Why monthly releases?

Hyperlight Unikraft wants to release at least monthly, so in order not to limit its cadence we can’t release less often.

Publishing based on day-of-week-of-month has the benefit we’ll never find ourselves publishing on weekends (day-of-month) or on holidays (every N weeks).

## Should we ever delay releases?

The goal is not to. Never say never, but we shouldn’t push releases based on wanting to land features or things not being quite ready yet. We release often enough that pushing it back to a next release shouldn't be a big deal.

This can be a bit more difficult for bigger features, but we should figure out how to introduce those in a way that if they span more than one release to land that's ok. Feature gates are something we haven’t historically made much use of, and we should probably leverage more.

## Why release guests and core in the same release?

It’s no good if we announce a release, and just because someone uses a specific guest they can’t use it when we announce it. That's a bad user experience that can be fixed by being better about how we schedule our releases. So I'm proposing we do.

## Why not wait until Hyperlight 1.0?

Hyperlight 1.0 will be plenty big as it is. If we can’t dial in our release processes before then, we’re not ready to go to 1.0. 1.0 is not the time to try out new processes, it's the time to announce that we have dialed in our processes and are comfortable keeping them up.
