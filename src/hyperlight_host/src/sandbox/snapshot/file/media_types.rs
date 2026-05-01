/*
Copyright 2025 The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Media types are versioned by suffix. The loader matches each
// version specifically (no `_CURRENT` shortcut on the read side); the
// writer always emits `_CURRENT`. A new version is added by:
//
//   1. Declare `MT_FOO_V2` next to `MT_FOO_V1`.
//   2. Point `MT_FOO_CURRENT` at `MT_FOO_V2`.
//   3. Add a dispatch arm in the loader that converts v1 -> v2 (or
//      rejects v1 if no compatibility window is offered).
pub(super) const MT_CONFIG_V1: &str = "application/vnd.hyperlight.snapshot.config.v1+json";
pub(super) const MT_CONFIG_CURRENT: &str = MT_CONFIG_V1;
pub(super) const MT_SNAPSHOT_V1: &str = "application/vnd.hyperlight.snapshot.memory.v1";
pub(super) const MT_SNAPSHOT_CURRENT: &str = MT_SNAPSHOT_V1;

/// ABI version for the snapshot memory blob. Bumped whenever the
/// host-guest contract for the bytes inside the snapshot blob changes
/// (PEB layout, calling convention, init state, etc.). Independent of
/// the config blob's media-type version.
pub(super) const SNAPSHOT_ABI_VERSION: u32 = 1;
