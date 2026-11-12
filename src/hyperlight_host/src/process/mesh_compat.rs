// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

#![expect(dead_code, reason = "compile-time dependency compatibility probe")]

type OwnedInvitation = mesh_process::OwnedInvitation;

#[cfg(unix)]
type ProcessBuilder<'a> = pal::unix::process::Builder<'a>;

#[cfg(windows)]
type ProcessBuilder<'a> = pal::windows::process::Builder<'a>;
