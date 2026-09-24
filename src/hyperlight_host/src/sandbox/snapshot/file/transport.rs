// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

//! Binary framing for the snapshot's ring-image layer.
//!
//! [`VirtqSnapshot::new`] admits decoded rings against the finalized layout.

use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::virtq::VirtqSnapshot;

pub(super) const MAX_BLOB_SIZE: u64 = 2 * 1024 * 1024;
const MAGIC: [u8; 8] = *b"HLVQSNAP";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 40;

/// Serialize the scratch size and ring images.
pub(super) fn encode(snapshot: &VirtqSnapshot) -> crate::Result<Vec<u8>> {
    let g2h_len = snapshot.g2h_ring().len();
    let h2g_len = snapshot.h2g_ring().len();

    let total_len = HEADER_LEN
        .checked_add(g2h_len)
        .and_then(|len| len.checked_add(h2g_len))
        .ok_or_else(|| crate::new_error!("snapshot transport length overflow"))?;

    if total_len as u64 > MAX_BLOB_SIZE {
        return Err(crate::new_error!(
            "transport blob of {total_len} bytes exceeds the {MAX_BLOB_SIZE} byte maximum"
        ));
    }

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total_len)
        .map_err(|error| crate::new_error!("failed to allocate transport blob: {error}"))?;

    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&u64::try_from(snapshot.scratch_size())?.to_le_bytes());
    bytes.extend_from_slice(&u64::try_from(g2h_len)?.to_le_bytes());
    bytes.extend_from_slice(&u64::try_from(h2g_len)?.to_le_bytes());
    bytes.extend_from_slice(snapshot.g2h_ring());
    bytes.extend_from_slice(snapshot.h2g_ring());
    Ok(bytes)
}

fn read_field<const N: usize>(bytes: &mut &[u8]) -> Option<[u8; N]> {
    let (value, remaining) = bytes.split_first_chunk::<N>()?;

    *bytes = remaining;
    Some(*value)
}

/// Validate framing and admit ring images against the loaded layout.
pub(super) fn decode(layout: &SandboxMemoryLayout, bytes: &[u8]) -> crate::Result<VirtqSnapshot> {
    let total_len = bytes.len();
    let mut bytes = bytes;

    let Some(magic) = read_field(&mut bytes) else {
        return Err(crate::new_error!("snapshot transport magic is truncated"));
    };
    if magic != MAGIC {
        return Err(crate::new_error!("snapshot transport magic is invalid"));
    }

    let Some(version) = read_field(&mut bytes) else {
        return Err(crate::new_error!("snapshot transport version is truncated"));
    };
    let version = u32::from_le_bytes(version);
    if version != VERSION {
        return Err(crate::new_error!(
            "snapshot transport version mismatch: file has version {version}, this build expects {VERSION}"
        ));
    }

    let Some(reserved) = read_field(&mut bytes) else {
        return Err(crate::new_error!(
            "snapshot transport reserved field is truncated"
        ));
    };
    let reserved = u32::from_le_bytes(reserved);
    if reserved != 0 {
        return Err(crate::new_error!(
            "snapshot transport reserved field is nonzero"
        ));
    }

    let Some(scratch_size) = read_field(&mut bytes) else {
        return Err(crate::new_error!(
            "snapshot transport scratch size is truncated"
        ));
    };
    let scratch_size = usize::try_from(u64::from_le_bytes(scratch_size))?;

    let Some(g2h_len) = read_field(&mut bytes) else {
        return Err(crate::new_error!(
            "snapshot transport G2H ring length is truncated"
        ));
    };
    let g2h_len = usize::try_from(u64::from_le_bytes(g2h_len))?;

    let Some(h2g_len) = read_field(&mut bytes) else {
        return Err(crate::new_error!(
            "snapshot transport H2G ring length is truncated"
        ));
    };
    let h2g_len = usize::try_from(u64::from_le_bytes(h2g_len))?;

    let expected_len = HEADER_LEN
        .checked_add(g2h_len)
        .and_then(|len| len.checked_add(h2g_len))
        .ok_or_else(|| crate::new_error!("snapshot transport length overflow"))?;

    if total_len != expected_len {
        return Err(crate::new_error!(
            "snapshot transport length {} does not match header length {expected_len}",
            total_len
        ));
    }

    // The checked total length guarantees both ring slices fit.
    let (g2h_ring, h2g_ring) = bytes.split_at(g2h_len);

    VirtqSnapshot::new(layout, scratch_size, g2h_ring.to_vec(), h2g_ring.to_vec())
}

#[cfg(test)]
mod tests {
    use hyperlight_common::virtq::Descriptor;

    use super::*;
    use crate::mem::virtq::tests::{TestCase, memory_layout};

    /// Capture canonical rings for transport framing tests.
    fn transport_snapshot() -> (SandboxMemoryLayout, VirtqSnapshot) {
        let case = TestCase::new();
        let layout = memory_layout();
        let snapshot = VirtqSnapshot::capture(&layout, &case.scratch).unwrap();
        (layout, snapshot)
    }

    #[test]
    fn transport_blob_round_trips() {
        let (layout, snapshot) = transport_snapshot();
        let mut expected = vec![
            b'H', b'L', b'V', b'Q', b'S', b'N', b'A', b'P', // Magic.
            1, 0, 0, 0, // Version.
            0, 0, 0, 0, // Reserved.
            0, 0, 2, 0, 0, 0, 0, 0, // Scratch size.
            8, 1, 0, 0, 0, 0, 0, 0, // G2H length.
            136, 0, 0, 0, 0, 0, 0, 0, // H2G length.
        ];
        assert_eq!(expected.len(), HEADER_LEN);
        expected.extend_from_slice(snapshot.g2h_ring());
        expected.extend_from_slice(snapshot.h2g_ring());

        assert_eq!(encode(&snapshot).unwrap(), expected);
        assert_eq!(decode(&layout, &expected).unwrap(), snapshot);
    }

    #[test]
    fn transport_blob_rejects_empty_rings() {
        let (layout, snapshot) = transport_snapshot();
        let mut bytes = encode(&snapshot).unwrap();
        bytes.truncate(HEADER_LEN);
        bytes[24..40].fill(0);

        let error = decode(&layout, &bytes).unwrap_err();
        assert!(error.to_string().contains("ring lengths"), "{error}");
    }

    #[test]
    fn transport_blob_rejects_invalid_magic() {
        let (layout, snapshot) = transport_snapshot();
        let mut bytes = encode(&snapshot).unwrap();
        bytes[0] ^= 1;

        assert!(
            decode(&layout, &bytes)
                .unwrap_err()
                .to_string()
                .contains("magic is invalid")
        );
    }

    #[test]
    fn transport_blob_rejects_version_mismatch() {
        let (layout, snapshot) = transport_snapshot();
        let mut bytes = encode(&snapshot).unwrap();
        bytes[8..12].copy_from_slice(&VERSION.wrapping_add(1).to_le_bytes());

        assert!(
            decode(&layout, &bytes)
                .unwrap_err()
                .to_string()
                .contains("version mismatch")
        );
    }

    #[test]
    fn transport_blob_rejects_nonzero_reserved_field() {
        let (layout, snapshot) = transport_snapshot();
        let mut bytes = encode(&snapshot).unwrap();
        bytes[12] = 1;

        assert!(
            decode(&layout, &bytes)
                .unwrap_err()
                .to_string()
                .contains("reserved field is nonzero")
        );
    }

    #[test]
    fn transport_blob_rejects_truncated_header_fields() {
        let (layout, snapshot) = transport_snapshot();
        let bytes = encode(&snapshot).unwrap();

        for (range, field) in [
            (0..8, "magic"),
            (8..12, "version"),
            (12..16, "reserved field"),
            (16..24, "scratch size"),
            (24..32, "G2H ring length"),
            (32..40, "H2G ring length"),
        ] {
            for len in range {
                let error = decode(&layout, &bytes[..len]).unwrap_err();
                assert!(
                    error.to_string().contains(&format!("{field} is truncated")),
                    "{error:?}"
                );
            }
        }
    }

    #[test]
    fn transport_blob_rejects_truncated_ring_images() {
        let (layout, snapshot) = transport_snapshot();
        let bytes = encode(&snapshot).unwrap();

        for len in HEADER_LEN..bytes.len() {
            let error = decode(&layout, &bytes[..len]).unwrap_err();
            assert!(error.to_string().contains("does not match"), "{error:?}");
        }
    }

    #[test]
    fn transport_blob_rejects_trailing_bytes() {
        let (layout, snapshot) = transport_snapshot();
        let mut bytes = encode(&snapshot).unwrap();
        bytes.push(3);

        assert!(
            decode(&layout, &bytes)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
    }

    #[test]
    fn transport_blob_rejects_length_overflow() {
        for (g2h_len, h2g_len) in [(usize::MAX, 0), (0, usize::MAX)] {
            let (layout, snapshot) = transport_snapshot();
            let mut bytes = encode(&snapshot).unwrap();
            bytes[24..32].copy_from_slice(&(g2h_len as u64).to_le_bytes());
            bytes[32..40].copy_from_slice(&(h2g_len as u64).to_le_bytes());

            let error = decode(&layout, &bytes).unwrap_err();
            assert!(error.to_string().contains("length overflow"), "{error:?}");
        }
    }

    #[test]
    fn transport_blob_rejects_layout_mismatch() {
        let (layout, snapshot) = transport_snapshot();
        let mut bytes = encode(&snapshot).unwrap();
        bytes[16..24].copy_from_slice(&(snapshot.scratch_size() as u64 + 1).to_le_bytes());

        let error = decode(&layout, &bytes).unwrap_err();
        assert!(error.to_string().contains("scratch size"), "{error}");

        bytes[16..24].copy_from_slice(&(snapshot.scratch_size() as u64).to_le_bytes());
        bytes[24..32].copy_from_slice(&(snapshot.g2h_ring().len() as u64 - 1).to_le_bytes());
        bytes[32..40].copy_from_slice(&(snapshot.h2g_ring().len() as u64 + 1).to_le_bytes());

        let error = decode(&layout, &bytes).unwrap_err();
        assert!(error.to_string().contains("ring lengths"), "{error}");
    }

    #[test]
    fn transport_blob_rejects_noncanonical_rings() {
        let (layout, snapshot) = transport_snapshot();
        let mut bytes = encode(&snapshot).unwrap();
        bytes[HEADER_LEN] = 1;

        let error = decode(&layout, &bytes).unwrap_err();
        assert!(
            error.to_string().contains("invalid canonical G2H image"),
            "{error}"
        );

        bytes[HEADER_LEN] = 0;
        let h2g_offset = HEADER_LEN + snapshot.g2h_ring().len();
        bytes[h2g_offset..].fill(0);

        let error = decode(&layout, &bytes).unwrap_err();
        assert!(
            error.to_string().contains("invalid canonical H2G image"),
            "{error}"
        );
    }

    /// Valid framing cannot admit metadata aliases or duplicate receive slots.
    #[test]
    fn transport_blob_rejects_h2g_buffer_addresses() {
        let case = TestCase::new();
        let layout = memory_layout();
        let snapshot = VirtqSnapshot::capture(&layout, &case.scratch).unwrap();

        let mut bytes = encode(&snapshot).unwrap();
        let addr_offset = HEADER_LEN + snapshot.g2h_ring().len() + Descriptor::ADDR_OFFSET;

        let ring_addr = case.g2h_layout.desc_table_addr();
        bytes[addr_offset..addr_offset + size_of::<u64>()]
            .copy_from_slice(&ring_addr.to_le_bytes());

        let err = decode(&layout, &bytes).unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("invalid canonical H2G image"), "{msg}");
        assert!(err.to_string().contains("buffer"), "{err}");

        let duplicate_addr = case.h2g_desc(1).addr;
        bytes[addr_offset..addr_offset + size_of::<u64>()]
            .copy_from_slice(&duplicate_addr.to_le_bytes());

        let err = decode(&layout, &bytes).unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("invalid canonical H2G image"), "{msg}");
        assert!(msg.contains("buffer"), "{err}");
    }
}
