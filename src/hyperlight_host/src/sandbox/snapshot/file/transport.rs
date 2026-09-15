// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

//! Binary framing for the snapshot's ring-image layer.
//!
//! [`VirtqSnapshot::preflight`] validates ring contents against the finalized layout.

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

/// Decode framing. The returned rings still require layout validation.
pub(super) fn decode(bytes: &[u8]) -> crate::Result<VirtqSnapshot> {
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

    Ok(VirtqSnapshot::new(
        scratch_size,
        g2h_ring.to_vec(),
        h2g_ring.to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_blob_round_trips() {
        let snapshot = VirtqSnapshot::new(0x0102_0304, vec![1, 2, 3], vec![4, 5]);
        let expected = [
            b'H', b'L', b'V', b'Q', b'S', b'N', b'A', b'P', // Magic.
            1, 0, 0, 0, // Version.
            0, 0, 0, 0, // Reserved.
            4, 3, 2, 1, 0, 0, 0, 0, // Scratch size.
            3, 0, 0, 0, 0, 0, 0, 0, // G2H length.
            2, 0, 0, 0, 0, 0, 0, 0, // H2G length.
            1, 2, 3, // G2H image.
            4, 5, // H2G image.
        ];

        assert_eq!(encode(&snapshot).unwrap(), expected);
        assert_eq!(decode(&expected).unwrap(), snapshot);
    }

    #[test]
    fn transport_blob_round_trips_empty_rings() {
        let snapshot = VirtqSnapshot::new(0x20_000, vec![], vec![]);
        let bytes = encode(&snapshot).unwrap();

        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(decode(&bytes).unwrap(), snapshot);
    }

    #[test]
    fn transport_blob_rejects_invalid_magic() {
        let snapshot = VirtqSnapshot::new(0x20_000, vec![1], vec![2]);
        let mut bytes = encode(&snapshot).unwrap();
        bytes[0] ^= 1;

        assert!(
            decode(&bytes)
                .unwrap_err()
                .to_string()
                .contains("magic is invalid")
        );
    }

    #[test]
    fn transport_blob_rejects_version_mismatch() {
        let snapshot = VirtqSnapshot::new(0x20_000, vec![1], vec![2]);
        let mut bytes = encode(&snapshot).unwrap();
        bytes[8..12].copy_from_slice(&VERSION.wrapping_add(1).to_le_bytes());

        assert!(
            decode(&bytes)
                .unwrap_err()
                .to_string()
                .contains("version mismatch")
        );
    }

    #[test]
    fn transport_blob_rejects_nonzero_reserved_field() {
        let snapshot = VirtqSnapshot::new(0x20_000, vec![1], vec![2]);
        let mut bytes = encode(&snapshot).unwrap();
        bytes[12] = 1;

        assert!(
            decode(&bytes)
                .unwrap_err()
                .to_string()
                .contains("reserved field is nonzero")
        );
    }

    #[test]
    fn transport_blob_rejects_truncated_header_fields() {
        let snapshot = VirtqSnapshot::new(0x20_000, vec![1], vec![2]);
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
                let error = decode(&bytes[..len]).unwrap_err();
                assert!(
                    error.to_string().contains(&format!("{field} is truncated")),
                    "{error:?}"
                );
            }
        }
    }

    #[test]
    fn transport_blob_rejects_truncated_ring_images() {
        let snapshot = VirtqSnapshot::new(0x20_000, vec![1, 2, 3], vec![4, 5]);
        let bytes = encode(&snapshot).unwrap();

        for len in HEADER_LEN..bytes.len() {
            let error = decode(&bytes[..len]).unwrap_err();
            assert!(error.to_string().contains("does not match"), "{error:?}");
        }
    }

    #[test]
    fn transport_blob_rejects_trailing_bytes() {
        let snapshot = VirtqSnapshot::new(0x20_000, vec![1], vec![2]);
        let mut bytes = encode(&snapshot).unwrap();
        bytes.push(3);

        assert!(
            decode(&bytes)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
    }

    #[test]
    fn transport_blob_rejects_length_overflow() {
        for (g2h_len, h2g_len) in [(usize::MAX, 0), (0, usize::MAX)] {
            let snapshot = VirtqSnapshot::new(0x20_000, vec![], vec![]);
            let mut bytes = encode(&snapshot).unwrap();
            bytes[24..32].copy_from_slice(&(g2h_len as u64).to_le_bytes());
            bytes[32..40].copy_from_slice(&(h2g_len as u64).to_le_bytes());

            let error = decode(&bytes).unwrap_err();
            assert!(error.to_string().contains("length overflow"), "{error:?}");
        }
    }

    #[test]
    fn transport_blob_accepts_size_limit() {
        let snapshot = VirtqSnapshot::new(
            0x20_000,
            vec![1; MAX_BLOB_SIZE as usize - HEADER_LEN - 1],
            vec![2],
        );
        let bytes = encode(&snapshot).unwrap();

        assert_eq!(bytes.len(), 2 * 1024 * 1024);
        assert_eq!(decode(&bytes).unwrap(), snapshot);
    }

    #[test]
    fn transport_blob_rejects_size_over_limit() {
        let snapshot = VirtqSnapshot::new(
            0x20_000,
            vec![1; MAX_BLOB_SIZE as usize - HEADER_LEN],
            vec![2],
        );
        let error = encode(&snapshot).unwrap_err();
        assert!(error.to_string().contains("exceeds"), "{error:?}");
    }
}
