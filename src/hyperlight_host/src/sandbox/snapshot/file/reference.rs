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

//! Validated identifiers for snapshots stored in an OCI Image Layout:
//! a human-readable tag, a content digest, and the reference enum that
//! selects a manifest by either one.

use std::fmt;
use std::str::FromStr;

use oci_spec::image::{Digest as OciSpecDigest, DigestAlgorithm};

/// A tag naming one snapshot inside an OCI Image Layout directory.
/// Used to save a snapshot under a name and to load it back by that
/// same name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OciTag(String);

impl OciTag {
    /// Construct a tag, validating it against the OCI Distribution
    /// grammar `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`. Returns an error
    /// if the input does not match.
    pub fn new(tag: impl Into<String>) -> crate::Result<Self> {
        Self::try_from(tag.into())
    }

    /// The tag as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_tag(tag: &str) -> crate::Result<()> {
    let bytes = tag.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return Err(crate::new_error!(
            "tag {:?} is invalid: must be 1..=128 bytes",
            tag
        ));
    }
    let first = bytes[0];
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return Err(crate::new_error!(
            "tag {:?} is invalid: first character must be alphanumeric or '_'",
            tag
        ));
    }
    for &b in &bytes[1..] {
        if !(b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-') {
            return Err(crate::new_error!(
                "tag {:?} is invalid: characters after the first must be \
                 alphanumeric or one of '_', '.', '-'",
                tag
            ));
        }
    }
    Ok(())
}

impl FromStr for OciTag {
    type Err = crate::HyperlightError;

    fn from_str(s: &str) -> crate::Result<Self> {
        validate_tag(s)?;
        Ok(Self(s.to_string()))
    }
}

impl TryFrom<&str> for OciTag {
    type Error = crate::HyperlightError;

    fn try_from(s: &str) -> crate::Result<Self> {
        s.parse()
    }
}

impl TryFrom<String> for OciTag {
    type Error = crate::HyperlightError;

    fn try_from(s: String) -> crate::Result<Self> {
        validate_tag(&s)?;
        Ok(Self(s))
    }
}

impl AsRef<str> for OciTag {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OciTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A sha256 content digest in canonical `sha256:<64 lowercase hex>`
/// form, identifying one snapshot by the bytes of its manifest.
/// Names that snapshot for loading even when no tag points at it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OciDigest(String);

impl OciDigest {
    /// The digest as a `sha256:<hex>` string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Wrap a validated `oci-spec` digest. The caller guarantees it
    /// uses the sha256 algorithm.
    pub(super) fn from_oci_spec_digest(digest: &OciSpecDigest) -> Self {
        Self(digest.to_string())
    }
}

fn validate_digest(s: &str) -> crate::Result<String> {
    let digest = OciSpecDigest::from_str(s)
        .map_err(|e| crate::new_error!("invalid OCI digest {:?}: {}", s, e))?;
    if digest.algorithm() != &DigestAlgorithm::Sha256 {
        return Err(crate::new_error!(
            "OCI digest {:?} must use the sha256 algorithm, found {}",
            s,
            digest.algorithm()
        ));
    }
    Ok(digest.to_string())
}

impl FromStr for OciDigest {
    type Err = crate::HyperlightError;

    fn from_str(s: &str) -> crate::Result<Self> {
        Ok(Self(validate_digest(s)?))
    }
}

impl TryFrom<&str> for OciDigest {
    type Error = crate::HyperlightError;

    fn try_from(s: &str) -> crate::Result<Self> {
        s.parse()
    }
}

impl TryFrom<String> for OciDigest {
    type Error = crate::HyperlightError;

    fn try_from(s: String) -> crate::Result<Self> {
        Ok(Self(validate_digest(&s)?))
    }
}

impl AsRef<str> for OciDigest {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OciDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Names one snapshot in an OCI Image Layout, either by tag or by
/// content digest.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum OciReference {
    /// A snapshot named by its tag.
    Tag(OciTag),
    /// A snapshot named by its content digest.
    Digest(OciDigest),
}

impl From<OciTag> for OciReference {
    fn from(tag: OciTag) -> Self {
        OciReference::Tag(tag)
    }
}

impl From<OciDigest> for OciReference {
    fn from(digest: OciDigest) -> Self {
        OciReference::Digest(digest)
    }
}

impl FromStr for OciReference {
    type Err = crate::HyperlightError;

    /// Parse a tag or a digest. A `:` marks a digest, since the tag
    /// grammar forbids that character.
    fn from_str(s: &str) -> crate::Result<Self> {
        if s.contains(':') {
            Ok(OciReference::Digest(s.parse()?))
        } else {
            Ok(OciReference::Tag(s.parse()?))
        }
    }
}

impl fmt::Display for OciReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OciReference::Tag(t) => fmt::Display::fmt(t, f),
            OciReference::Digest(d) => fmt::Display::fmt(d, f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 64-character lowercase hex string, the body of a canonical
    /// sha256 digest.
    const HEX64: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn tag_accepts_grammar_and_length_bounds() {
        // First character may be alphanumeric or underscore.
        assert!(OciTag::new("a").is_ok());
        assert!(OciTag::new("Z").is_ok());
        assert!(OciTag::new("9").is_ok());
        assert!(OciTag::new("_").is_ok());
        // Later characters add '.', '-'.
        assert!(OciTag::new("v1.0_release-2").is_ok());
        // 128 bytes is the maximum.
        assert!(OciTag::new("a".repeat(128)).is_ok());
    }

    #[test]
    fn tag_rejects_out_of_grammar_input() {
        // Empty and over-length.
        assert!(OciTag::new("").is_err());
        assert!(OciTag::new("a".repeat(129)).is_err());
        // First character cannot be '.', '-', or punctuation.
        assert!(OciTag::new(".tag").is_err());
        assert!(OciTag::new("-tag").is_err());
        // Later characters cannot include these.
        assert!(OciTag::new("a/b").is_err());
        assert!(OciTag::new("a b").is_err());
    }

    #[test]
    fn tag_never_contains_colon() {
        // The reference parser routes on ':'. A valid tag must never
        // carry one, otherwise a tag would be parsed as a digest.
        assert!(OciTag::new("sha256:abc").is_err());
    }

    #[test]
    fn digest_accepts_canonical_sha256() {
        let s = format!("sha256:{HEX64}");
        let d = OciDigest::try_from(s.as_str()).unwrap();
        assert_eq!(d.as_str(), s);
    }

    #[test]
    fn digest_rejects_non_sha256_algorithm() {
        let s = format!("sha512:{}", "0".repeat(128));
        assert!(OciDigest::try_from(s.as_str()).is_err());
    }

    #[test]
    fn digest_rejects_malformed_input() {
        // Missing algorithm prefix.
        assert!(OciDigest::try_from(HEX64).is_err());
        // Hex body of the wrong length.
        assert!(OciDigest::try_from("sha256:abcd").is_err());
    }

    #[test]
    fn reference_parses_tag_when_no_colon() {
        let r: OciReference = "latest".parse().unwrap();
        assert_eq!(r, OciReference::Tag(OciTag::new("latest").unwrap()));
    }

    #[test]
    fn reference_parses_digest_when_colon_present() {
        let s = format!("sha256:{HEX64}");
        let r: OciReference = s.parse().unwrap();
        assert_eq!(
            r,
            OciReference::Digest(OciDigest::try_from(s.as_str()).unwrap())
        );
    }

    #[test]
    fn tag_display_round_trips() {
        let tag = OciTag::new("v1.2-rc1").unwrap();
        assert_eq!(OciTag::new(tag.to_string()).unwrap(), tag);
    }

    #[test]
    fn digest_display_round_trips() {
        let d = OciDigest::try_from(format!("sha256:{HEX64}").as_str()).unwrap();
        assert_eq!(OciDigest::try_from(d.to_string().as_str()).unwrap(), d);
    }

    #[test]
    fn reference_display_round_trips() {
        let tag_ref: OciReference = "latest".parse().unwrap();
        assert_eq!(
            tag_ref.to_string().parse::<OciReference>().unwrap(),
            tag_ref
        );

        let digest_ref: OciReference = format!("sha256:{HEX64}").parse().unwrap();
        assert_eq!(
            digest_ref.to_string().parse::<OciReference>().unwrap(),
            digest_ref
        );
    }
}
