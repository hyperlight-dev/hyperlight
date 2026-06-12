use std::fmt::Write;
use std::ops::Range;

use ansi_replace::AnsiExt as _;
use ansi_replace::replacer::Writable;

/// Returns true if an output line is build noise that should be suppressed.
pub fn is_noisy_line(line: &str) -> bool {
    line.contains("waiting for file lock on")
        || line.contains("Gnuplot not found")
        || line.contains("`bench` profile [optimized]")
}

/// Strip the bench name from an output line.
///
/// Strategy:
/// - If the line starts with the bench name, replace it with spaces to preserve alignment
/// - Any other appearance of the bench name and surrounding whitespace are removed entirely
/// - ANSI codes are preserved in all cases
pub fn strip_bench_prefix(line: &str, bench: &str) -> String {
    let escaped = regex::escape(bench);
    let pattern = regex::Regex::new(&format!(r" ?{escaped}")).unwrap();

    let result = line.ansi_replace(&pattern, |m: &str, i: Range<usize>, dst: &mut Writable| {
        if i.start == 0 && m == bench {
            write!(dst, "{:n$}", " ", n = m.len())?;
        }
        Ok(())
    });

    if result.ansi_strip().trim().is_empty() {
        return String::new();
    }

    result
}
