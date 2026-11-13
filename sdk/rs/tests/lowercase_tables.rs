//! Generates the lowercase tables of the TypeScript SDK from the standard library and checks them.
//!
//! The TypeScript SDK computes the `lower` function of a Reduce in the page from tables it ships,
//! and must give what `str::to_lowercase` gives. The tables follow the Unicode version of the
//! standard library that generated them, and they name that version. Two checks keep them right:
//!
//! - The tables carry a digest of `str::to_lowercase` over every scalar value. The tests of the
//!   TypeScript SDK compute the same digest from the tables on every run, whatever Unicode version
//!   their runtime has.
//! - The test here compares the whole file with what the standard library generates. It compares
//!   only under a standard library of the tables' Unicode version and passes without comparing
//!   under any other.
//!
//! The tables move to another Unicode version only when this command writes them anew, and the
//! toolchain it runs with decides the version. The command runs the ignored test
//! `regenerate_lowercase_tables`:
//!
//! ```text
//! cargo test -p exoware-sdk --test lowercase_tables -- --ignored regenerate_lowercase_tables
//! ```

use std::path::{Path, PathBuf};

/// The TypeScript SDK's lowercase tables, relative to this crate's manifest directory.
const TABLES: &str = "../ts/src/indexeddb/reduce/lowercase-tables.ts";

/// The command that writes the tables anew.
const REGENERATE: &str =
    "cargo test -p exoware-sdk --test lowercase_tables -- --ignored regenerate_lowercase_tables";

/// The capital sigma. Its lowercase form depends on the scalar values around it.
const SIGMA: char = '\u{3a3}';

/// The final sigma. A capital sigma lowers to it or to the small sigma, by the rule that
/// `is_cased` states.
const FINAL_SIGMA: char = '\u{3c2}';

/// Every scalar value, in ascending order.
fn scalars() -> impl Iterator<Item = char> {
    (0..=u32::from(char::MAX)).filter_map(char::from_u32)
}

/// Whether `str::to_lowercase` counts a scalar value as a cased letter when it lowers a capital
/// sigma. A value counts when it is cased and not case ignorable.
///
/// A capital sigma becomes the final sigma when, with case ignorable scalar values skipped, a cased
/// letter stands before it and none stands after it. After a lone scalar value it is therefore
/// final exactly when that value counts.
fn is_cased(c: char) -> bool {
    format!("{c}{SIGMA}").to_lowercase().ends_with(FINAL_SIGMA)
}

/// Whether `str::to_lowercase` skips a scalar value as case ignorable.
///
/// In `A{SIGMA}{c}A` the sigma is final exactly when `c` is neither skipped nor cased. So a `c`
/// that leaves the sigma not final and that `is_cased` rejects is skipped.
fn is_ignorable(c: char) -> bool {
    let neither = format!("A{SIGMA}{c}A").to_lowercase().chars().nth(1) == Some(FINAL_SIGMA);
    !neither && !is_cased(c)
}

/// A digest of `str::to_lowercase` over every scalar value.
///
/// Every scalar value c, in ascending order, gives seven texts: c, cS, Sc, AcS, ASc, AcSA and AScA,
/// where S is the capital sigma and A the letter A. Each text is lowered on its own and followed by
/// a line feed. The digest is the 32 bit FNV-1a hash of the UTF-16 code units of the lowered texts
/// and their line feeds.
fn digest() -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for c in scalars() {
        let texts = [
            format!("{c}"),
            format!("{c}{SIGMA}"),
            format!("{SIGMA}{c}"),
            format!("A{c}{SIGMA}"),
            format!("A{SIGMA}{c}"),
            format!("A{c}{SIGMA}A"),
            format!("A{SIGMA}{c}A"),
        ];
        for text in texts {
            for unit in text.to_lowercase().encode_utf16().chain([0x0a]) {
                hash = (hash ^ u32::from(unit)).wrapping_mul(0x0100_0193);
            }
        }
    }
    hash
}

/// The scalar values of a set as ranges, each a pair of its first and last value.
fn ranges_of(member: impl Fn(char) -> bool) -> Vec<(u32, u32)> {
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for c in scalars().filter(|&c| member(c)).map(u32::from) {
        match ranges.last_mut() {
            Some(last) if last.1 + 1 == c => last.1 = c,
            _ => ranges.push((c, c)),
        }
    }
    ranges
}

/// Formats array entries as lines of TypeScript source, `per_line` entries to a line.
fn lines(entries: Vec<String>, per_line: usize) -> String {
    entries
        .chunks(per_line)
        .map(|line| format!("    {},\n", line.join(", ")))
        .collect()
}

/// Generates the TypeScript source of the tables from the standard library.
fn generate() -> String {
    // Collect the scalar values whose lowercase form is one other scalar value, and those whose
    // form is two.
    let mut single: Vec<(u32, i64)> = Vec::new();
    let mut expansions: Vec<String> = Vec::new();
    for c in scalars() {
        let lower: Vec<u32> = c.to_lowercase().map(u32::from).collect();
        match lower[..] {
            [same] if same == u32::from(c) => {}
            [other] => single.push((u32::from(c), i64::from(other) - i64::from(u32::from(c)))),
            [first, second] => {
                expansions.push(format!("{:#x}, {first:#x}, {second:#x}", u32::from(c)))
            }
            _ => panic!("the lowercase form of {c:?} must be at most two scalar values"),
        }
    }

    // Group the one-value forms into runs. A run holds scalar values a step of 1 or 2 apart that
    // share the distance to their lowercase form.
    let mut runs: Vec<String> = Vec::new();
    let mut next = 0;
    while next < single.len() {
        let (first, distance) = single[next];
        let follows =
            |at: usize, step: u32, last: u32| single.get(at) == Some(&(last + step, distance));
        let step = if follows(next + 1, 1, first) { 1 } else { 2 };
        let mut last = first;
        next += 1;
        while follows(next, step, last) {
            last += step;
            next += 1;
        }
        let step = if last == first { 1 } else { step };
        runs.push(format!("{first:#x}, {last:#x}, {step}, {distance}"));
    }

    let pairs = |ranges: Vec<(u32, u32)>| {
        let entries = ranges
            .iter()
            .map(|(first, last)| format!("{first:#x}, {last:#x}"));
        lines(entries.collect(), 6)
    };
    let (major, minor, patch) = char::UNICODE_VERSION;
    format!(
        r"/**
 * The lowercase mapping of Unicode {major}.{minor}.{patch} as the service applies it to text.
 *
 * This file is generated from the Rust standard library, and the service computes lower with its
 * str::to_lowercase. LOWERCASE_RUNS and LOWERCASE_EXPANSIONS hold char::to_lowercase of every
 * scalar value that it changes. CASE_IGNORABLE and CASED are the two sets that decide the lowercase
 * form of a capital sigma. They are read off str::to_lowercase on texts that put each scalar value
 * next to a capital sigma. Do not edit this file by hand.
 *
 * Two checks keep the file right. The tests of this package compute LOWERCASE_DIGEST from the
 * tables on every run. The test sdk/rs/tests/lowercase_tables.rs compares the whole file with what
 * the standard library generates whenever that library has the Unicode version named here.
 *
 * The tables move to another Unicode version only when this command writes them anew, and the
 * toolchain it runs with decides the version. Run it inside the repository:
 *
 *     {REGENERATE}
 */

/** The Unicode version of the tables. */
export const UNICODE_VERSION = '{major}.{minor}.{patch}';

/**
 * A digest of str::to_lowercase over every scalar value. The lowercase forms computed from the
 * tables must reproduce it. Every scalar value c, in ascending order, gives seven texts: c, cS, Sc,
 * AcS, ASc, AcSA and AScA, where S is the capital sigma and A the letter A. Each text is lowered on
 * its own and followed by a line feed. The digest is the 32 bit FNV-1a hash of the UTF-16 code
 * units of the lowered texts and their line feeds.
 */
export const LOWERCASE_DIGEST = {digest:#010x};

/**
 * The scalar values whose lowercase form is one other scalar value, in runs. A run is four numbers:
 * its first and last scalar value, the step between its members, and the distance from a member to
 * its lowercase form.
 */
export const LOWERCASE_RUNS: readonly number[] = [
{runs}];

/**
 * The scalar values whose lowercase form is two scalar values. An entry is three numbers: the
 * scalar value and the two of its lowercase form.
 */
export const LOWERCASE_EXPANSIONS: readonly number[] = [
{expansions}];

/**
 * The scalar values that the rule for a capital sigma skips when it looks for a cased letter on
 * either side, as pairs of the first and the last scalar value of a range.
 */
export const CASE_IGNORABLE: readonly number[] = [
{ignorable}];

/**
 * The scalar values that the rule for a capital sigma counts as a cased letter and does not skip,
 * as pairs of the first and the last scalar value of a range. A cased scalar value that is also
 * case ignorable is skipped, so it is in CASE_IGNORABLE alone.
 */
export const CASED: readonly number[] = [
{cased}];
",
        runs = lines(runs, 4),
        expansions = lines(expansions, 4),
        digest = digest(),
        ignorable = pairs(ranges_of(is_ignorable)),
        cased = pairs(ranges_of(is_cased)),
    )
}

fn path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(TABLES)
}

fn tables() -> String {
    std::fs::read_to_string(path())
        .unwrap_or_else(|e| panic!("{} must be readable: {e}", path().display()))
}

/// The Unicode version that the tables name. It must be three numbers separated by dots.
fn named_version(source: &str) -> (u8, u8, u8) {
    let declaration = "export const UNICODE_VERSION = '";
    let start = source
        .find(declaration)
        .expect("the tables must export UNICODE_VERSION")
        + declaration.len();
    let end = source[start..]
        .find('\'')
        .expect("UNICODE_VERSION must end with a quote");
    let named = &source[start..start + end];
    let numbers: Option<Vec<u8>> = named
        .split('.')
        .map(|number| {
            let digits = number.bytes().all(|byte| byte.is_ascii_digit());
            number.parse().ok().filter(|_| digits)
        })
        .collect();
    match numbers.as_deref() {
        Some(&[major, minor, patch]) => (major, minor, patch),
        _ => panic!("UNICODE_VERSION must be three numbers separated by dots, not {named:?}"),
    }
}

#[test]
fn tables_are_what_the_standard_library_generates() {
    let source = tables();
    let named = named_version(&source);
    if named != char::UNICODE_VERSION {
        let dotted = |(major, minor, patch): (u8, u8, u8)| format!("{major}.{minor}.{patch}");
        println!(
            "{TABLES} follows Unicode {} and the standard library has Unicode {}, so the two are \
            not compared",
            dotted(named),
            dotted(char::UNICODE_VERSION)
        );
        return;
    }
    assert!(
        source == generate(),
        "{TABLES} must match what the standard library generates. Write it anew with: {REGENERATE}"
    );
}

/// Writes the tables anew from the standard library of the toolchain.
#[test]
#[ignore = "rewrites the lowercase tables of the TypeScript SDK"]
fn regenerate_lowercase_tables() {
    std::fs::write(path(), generate())
        .unwrap_or_else(|e| panic!("{} must be writable: {e}", path().display()));
}
