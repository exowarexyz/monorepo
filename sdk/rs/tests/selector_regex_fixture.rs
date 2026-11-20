//! Reads the selector regex fixture of the TypeScript SDK and checks it against the regex crate.
//! It does not write the fixture.
//!
//! The TypeScript SDK matches key selectors and value filters with its own engine for a subset of
//! the regex syntax. Its fixture records, for each pattern, whether the regex crate compiles it
//! and, if it does, its capture group names. For a pattern inside the subset it also records the
//! match and capture spans on every input. This test checks every recorded expectation against the
//! regex crate that this SDK depends on.

use regex::bytes::Regex;
use std::path::Path;

/// The TypeScript SDK's regex fixture, relative to this crate's manifest directory.
const FIXTURE: &str = "../ts/__tests__/fixtures/selector-regex.txt";

fn unhex(hex: &str) -> Vec<u8> {
    assert!(
        hex.len().is_multiple_of(2),
        "hex {hex:?} must have an even length"
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex must hold only hex digits"))
        .collect()
}

/// Describes the leftmost-first match in the fixture's result format.
fn describe(regex: &Regex, input: &[u8]) -> String {
    let Some(captures) = regex.captures(input) else {
        return "N".to_string();
    };
    let spans: Vec<String> = (0..captures.len())
        .map(|i| match captures.get(i) {
            Some(m) => format!("{}-{}", m.start(), m.end()),
            None => "x".to_string(),
        })
        .collect();
    format!("M{}", spans.join(","))
}

#[test]
fn fixture_matches_the_regex_crate() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display()));
    let mut records = text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_once(' ').unwrap_or((line, "")));
    let mut inputs = Vec::new();
    let mut patterns = 0;
    while let Some((tag, payload)) = records.next() {
        if tag == "H" {
            inputs.push(unhex(payload));
            continue;
        }
        assert_eq!(tag, "P", "record {tag} must be H or P");
        patterns += 1;
        let pattern = String::from_utf8(unhex(payload)).expect("pattern must be UTF-8");
        let (status, names) = records.next().expect("a status line must follow a pattern");
        let compiled = Regex::new(&pattern);
        if status == "ERR" {
            assert!(compiled.is_err(), "{pattern:?} must not compile");
            continue;
        }
        assert!(
            status == "OK" || status == "UNSUPPORTED",
            "status {status} must be OK, UNSUPPORTED or ERR"
        );
        let regex = compiled.unwrap_or_else(|e| panic!("{pattern:?} must compile: {e}"));
        let actual: Vec<&str> = regex.capture_names().map(|n| n.unwrap_or("")).collect();
        assert_eq!(
            actual.join(","),
            names,
            "capture names of {pattern:?} must match the fixture"
        );
        if status == "UNSUPPORTED" {
            continue;
        }
        let (tag, results) = records.next().expect("a results line must follow OK");
        assert_eq!(tag, "R", "a results line must follow OK for {pattern:?}");
        let results: Vec<&str> = results.split(' ').collect();
        assert_eq!(
            results.len(),
            inputs.len(),
            "{pattern:?} must have one result per input"
        );
        for (input, expected) in inputs.iter().zip(results) {
            assert_eq!(
                regex.is_match(input),
                expected != "N",
                "is_match of {pattern:?} on {input:02x?} must match the fixture"
            );
            assert_eq!(
                describe(&regex, input),
                expected,
                "captures of {pattern:?} on {input:02x?} must match the fixture"
            );
        }
    }
    assert!(patterns > 0, "{} must hold a pattern", path.display());
}
