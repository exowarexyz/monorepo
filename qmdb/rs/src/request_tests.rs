//! Request constraint tests, kept outside `request.rs` so the WASM include compiles them once

use crate::request::{span_contains, validate_key_range, InvalidWindow, OperationWindow};

#[test]
fn spans_wrap_past_the_greatest_key() {
    assert!(span_contains(&2, &6, &2));
    assert!(span_contains(&2, &6, &5));
    assert!(!span_contains(&2, &6, &6));
    assert!(!span_contains(&2, &6, &1));
    assert!(span_contains(&6, &2, &7));
    assert!(span_contains(&6, &2, &1));
    assert!(!span_contains(&6, &2, &2));
    assert!(!span_contains(&6, &2, &4));
    assert!(span_contains(&3, &3, &9));
}

#[test]
fn operation_windows_preserve_large_absolute_positions() {
    for start in [u32::MAX as u64 - 1, u32::MAX as u64 + 1, (1u64 << 53) + 1] {
        let window = OperationWindow::new(start + 2, start, 10).unwrap();
        assert!(window.validate(start, 3, start + 3).is_ok());
        assert!(window.validate(start + 1, 3, start + 3).is_err());
        assert!(window.validate(start, 2, start + 3).is_err());
        assert!(window.validate(start, 3, start + 4).is_err());
    }
    assert!(matches!(
        OperationWindow::new(u64::MAX, 0, 1),
        Err(InvalidWindow::TipOverflow)
    ));
    assert!(matches!(
        OperationWindow::new(10, 11, 1),
        Err(InvalidWindow::StartOutOfBounds {
            start: 11,
            count: 11
        })
    ));
    assert!(matches!(
        OperationWindow::new(10, 0, 0),
        Err(InvalidWindow::ZeroMaximum)
    ));
}

#[test]
fn linear_key_ranges_match_sorted_map_pages() {
    let keys = [2, 4, 6];
    for start in 0..9 {
        for end in (start + 1)..10 {
            for limit in 1..5 {
                let matching = keys
                    .iter()
                    .filter(|key| **key >= start && **key < end)
                    .collect::<Vec<_>>();
                let selected = matching
                    .iter()
                    .take(limit as usize)
                    .map(|key| {
                        let index = keys.iter().position(|candidate| candidate == *key).unwrap();
                        (*key, &keys[(index + 1) % keys.len()])
                    })
                    .collect::<Vec<_>>();
                let successor = keys.iter().find(|key| **key > start).or(keys.first());
                let more = matching.len() > limit as usize;
                let next = more.then(|| selected.last().unwrap().1);
                assert!(validate_key_range(
                    &start,
                    Some(&end),
                    limit,
                    &selected,
                    successor,
                    more,
                    next
                )
                .is_ok());
            }
        }
    }
}

#[test]
fn key_ranges_reject_wraparound_and_incomplete_pages() {
    assert!(validate_key_range(&1, Some(&7), 3, &[], Some(&2), false, None).is_err());
    assert!(validate_key_range(&1, Some(&7), 3, &[(&2, &4)], Some(&2), false, None).is_err());
    assert!(validate_key_range(
        &4,
        None,
        3,
        &[(&4, &6), (&6, &2), (&2, &4)],
        None,
        false,
        None
    )
    .is_err());
    assert!(validate_key_range(&4, Some(&6), 2, &[(&4, &6)], None, true, Some(&6)).is_err());
    assert!(validate_key_range(
        &1,
        Some(&7),
        1,
        &[(&2, &4), (&4, &6)],
        Some(&2),
        false,
        None
    )
    .is_err());
    // A complete page cannot carry a continuation
    assert!(validate_key_range(
        &1,
        Some(&7),
        3,
        &[(&2, &4), (&4, &6), (&6, &2)],
        Some(&2),
        false,
        Some(&2)
    )
    .is_err());
    // An empty-database start proof cannot precede entries
    assert!(validate_key_range(&1, Some(&7), 3, &[(&2, &4)], None, false, None).is_err());
    // The continuation must be the last entry's authenticated successor
    assert!(validate_key_range(&1, Some(&7), 1, &[(&2, &4)], Some(&2), true, Some(&5)).is_err());
}

#[test]
fn single_key_databases_accept_self_successors() {
    assert!(validate_key_range(&0, None, 5, &[(&3, &3)], Some(&3), false, None).is_ok());
    assert!(validate_key_range(&3, None, 5, &[(&3, &3)], None, false, None).is_ok());
    // A start above the only key wraps to it, so an empty page is complete
    assert!(validate_key_range(&4, None, 5, &[], Some(&3), false, None).is_ok());
    assert!(validate_key_range(&0, None, 5, &[(&3, &3)], Some(&3), true, Some(&3)).is_err());
}
