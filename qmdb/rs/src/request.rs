//! Request constraints shared by native and browser proof consumers

#[derive(Clone, Copy)]
pub(crate) struct OperationWindow {
    leaves: u64,
    start: u64,
    count: u64,
}

impl OperationWindow {
    pub(crate) fn new(tip: u64, start: u64, maximum: u32) -> Result<Self, &'static str> {
        let leaves = tip.checked_add(1).ok_or("operation tip overflow")?;
        if start >= leaves || maximum == 0 {
            return Err("invalid requested operation window");
        }
        Ok(Self {
            leaves,
            start,
            count: (leaves - start).min(u64::from(maximum)),
        })
    }

    pub(crate) fn validate(
        self,
        start: u64,
        count: usize,
        leaves: u64,
    ) -> Result<(), &'static str> {
        if start != self.start
            || u64::try_from(count).ok() != Some(self.count)
            || leaves != self.leaves
        {
            return Err("operation proof does not match requested window");
        }
        Ok(())
    }
}

/// Entries and the start exclusion's successor must already be authenticated
pub(crate) fn validate_key_range<K: Ord>(
    start: &K,
    end: Option<&K>,
    limit: u32,
    entries: &[(&K, &K)],
    start_successor: Option<&K>,
    has_more: bool,
    next_start: Option<&K>,
) -> Result<(), &'static str> {
    if limit == 0 || end.is_some_and(|end| end <= start) || entries.len() > limit as usize {
        return Err("invalid key range bounds or entry count");
    }
    for &(key, _) in entries {
        if key < start || end.is_some_and(|end| key >= end) {
            return Err("key range entry lies outside requested interval");
        }
    }
    for pair in entries.windows(2) {
        if pair[0].0 >= pair[1].0 || pair[0].1 != pair[1].0 {
            return Err("key range entries are not strictly ordered successors");
        }
    }
    if let Some(&(first, _)) = entries.first() {
        if first != start && start_successor != Some(first) {
            return Err("key range start proof does not reach first entry");
        }
    } else if start_successor.is_some_and(|next| next > start && end.is_none_or(|end| next < end)) {
        return Err("empty key range omits an in-range successor");
    }
    match entries.last() {
        Some(&(last, next)) if has_more => {
            if entries.len() != limit as usize
                || next <= last
                || end.is_some_and(|end| next >= end)
                || next_start != Some(next)
            {
                return Err("key range continuation does not advance within requested interval");
            }
        }
        Some(&(last, next)) => {
            if next > last && end.is_none_or(|end| next < end) {
                return Err("key range stops before an in-range successor");
            }
        }
        None if has_more => return Err("empty key range cannot have a continuation"),
        None => {}
    }
    if !has_more && next_start.is_some() {
        return Err("complete key range has an unexpected continuation");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_windows_preserve_large_absolute_positions() {
        for start in [u32::MAX as u64 - 1, u32::MAX as u64 + 1, (1u64 << 53) + 1] {
            let window = OperationWindow::new(start + 2, start, 10).unwrap();
            assert!(window.validate(start, 3, start + 3).is_ok());
            assert!(window.validate(start + 1, 3, start + 3).is_err());
            assert!(window.validate(start, 2, start + 3).is_err());
            assert!(window.validate(start, 3, start + 4).is_err());
        }
        assert!(OperationWindow::new(u64::MAX, 0, 1).is_err());
        assert!(OperationWindow::new(10, 11, 1).is_err());
        assert!(OperationWindow::new(10, 0, 0).is_err());
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
                            let index =
                                keys.iter().position(|candidate| candidate == *key).unwrap();
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
    }
}
