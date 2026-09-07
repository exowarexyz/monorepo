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

/// Whether `key` lies in the cyclic span from an active key to its successor
pub(crate) fn span_contains<K: Ord>(start: &K, end: &K, key: &K) -> bool {
    if start >= end {
        key >= start || key < end
    } else {
        key >= start && key < end
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
