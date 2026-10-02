//! Request constraints shared by native and browser proof consumers

/// A requested operation window that cannot be served regardless of the response
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InvalidWindow {
    TipOverflow,
    StartOutOfBounds { start: u64, count: u64 },
    ZeroMaximum,
}

impl core::fmt::Display for InvalidWindow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TipOverflow => f.write_str("operation tip overflow"),
            Self::StartOutOfBounds { start, count } => write!(
                f,
                "range proof start {start} is out of bounds for watermark with {count} leaves"
            ),
            Self::ZeroMaximum => f.write_str("range proof max_locations must be > 0"),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct OperationWindow {
    leaves: u64,
    start: u64,
    count: u64,
}

impl OperationWindow {
    pub(crate) fn new(tip: u64, start: u64, maximum: u32) -> Result<Self, InvalidWindow> {
        let leaves = tip.checked_add(1).ok_or(InvalidWindow::TipOverflow)?;
        if maximum == 0 {
            return Err(InvalidWindow::ZeroMaximum);
        }
        if start >= leaves {
            return Err(InvalidWindow::StartOutOfBounds {
                start,
                count: leaves,
            });
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

/// Maximum number of locations in one operations multi-proof request
pub(crate) const MAX_REQUESTED_LOCATIONS: usize = 1024;

/// Maximum number of entries in one key range proof request
pub(crate) const MAX_RANGE_LIMIT: u32 = 1000;

/// Requested operation locations that cannot be served regardless of the response
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InvalidLocations {
    TipOverflow,
    Empty,
    TooMany { count: usize },
    NotAscending { location: u64 },
    OutOfBounds { location: u64, count: u64 },
}

impl core::fmt::Display for InvalidLocations {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TipOverflow => f.write_str("operation tip overflow"),
            Self::Empty => f.write_str("operations request must contain at least one location"),
            Self::TooMany { count } => write!(
                f,
                "operations request has {count} locations, maximum is {MAX_REQUESTED_LOCATIONS}"
            ),
            Self::NotAscending { location } => write!(
                f,
                "operations request locations must be strictly ascending at {location}"
            ),
            Self::OutOfBounds { location, count } => write!(
                f,
                "requested location {location} is out of bounds for watermark with {count} leaves"
            ),
        }
    }
}

/// Requested locations for an operations multi-proof at one tip
pub(crate) struct OperationLocations<'a> {
    leaves: u64,
    locations: &'a [u64],
}

impl<'a> OperationLocations<'a> {
    pub(crate) fn new(tip: u64, locations: &'a [u64]) -> Result<Self, InvalidLocations> {
        let leaves = tip.checked_add(1).ok_or(InvalidLocations::TipOverflow)?;
        if locations.is_empty() {
            return Err(InvalidLocations::Empty);
        }
        if locations.len() > MAX_REQUESTED_LOCATIONS {
            return Err(InvalidLocations::TooMany {
                count: locations.len(),
            });
        }
        for pair in locations.windows(2) {
            if pair[0] >= pair[1] {
                return Err(InvalidLocations::NotAscending { location: pair[1] });
            }
        }
        let last = locations[locations.len() - 1];
        if last >= leaves {
            return Err(InvalidLocations::OutOfBounds {
                location: last,
                count: leaves,
            });
        }
        Ok(Self { leaves, locations })
    }

    /// A response must prove exactly the requested locations against the requested tip
    pub(crate) fn validate(
        &self,
        returned: impl ExactSizeIterator<Item = u64>,
        leaves: u64,
    ) -> Result<(), &'static str> {
        if leaves != self.leaves {
            return Err("operations proof does not match requested tip");
        }
        if returned.len() != self.locations.len()
            || !returned.zip(self.locations).all(|(got, want)| got == *want)
        {
            return Err("operations proof does not match requested locations");
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
pub(crate) fn validate_key_range<'a, K: Ord>(
    start: &K,
    end: Option<&K>,
    limit: u32,
    entries: &[(&'a K, &'a K)],
    start_successor: Option<&K>,
) -> Result<Option<&'a K>, &'static str> {
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
    if let Some(&(last, next)) = entries.last() {
        if next > last && end.is_none_or(|end| next < end) {
            if entries.len() != limit as usize {
                return Err("key range stops before an in-range successor");
            }
            return Ok(Some(next));
        }
    }
    Ok(None)
}
