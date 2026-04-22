use std::collections::BTreeMap;

use commonware_storage::mmr::Location;

/// Family an incoming key belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Op,
    Presence,
    Watermark,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosedBatch {
    pub start: Location,
    pub latest: Location,
    pub sequence_number: u64,
    /// Snapshot of the watermark in force at drain time.
    pub watermark: Location,
    /// Store sequence number that makes this batch readable end-to-end.
    pub read_floor_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InProgressBatch {
    start: Location,
    next_expected: Location,
}

/// Pure batch assembler used by QMDB stream adapters.
///
/// Feed it per-entry `(family, location, sequence_number)` observations from
/// store stream frames; it drains fully-authorized batches once both the batch
/// presence row and a covering watermark have been observed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Accumulator {
    in_progress: BTreeMap<Location, InProgressBatch>,
    pending: BTreeMap<Location, ClosedBatch>,
    watermarks: BTreeMap<Location, u64>,
}

impl Accumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ingest_entry(&mut self, family: Family, location: Location, sequence_number: u64) {
        match family {
            Family::Op => {
                let key = self
                    .in_progress
                    .iter()
                    .find_map(|(start, batch)| (batch.next_expected == location).then_some(*start));
                match key {
                    Some(start) => {
                        self.in_progress.get_mut(&start).unwrap().next_expected += 1;
                    }
                    None => {
                        self.in_progress.insert(
                            location,
                            InProgressBatch {
                                start: location,
                                next_expected: location + 1,
                            },
                        );
                    }
                }
            }
            Family::Presence => {
                let key = self.in_progress.iter().find_map(|(start, batch)| {
                    (batch.next_expected == location + 1).then_some(*start)
                });
                if let Some(start) = key {
                    let in_progress = self.in_progress.remove(&start).unwrap();
                    self.pending.insert(
                        location,
                        ClosedBatch {
                            start: in_progress.start,
                            latest: location,
                            sequence_number,
                            watermark: Location::new(0),
                            read_floor_sequence: 0,
                        },
                    );
                }
            }
            Family::Watermark => {
                self.watermarks.entry(location).or_insert(sequence_number);
            }
        }
    }

    /// Drain every pending batch whose latest location is covered by an observed watermark.
    pub fn drain_ready(&mut self) -> Vec<ClosedBatch> {
        let mut ready = Vec::new();
        while let Some((&latest, _)) = self.pending.iter().next() {
            let Some((&watermark, &watermark_sequence)) = self.watermarks.range(latest..).next()
            else {
                break;
            };
            let (_, mut batch) = self.pending.pop_first().unwrap();
            batch.watermark = watermark;
            batch.read_floor_sequence = batch.sequence_number.max(watermark_sequence);
            ready.push(batch);
        }
        if let Some(&floor) = self
            .pending
            .keys()
            .next()
            .or_else(|| self.watermarks.keys().next_back())
        {
            self.watermarks = self.watermarks.split_off(&floor);
        }
        ready
    }

    pub fn has_watermark(&self, location: Location) -> bool {
        self.watermarks.contains_key(&location)
    }
}
