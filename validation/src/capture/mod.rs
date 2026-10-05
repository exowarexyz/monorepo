//! Capture issued batches and load portable workload bundles.

mod bundle;
mod generate;
mod profile;
mod reader;
mod recorder;
mod stats;

pub use generate::Generator;
pub use profile::{Domain, Endian, Family, Offset, Patch, Profile, Target};
pub use reader::FileGenerator;
pub use recorder::{Limits, Recorder};
pub use stats::{Statistics, StatisticsSnapshot};

use bytes::Bytes;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub family: u32,
    pub key: Bytes,
    pub value: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub offset_ns: u64,
    pub rows: Vec<Row>,
}

#[derive(Clone, Debug)]
pub struct Bundle {
    pub profile: Profile,
    pub source: BTreeMap<String, String>,
    pub repeat_period_ns: u64,
    pub batches: Vec<Batch>,
}
