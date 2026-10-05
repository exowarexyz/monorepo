use std::{collections::BTreeMap, path::PathBuf};

use bytes::Bytes;
use exoware_validation::capture::{
    Batch, Bundle, Domain, Endian, Family, Offset, Patch, Profile, Row, Target,
};

fn main() -> anyhow::Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: capture_fixture <new-directory>"))?;
    let profile = Profile {
        version: 1,
        domains: BTreeMap::from([("location".into(), Domain::Numeric { width: 8 })]),
        families: vec![Family {
            id: 1,
            name: "locations".into(),
            key_prefix_hex: "aa".into(),
            fresh_key: 0,
            patches: vec![Patch {
                target: Target::Key,
                offset: Offset::End(8),
                domain: "location".into(),
                endian: Endian::Big,
            }],
        }],
    };
    let row = |location: u64, value: &'static [u8]| {
        let mut key = vec![0xaa];
        key.extend_from_slice(&location.to_be_bytes());
        Row {
            family: 1,
            key: key.into(),
            value: Bytes::from_static(value),
        }
    };
    Bundle {
        profile,
        source: BTreeMap::from([("fixture".into(), "synthetic-example-v1".into())]),
        repeat_period_ns: 100_000_000,
        batches: vec![
            Batch {
                offset_ns: 0,
                rows: vec![row(100, b"first"), row(101, b"second")],
            },
            Batch {
                offset_ns: 25_000_000,
                rows: vec![row(102, b"third")],
            },
        ],
    }
    .write(path)
}
