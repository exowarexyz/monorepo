use std::{collections::BTreeMap, ops::Range};

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};

use super::profile::{Domain, Endian, Family, Offset, Patch, Target};
use super::{Batch, Bundle, Profile};

#[derive(Clone, Debug)]
pub struct Generator {
    bundle: Bundle,
    prepared: PreparedGenerator,
}

#[derive(Clone, Debug)]
pub(super) struct PreparedGenerator {
    profile: Profile,
    families: BTreeMap<u32, usize>,
    domains: BTreeMap<String, PreparedDomain>,
    max_pass: u64,
    seed: u64,
}

#[derive(Clone, Debug)]
enum PreparedDomain {
    Numeric { width: usize, span: u128 },
    Identity { width: usize },
}

pub(super) struct Preparation {
    profile: Profile,
    families: BTreeMap<u32, usize>,
    numeric_bounds: BTreeMap<String, (u128, u128)>,
}

impl Preparation {
    pub(super) fn new(profile: Profile) -> Result<Self> {
        profile.validate()?;
        let families = profile
            .families
            .iter()
            .enumerate()
            .map(|(index, family)| (family.id, index))
            .collect();
        Ok(Self {
            profile,
            families,
            numeric_bounds: BTreeMap::new(),
        })
    }

    pub(super) fn observe(&mut self, batch: &Batch) -> Result<()> {
        for row in &batch.rows {
            let index = self
                .families
                .get(&row.family)
                .with_context(|| format!("unknown family {}", row.family))?;
            let family = &self.profile.families[*index];
            let prefix = hex::decode(&family.key_prefix_hex)?;
            ensure!(
                row.key.starts_with(&prefix),
                "key does not match family {} prefix",
                family.name
            );
            let mut key_ranges = Vec::new();
            let mut value_ranges = Vec::new();
            for patch in &family.patches {
                let domain = &self.profile.domains[&patch.domain];
                let width = domain.width();
                let (bytes, ranges) = match patch.target {
                    Target::Key => (&row.key, &mut key_ranges),
                    Target::Value => (&row.value, &mut value_ranges),
                };
                let range = patch_range(patch, width, bytes.len())?;
                if patch.target == Target::Key {
                    ensure!(
                        range.start >= prefix.len(),
                        "key patch changes family prefix"
                    );
                }
                ensure!(
                    ranges.iter().all(|other: &Range<usize>| {
                        range.end <= other.start || other.end <= range.start
                    }),
                    "overlapping patches in family {}",
                    family.name
                );
                ranges.push(range.clone());
                if matches!(domain, Domain::Numeric { .. }) {
                    let value = decode(&canonical(&bytes[range], patch.endian));
                    let bounds = self
                        .numeric_bounds
                        .entry(patch.domain.clone())
                        .or_insert((value, value));
                    bounds.0 = bounds.0.min(value);
                    bounds.1 = bounds.1.max(value);
                }
            }
        }
        Ok(())
    }

    pub(super) fn finish(self, seed: u64) -> PreparedGenerator {
        let mut domains = BTreeMap::new();
        let mut max_pass = u64::MAX;
        for (name, domain) in &self.profile.domains {
            let prepared = match domain {
                Domain::Numeric { width } => {
                    let Some((min, max)) = self.numeric_bounds.get(name) else {
                        continue;
                    };
                    let span = max - min + 1;
                    let limit = (1u128 << (width * 8)) - 1;
                    max_pass = max_pass.min(((limit - max) / span).min(u64::MAX as u128) as u64);
                    PreparedDomain::Numeric {
                        width: *width,
                        span,
                    }
                }
                Domain::Identity { width } => PreparedDomain::Identity { width: *width },
            };
            domains.insert(name.clone(), prepared);
        }
        PreparedGenerator {
            profile: self.profile,
            families: self.families,
            domains,
            max_pass,
            seed,
        }
    }
}

impl Generator {
    pub fn new(bundle: Bundle, seed: u64) -> Result<Self> {
        bundle.validate()?;
        let mut preparation = Preparation::new(bundle.profile.clone())?;
        for batch in &bundle.batches {
            preparation.observe(batch)?;
        }
        Ok(Self {
            bundle,
            prepared: preparation.finish(seed),
        })
    }

    pub fn bundle(&self) -> &Bundle {
        &self.bundle
    }

    pub fn max_pass(&self) -> u64 {
        self.prepared.max_pass
    }

    pub fn validate_passes(&self, start_pass: u64, passes: u64) -> Result<()> {
        self.prepared.validate_passes(start_pass, passes)
    }

    pub fn batch(&self, event: usize, absolute_pass: u64) -> Result<Batch> {
        self.validate_passes(absolute_pass, 1)?;
        let original = self
            .bundle
            .batches
            .get(event)
            .context("event index out of bounds")?;
        self.prepared
            .transform(original.clone(), u64::try_from(event)?, absolute_pass)
    }
}

impl PreparedGenerator {
    pub(super) fn profile(&self) -> &Profile {
        &self.profile
    }

    pub(super) fn max_pass(&self) -> u64 {
        self.max_pass
    }

    pub(super) fn validate_passes(&self, start_pass: u64, passes: u64) -> Result<()> {
        ensure!(passes > 0, "pass count must be positive");
        let last = start_pass
            .checked_add(passes - 1)
            .context("pass range overflows")?;
        ensure!(
            last <= self.max_pass,
            "pass range exceeds profile capacity {}",
            self.max_pass
        );
        Ok(())
    }

    pub(super) fn transform(
        &self,
        mut batch: Batch,
        event: u64,
        absolute_pass: u64,
    ) -> Result<Batch> {
        self.validate_passes(absolute_pass, 1)?;
        if absolute_pass == 0 {
            return Ok(batch);
        }
        for (row_index, row) in batch.rows.iter_mut().enumerate() {
            let family: &Family = &self.profile.families[self.families[&row.family]];
            let mut key = std::mem::take(&mut row.key)
                .try_into_mut()
                .unwrap_or_else(|bytes| bytes::BytesMut::from(bytes.as_ref()));
            let mut value = std::mem::take(&mut row.value)
                .try_into_mut()
                .unwrap_or_else(|bytes| bytes::BytesMut::from(bytes.as_ref()));
            for (patch_index, patch) in family.patches.iter().enumerate() {
                let domain = &self.domains[&patch.domain];
                let bytes = match patch.target {
                    Target::Key => &mut key,
                    Target::Value => &mut value,
                };
                let range = patch_range(patch, domain.width(), bytes.len())?;
                match domain {
                    PreparedDomain::Numeric { width, span } => {
                        let original = decode(&canonical(&bytes[range.clone()], patch.endian));
                        let shifted = span
                            .checked_mul(absolute_pass as u128)
                            .and_then(|shift| original.checked_add(shift))
                            .context("numeric transform overflows")?;
                        ensure!(shifted < (1u128 << (width * 8)), "numeric domain exhausted");
                        let mut transformed = encode(shifted, *width);
                        if patch.endian == Endian::Little {
                            transformed.reverse();
                        }
                        bytes[range].copy_from_slice(&transformed);
                    }
                    PreparedDomain::Identity { width } => {
                        // Coordinates make random access independent of generation order.
                        let mut hash = Sha256::new();
                        hash.update(b"exoware.capture.identity.v1");
                        for coordinate in [
                            self.seed,
                            absolute_pass,
                            event,
                            row_index as u64,
                            patch_index as u64,
                        ] {
                            hash.update(coordinate.to_be_bytes());
                        }
                        bytes[range].copy_from_slice(&hash.finalize()[..*width]);
                    }
                }
            }
            row.key = key.into();
            row.value = value.into();
        }
        Ok(batch)
    }
}

impl PreparedDomain {
    fn width(&self) -> usize {
        match self {
            Self::Numeric { width, .. } | Self::Identity { width, .. } => *width,
        }
    }
}

fn patch_range(patch: &Patch, width: usize, length: usize) -> Result<Range<usize>> {
    let start = match patch.offset {
        Offset::Start(start) => start,
        Offset::End(distance) => length
            .checked_sub(distance)
            .context("patch starts before row bytes")?,
    };
    let end = start.checked_add(width).context("patch range overflows")?;
    ensure!(end <= length, "patch ends beyond row bytes");
    Ok(start..end)
}

fn canonical(bytes: &[u8], endian: Endian) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    if endian == Endian::Little {
        bytes.reverse();
    }
    bytes
}

fn decode(bytes: &[u8]) -> u128 {
    bytes
        .iter()
        .fold(0, |value, byte| (value << 8) | *byte as u128)
}

fn encode(value: u128, width: usize) -> Vec<u8> {
    value.to_be_bytes()[16 - width..].to_vec()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use bytes::Bytes;

    use super::super::{profile::Profile, Row};
    use super::*;

    fn bundle(domain: Domain, keys: &[Vec<u8>]) -> Bundle {
        Bundle {
            profile: Profile {
                version: 1,
                domains: BTreeMap::from([("id".into(), domain)]),
                families: vec![Family {
                    id: 7,
                    name: "rows".into(),
                    key_prefix_hex: "aa".into(),
                    fresh_key: 0,
                    patches: vec![Patch {
                        target: Target::Key,
                        offset: Offset::Start(1),
                        domain: "id".into(),
                        endian: Endian::Big,
                    }],
                }],
            },
            source: BTreeMap::new(),
            repeat_period_ns: 100,
            batches: vec![Batch {
                offset_ns: 12,
                rows: keys
                    .iter()
                    .map(|key| Row {
                        family: 7,
                        key: Bytes::from([&[0xaa][..], key].concat()),
                        value: Bytes::from_static(b"unchanged"),
                    })
                    .collect(),
            }],
        }
    }

    #[test]
    fn numeric_span_is_global_and_preserves_references_and_pass_zero() {
        let mut bundle = bundle(Domain::Numeric { width: 2 }, &[vec![0, 10], vec![0, 12]]);
        bundle.batches[0].rows[0].value = Bytes::from_static(&[0xff, 10, 0]);
        bundle.batches[0].rows[1].value = Bytes::from_static(&[0xfe, 20, 0]);
        bundle.profile.families[0].patches.push(Patch {
            target: Target::Value,
            offset: Offset::End(2),
            domain: "id".into(),
            endian: Endian::Little,
        });
        let original = bundle.batches[0].clone();
        let generator = Generator::new(bundle, 19).unwrap();
        assert_eq!(generator.batch(0, 0).unwrap(), original);
        let generated = generator.batch(0, 2).unwrap();
        assert_eq!(generated.offset_ns, original.offset_ns);
        assert_eq!(&generated.rows[0].key[..], &[0xaa, 0, 32]);
        assert_eq!(&generated.rows[0].value[..], &[0xff, 32, 0]);
        assert_eq!(&generated.rows[1].key[..], &[0xaa, 0, 34]);
        assert_eq!(&generated.rows[1].value[..], &[0xfe, 42, 0]);
        assert_eq!(generator.max_pass(), (u16::MAX as u64 - 20) / 11);
        assert_eq!(generator.bundle().batches[0], original);
    }

    #[test]
    fn numeric_widths_and_entire_pass_range_capacity() {
        for width in [1, 2, 4, 8] {
            let generator =
                Generator::new(bundle(Domain::Numeric { width }, &[vec![0; width]]), 0).unwrap();
            let limit = ((1u128 << (8 * width)) - 1) as u64;
            assert_eq!(generator.max_pass(), limit);
            let generated = generator.batch(0, limit).unwrap();
            assert_eq!(&generated.rows[0].key[1..], &vec![0xff; width]);
            generator.validate_passes(limit, 1).unwrap();
            assert!(generator.validate_passes(limit, 2).is_err());
            assert!(generator.validate_passes(0, 0).is_err());
        }
        let generator = Generator::new(
            bundle(Domain::Numeric { width: 8 }, &[vec![0; 8], vec![0xff; 8]]),
            0,
        )
        .unwrap();
        assert_eq!(generator.max_pass(), 0);
        assert!(generator.batch(0, 1).is_err());
        assert!(generator.batch(1, 0).is_err());
    }

    #[test]
    fn duplicate_physical_keys_are_preserved_across_events_and_families() {
        let mut bundle = bundle(Domain::Numeric { width: 1 }, &[vec![1]]);
        let mut family = bundle.profile.families[0].clone();
        family.id = 8;
        family.name = "other".into();
        bundle.profile.families.push(family);
        let mut other = bundle.batches[0].clone();
        other.rows[0].family = 8;
        bundle.batches.push(other);
        let generator = Generator::new(bundle.clone(), 0).unwrap();
        for event in 0..bundle.batches.len() {
            assert_eq!(generator.batch(event, 0).unwrap(), bundle.batches[event]);
        }
        assert_eq!(
            generator.batch(0, 1).unwrap().rows[0].key,
            generator.batch(1, 1).unwrap().rows[0].key
        );
    }

    #[test]
    fn bounds_overlap_and_prefix_changes_are_rejected() {
        let original = bundle(Domain::Identity { width: 2 }, &[vec![1, 2]]);
        for offset in [Offset::Start(2), Offset::End(4), Offset::End(3)] {
            let mut invalid = original.clone();
            invalid.profile.families[0].patches[0].offset = offset;
            assert!(Generator::new(invalid, 0).is_err());
        }
        let mut invalid = original.clone();
        let overlapping = invalid.profile.families[0].patches[0].clone();
        invalid.profile.families[0].patches.push(overlapping);
        assert!(Generator::new(invalid, 0).is_err());
        invalid = original.clone();
        invalid.batches[0].rows[0].family = 20;
        assert!(Generator::new(invalid, 0).is_err());
        invalid = original;
        invalid.profile.families[0].key_prefix_hex = "bb".into();
        assert!(Generator::new(invalid, 0).is_err());
    }

    #[test]
    fn unused_valid_declarations_do_not_limit_capacity() {
        let mut capture = bundle(Domain::Identity { width: 16 }, &[vec![1; 16]]);
        capture
            .profile
            .domains
            .insert("unused".into(), Domain::Numeric { width: 1 });
        let mut unused = capture.profile.families[0].clone();
        unused.id = 8;
        unused.name = "unused".into();
        unused.key_prefix_hex = "bb".into();
        unused.patches[0].domain = "unused".into();
        capture.profile.families.push(unused);
        assert_eq!(
            Generator::new(capture.clone(), 0).unwrap().max_pass(),
            u64::MAX
        );
        capture
            .profile
            .domains
            .insert("unused".into(), Domain::Numeric { width: 3 });
        assert!(Generator::new(capture, 0).is_err());
    }

    #[test]
    fn identity_occurrences_are_independent_and_reproducible() {
        let token = vec![7; 32];
        let mut capture = bundle(
            Domain::Identity { width: 32 },
            &[token.clone(), token.clone()],
        );
        capture.batches.push(capture.batches[0].clone());
        for (event, batch) in capture.batches.iter_mut().enumerate() {
            for (index, row) in batch.rows.iter_mut().enumerate() {
                row.key = Bytes::from([row.key.as_ref(), &[event as u8, index as u8]].concat());
                row.value = Bytes::from([&[0xcc][..], &token, &token].concat());
            }
        }
        for offset in [Offset::Start(1), Offset::End(32)] {
            capture.profile.families[0].patches.push(Patch {
                target: Target::Value,
                offset,
                domain: "id".into(),
                endian: Endian::Big,
            });
        }
        let generator = Generator::new(capture.clone(), 55).unwrap();
        let second = generator.batch(1, 19).unwrap();
        let first = generator.batch(0, 19).unwrap();
        assert_eq!(generator.batch(1, 19).unwrap(), second);
        assert_eq!(generator.batch(0, 0).unwrap(), capture.batches[0]);
        assert_eq!(generator.batch(1, 0).unwrap(), capture.batches[1]);
        let mut identities = BTreeSet::new();
        for (event, batch) in [&first, &second].into_iter().enumerate() {
            assert_eq!(batch.offset_ns, capture.batches[event].offset_ns);
            for (index, row) in batch.rows.iter().enumerate() {
                assert!(identities.insert(row.key.slice(1..33)));
                assert!(identities.insert(row.value.slice(1..33)));
                assert!(identities.insert(row.value.slice(33..65)));
                assert_eq!(row.key.len(), capture.batches[event].rows[index].key.len());
                assert_eq!(
                    row.value.len(),
                    capture.batches[event].rows[index].value.len()
                );
                assert_eq!(row.key[0], 0xaa);
                assert_eq!(&row.key[33..], &[event as u8, index as u8]);
                assert_eq!(row.value[0], 0xcc);
            }
        }
        assert_eq!(
            Generator::new(capture.clone(), 55)
                .unwrap()
                .batch(0, 19)
                .unwrap(),
            first
        );
        assert_ne!(
            Generator::new(capture.clone(), 56)
                .unwrap()
                .batch(0, 19)
                .unwrap(),
            first
        );
        assert_ne!(generator.batch(0, 20).unwrap(), first);
        assert_eq!(generator.bundle().batches, capture.batches);
    }

    #[test]
    fn identity_generation_does_not_reserve_captured_or_generated_bytes() {
        let all_bytes = (0..=255).map(|byte| vec![byte]).collect::<Vec<_>>();
        let generator =
            Generator::new(bundle(Domain::Identity { width: 1 }, &all_bytes), 23).unwrap();
        assert_eq!(generator.max_pass(), u64::MAX);
        generator.validate_passes(u64::MAX, 1).unwrap();
        assert_eq!(generator.batch(0, 1).unwrap().rows.len(), 256);
        assert_eq!(generator.batch(0, u64::MAX).unwrap().rows.len(), 256);
        assert!(generator.validate_passes(u64::MAX, 2).is_err());
    }

    #[test]
    fn numeric_key_transforms_protect_intersecting_families_across_passes() {
        let mut capture = bundle(
            Domain::Numeric { width: 1 },
            &[vec![0xbb, 1], vec![0xbb, 2]],
        );
        capture.profile.families[0].patches[0].offset = Offset::End(1);
        let mut family = capture.profile.families[0].clone();
        family.id = 8;
        family.name = "narrow".into();
        family.key_prefix_hex = "aabb".into();
        capture.profile.families.push(family);
        capture.batches[0].rows[1].family = 8;
        let generator = Generator::new(capture.clone(), 42).unwrap();
        let mut seen = BTreeSet::new();
        for pass in 0..=generator.max_pass() {
            for row in generator.batch(0, pass).unwrap().rows {
                assert!(seen.insert(row.key));
            }
        }
        capture.profile.families[1].patches[0].endian = Endian::Little;
        assert!(Generator::new(capture, 42).is_err());
    }

    #[test]
    fn identity_bytes_ignore_original_values_and_endianness() {
        for width in 1..=32 {
            let first = bundle(Domain::Identity { width }, &[vec![1; width]]);
            let mut second = bundle(Domain::Identity { width }, &[vec![2; width]]);
            second.profile.families[0].patches[0].endian = Endian::Little;
            let first = Generator::new(first, 123).unwrap().batch(0, 7).unwrap();
            let second = Generator::new(second, 123).unwrap().batch(0, 7).unwrap();
            assert_eq!(first, second);
            assert_eq!(first.rows[0].key.len(), width + 1);
            assert_eq!(first.rows[0].key[0], 0xaa);
            assert_eq!(&first.rows[0].value[..], b"unchanged");
        }
    }

    #[test]
    fn version_one_identity_golden_vector() {
        let generator =
            Generator::new(bundle(Domain::Identity { width: 32 }, &[vec![0; 32]]), 123).unwrap();
        assert_eq!(
            hex::encode(&generator.batch(0, 7).unwrap().rows[0].key[1..]),
            "70cb8253153104dd954a3ebbfbb864312c4de857c9062650ac70b65aeb67686a"
        );
    }
}
