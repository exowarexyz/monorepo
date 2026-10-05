use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u32,
    pub domains: BTreeMap<String, Domain>,
    pub families: Vec<Family>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Domain {
    Numeric { width: usize },
    Identity { width: usize },
}

impl Domain {
    pub fn width(&self) -> usize {
        match self {
            Self::Numeric { width } | Self::Identity { width } => *width,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Family {
    pub id: u32,
    pub name: String,
    pub key_prefix_hex: String,
    pub fresh_key: usize,
    pub patches: Vec<Patch>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Patch {
    pub target: Target,
    pub offset: Offset,
    pub domain: String,
    #[serde(default)]
    pub endian: Endian,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Key,
    Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Offset {
    Start(usize),
    End(usize),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endian {
    #[default]
    Big,
    Little,
}

impl Profile {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "unsupported profile version {}",
            self.version
        );
        ensure!(!self.domains.is_empty(), "profile has no domains");
        ensure!(!self.families.is_empty(), "profile has no families");
        for (name, domain) in &self.domains {
            ensure!(!name.is_empty(), "domain name is empty");
            match domain {
                Domain::Numeric { width } => ensure!(
                    matches!(width, 1 | 2 | 4 | 8),
                    "numeric domain {name} must have width 1, 2, 4, or 8"
                ),
                Domain::Identity { width } => ensure!(
                    (1..=32).contains(width),
                    "identity domain {name} must have width 1 through 32"
                ),
            }
        }

        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut prefixes = Vec::with_capacity(self.families.len());
        for family in &self.families {
            ensure!(ids.insert(family.id), "duplicate family id {}", family.id);
            ensure!(!family.name.is_empty(), "family name is empty");
            ensure!(
                names.insert(&family.name),
                "duplicate family name {}",
                family.name
            );
            let prefix = hex::decode(&family.key_prefix_hex)
                .with_context(|| format!("invalid prefix for family {}", family.name))?;
            ensure!(
                prefix.len() <= 254,
                "family prefix exceeds maximum key length"
            );
            let fresh = family
                .patches
                .get(family.fresh_key)
                .context("fresh_key must identify a patch")?;
            ensure!(
                fresh.target == Target::Key,
                "fresh_key must identify a key patch"
            );
            for patch in &family.patches {
                let domain = self
                    .domains
                    .get(&patch.domain)
                    .with_context(|| format!("unknown domain {}", patch.domain))?;
                match patch.offset {
                    Offset::Start(offset) => {
                        ensure!(
                            offset.checked_add(domain.width()).is_some(),
                            "patch offset overflows"
                        );
                        if patch.target == Target::Key {
                            ensure!(offset >= prefix.len(), "key patch changes family prefix");
                        }
                    }
                    Offset::End(offset) => {
                        ensure!(
                            offset >= domain.width(),
                            "end offset is smaller than patch width"
                        );
                    }
                }
            }
            prefixes.push(prefix);
        }

        // Matching key layouts keep numeric shifts consistent across overlapping families.
        for (index, family) in self.families.iter().enumerate() {
            for (other_index, other) in self.families[..index].iter().enumerate() {
                if prefixes[index].starts_with(&prefixes[other_index])
                    || prefixes[other_index].starts_with(&prefixes[index])
                {
                    let keys: Vec<_> = family
                        .patches
                        .iter()
                        .filter(|patch| patch.target == Target::Key)
                        .collect();
                    let other_keys: Vec<_> = other
                        .patches
                        .iter()
                        .filter(|patch| patch.target == Target::Key)
                        .collect();
                    ensure!(
                        keys == other_keys,
                        "overlapping family prefixes require identical key patches"
                    );
                    ensure!(
                        family.patches[family.fresh_key] == other.patches[other.fresh_key],
                        "overlapping family prefixes require the same freshness patch"
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(domain: Domain) -> Profile {
        Profile {
            version: 1,
            domains: BTreeMap::from([("id".into(), domain)]),
            families: vec![Family {
                id: 0,
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
        }
    }

    #[test]
    fn version_one_json_is_explicit_and_defaults_big_endian() {
        let json = r#"{"version":1,"domains":{"id":{"kind":"numeric","width":8}},"families":[{"id":0,"name":"rows","key_prefix_hex":"aa","fresh_key":0,"patches":[{"target":"key","offset":{"start":1},"domain":"id"}]}]}"#;
        let parsed: Profile = serde_json::from_str(json).unwrap();
        assert_eq!(parsed, profile(Domain::Numeric { width: 8 }));
        assert_eq!(
            serde_json::from_str::<Profile>(&serde_json::to_string(&parsed).unwrap()).unwrap(),
            parsed
        );
        parsed.validate().unwrap();
    }

    #[test]
    fn invalid_declarations_are_rejected() {
        let valid = profile(Domain::Identity { width: 1 });
        for width in [0, 33, usize::MAX] {
            let mut invalid = valid.clone();
            invalid
                .domains
                .insert("id".into(), Domain::Identity { width });
            assert!(invalid.validate().is_err());
        }
        for width in [0, 3, 16] {
            let mut invalid = valid.clone();
            invalid
                .domains
                .insert("id".into(), Domain::Numeric { width });
            assert!(invalid.validate().is_err());
        }
        let mut invalid = valid.clone();
        invalid.version = 2;
        assert!(invalid.validate().is_err());
        invalid = valid.clone();
        invalid.families[0].fresh_key = 1;
        assert!(invalid.validate().is_err());
        invalid = valid.clone();
        invalid.families[0].patches[0].offset = Offset::Start(0);
        assert!(invalid.validate().is_err());
        invalid = valid.clone();
        invalid.families[0].patches[0].domain = "missing".into();
        assert!(invalid.validate().is_err());
        invalid = valid;
        invalid.families[0].patches[0].target = Target::Value;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn overlapping_prefixes_require_every_key_transform_to_match() {
        let mut profile = profile(Domain::Numeric { width: 1 });
        profile.families[0].patches[0].offset = Offset::Start(2);
        let mut other = profile.families[0].clone();
        other.id = 1;
        other.name = "other".into();
        other.key_prefix_hex = "aabb".into();
        profile.families.push(other);
        profile.validate().unwrap();
        profile.families[1].patches.push(Patch {
            target: Target::Key,
            offset: Offset::Start(3),
            domain: "id".into(),
            endian: Endian::Big,
        });
        assert!(profile.validate().is_err());
        let second = profile.families[1].patches[1].clone();
        profile.families[0].patches.push(second);
        profile.validate().unwrap();
        profile.families[1].fresh_key = 1;
        assert!(profile.validate().is_err());
    }
}
