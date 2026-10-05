use std::{collections::BTreeMap, path::PathBuf};

use serde::Serialize;

use crate::capture::FileGenerator;

#[derive(clap::Args, Debug)]
pub struct Args {
    #[arg(long)]
    pub capture: PathBuf,
    #[arg(long, default_value_t = 0)]
    pub seed: u64,
}

#[derive(Serialize)]
struct Summary {
    source: BTreeMap<String, String>,
    events: u64,
    repeat_period_ns: u64,
    max_pass: u64,
    seed: u64,
    families: BTreeMap<u32, Family>,
}

#[derive(Serialize)]
struct Family {
    name: String,
    rows: u64,
    key_bytes: u64,
    value_bytes: u64,
    min_key_bytes: usize,
    max_key_bytes: usize,
    min_value_bytes: usize,
    max_value_bytes: usize,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let mut generator = FileGenerator::open(&args.capture, args.seed)?;
    let mut families = BTreeMap::<u32, Family>::new();
    while let Some(batch) = generator.next_batch(0)? {
        for row in &batch.rows {
            let family = families.entry(row.family).or_insert_with(|| Family {
                name: generator
                    .profile()
                    .families
                    .iter()
                    .find(|family| family.id == row.family)
                    .unwrap()
                    .name
                    .clone(),
                rows: 0,
                key_bytes: 0,
                value_bytes: 0,
                min_key_bytes: row.key.len(),
                max_key_bytes: row.key.len(),
                min_value_bytes: row.value.len(),
                max_value_bytes: row.value.len(),
            });
            family.rows += 1;
            family.key_bytes += row.key.len() as u64;
            family.value_bytes += row.value.len() as u64;
            family.min_key_bytes = family.min_key_bytes.min(row.key.len());
            family.max_key_bytes = family.max_key_bytes.max(row.key.len());
            family.min_value_bytes = family.min_value_bytes.min(row.value.len());
            family.max_value_bytes = family.max_value_bytes.max(row.value.len());
        }
    }
    let summary = Summary {
        source: generator.source().clone(),
        events: generator.event_count(),
        repeat_period_ns: generator.repeat_period_ns(),
        max_pass: generator.max_pass(),
        seed: args.seed,
        families,
    };
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}
