use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

use anyhow::Context;
use serde::Serialize;

use super::{schedule, Args};

#[derive(Serialize)]
pub(super) struct Header {
    pub capture_sha256: String,
    pub source: BTreeMap<String, String>,
    pub settings: Args,
}

pub(super) struct Writer {
    file: BufWriter<File>,
    first: bool,
}

impl Writer {
    pub fn create(path: impl AsRef<Path>, header: Header) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let file = File::options()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("creating report {}", path.display()))?;
        let mut file = BufWriter::new(file);
        file.write_all(b"{\"format_version\":2")?;
        let serde_json::Value::Object(fields) = serde_json::to_value(header)? else {
            unreachable!("report header is an object")
        };
        for (name, value) in fields {
            file.write_all(b",")?;
            serde_json::to_writer(&mut file, &name)?;
            file.write_all(b":")?;
            serde_json::to_writer(&mut file, &value)?;
        }
        file.write_all(b",\"run\":{\"requests\":[")?;
        file.flush()?;
        Ok(Self { file, first: true })
    }

    pub fn record(&mut self, request: &schedule::Request) -> anyhow::Result<()> {
        if !self.first {
            self.file.write_all(b",")?;
        }
        serde_json::to_writer(&mut self.file, request)?;
        self.first = false;
        Ok(())
    }

    pub fn finish(mut self, report: &schedule::Report) -> anyhow::Result<()> {
        self.file.write_all(b"]")?;
        let serde_json::Value::Object(fields) = serde_json::to_value(report)? else {
            unreachable!("replay summary is an object")
        };
        for (name, value) in fields {
            self.file.write_all(b",")?;
            serde_json::to_writer(&mut self.file, &name)?;
            self.file.write_all(b":")?;
            serde_json::to_writer(&mut self.file, &value)?;
        }
        self.file.write_all(b"}}\n")?;
        self.file.flush()?;
        Ok(())
    }
}
