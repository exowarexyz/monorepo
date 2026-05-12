use std::future::Future;

use bytes::Bytes;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Column {
    Default,
    Meta,
    Log,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KvWrite {
    Put {
        column: Column,
        key: Bytes,
        value: Bytes,
    },
    Delete {
        column: Column,
        key: Bytes,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanBounds {
    pub start: Bytes,
    pub end: Option<Bytes>,
    pub end_inclusive: bool,
    pub forward: bool,
    pub limit: usize,
}

pub trait RowScan: Send {
    fn next_batch(
        &mut self,
        max_items: usize,
    ) -> impl Future<Output = Result<Vec<(Bytes, Bytes)>, String>> + Send + '_;
}

pub struct VecRowScan {
    rows: Vec<(Bytes, Bytes)>,
    offset: usize,
}

impl VecRowScan {
    pub fn new(rows: Vec<(Bytes, Bytes)>) -> Self {
        Self { rows, offset: 0 }
    }
}

impl RowScan for VecRowScan {
    async fn next_batch(&mut self, max_items: usize) -> Result<Vec<(Bytes, Bytes)>, String> {
        if max_items == 0 || self.offset >= self.rows.len() {
            return Ok(Vec::new());
        }
        let end = self.offset.saturating_add(max_items).min(self.rows.len());
        let batch = self.rows[self.offset..end].to_vec();
        self.offset = end;
        Ok(batch)
    }
}

pub trait KvBackend: Clone + Send + Sync + 'static {
    type Scan: RowScan + 'static;

    fn initial_sequence(&self) -> u64;

    fn get(
        &self,
        column: Column,
        key: Bytes,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, String>> + Send + '_;

    fn get_many(
        &self,
        column: Column,
        keys: Vec<Bytes>,
    ) -> impl Future<Output = Result<Vec<Option<Vec<u8>>>, String>> + Send + '_;

    fn write_batch(
        &self,
        writes: Vec<KvWrite>,
    ) -> impl Future<Output = Result<(), String>> + Send + '_;

    fn scan(
        &self,
        column: Column,
        bounds: ScanBounds,
    ) -> impl Future<Output = Result<Self::Scan, String>> + Send + '_;
}

pub(crate) fn beyond_upper_bound(key: &[u8], end: Option<&[u8]>, inclusive: bool) -> bool {
    match end {
        Some(end) if inclusive => key > end,
        Some(end) => key >= end,
        None => false,
    }
}
