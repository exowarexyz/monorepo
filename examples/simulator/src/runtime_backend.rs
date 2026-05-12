use std::{collections::BTreeMap, sync::Arc};

use bytes::Bytes;
use commonware_codec::{
    Decode, Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write,
};
use commonware_runtime::{Blob, Buf, BufMut, Storage};
use commonware_utils::sync::AsyncMutex;

use crate::{
    kv_backend::{beyond_upper_bound, VecRowScan},
    store::SEQ_META_KEY,
    Column, KvBackend, KvWrite, ScanBounds,
};

const STATE_VERSION: u8 = 1;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RuntimeKvState {
    version: u8,
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
    meta: BTreeMap<Vec<u8>, Vec<u8>>,
    log: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl RuntimeKvState {
    fn empty() -> Self {
        Self {
            version: STATE_VERSION,
            ..Default::default()
        }
    }

    fn column(&self, column: Column) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        match column {
            Column::Default => &self.rows,
            Column::Meta => &self.meta,
            Column::Log => &self.log,
        }
    }

    fn column_mut(&mut self, column: Column) -> &mut BTreeMap<Vec<u8>, Vec<u8>> {
        match column {
            Column::Default => &mut self.rows,
            Column::Meta => &mut self.meta,
            Column::Log => &mut self.log,
        }
    }
}

impl Write for RuntimeKvState {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.rows.write(buf);
        self.meta.write(buf);
        self.log.write(buf);
    }
}

impl EncodeSize for RuntimeKvState {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
            + self.rows.encode_size()
            + self.meta.encode_size()
            + self.log.encode_size()
    }
}

impl Read for RuntimeKvState {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &()) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        if version != STATE_VERSION {
            return Err(CodecError::Invalid("RuntimeKvState", "unknown version"));
        }
        let map_cfg = map_cfg();
        Ok(Self {
            version,
            rows: BTreeMap::<Vec<u8>, Vec<u8>>::read_cfg(buf, &map_cfg)?,
            meta: BTreeMap::<Vec<u8>, Vec<u8>>::read_cfg(buf, &map_cfg)?,
            log: BTreeMap::<Vec<u8>, Vec<u8>>::read_cfg(buf, &map_cfg)?,
        })
    }
}

type BytesMapCfg = (
    RangeCfg<usize>,
    ((RangeCfg<usize>, ()), (RangeCfg<usize>, ())),
);

fn map_cfg() -> BytesMapCfg {
    ((..).into(), (((..).into(), ()), ((..).into(), ())))
}

#[derive(Clone, Debug)]
pub struct RuntimeKvConfig {
    pub partition: String,
    pub name: Vec<u8>,
}

struct RuntimeKvBlob<B: Blob> {
    blob: B,
    len: u64,
}

impl<B: Blob> RuntimeKvBlob<B> {
    async fn load_state(&self) -> Result<RuntimeKvState, String> {
        if self.len == 0 {
            return Ok(RuntimeKvState::empty());
        }
        read_state_from_blob(&self.blob, self.len).await
    }

    async fn write_state(&mut self, state: &RuntimeKvState) -> Result<(), String> {
        let encoded = state.encode();
        self.blob
            .resize(encoded.len() as u64)
            .await
            .map_err(|e| e.to_string())?;
        self.blob
            .write_at(0, encoded.clone())
            .await
            .map_err(|e| e.to_string())?;
        self.blob.sync().await.map_err(|e| e.to_string())?;
        self.len = encoded.len() as u64;
        Ok(())
    }
}

struct RuntimeKvInner<B: Blob> {
    storage: AsyncMutex<RuntimeKvBlob<B>>,
    initial_sequence: u64,
}

pub struct RuntimeKvBackend<E: Storage> {
    inner: Arc<RuntimeKvInner<E::Blob>>,
}

impl<E: Storage> Clone for RuntimeKvBackend<E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<E: Storage> RuntimeKvBackend<E> {
    pub async fn init(context: E, cfg: RuntimeKvConfig) -> Result<Self, String> {
        let (blob, len) = context
            .open(&cfg.partition, &cfg.name)
            .await
            .map_err(|e| e.to_string())?;
        let mut len = len;
        let state = if len == 0 {
            let state = RuntimeKvState::empty();
            let encoded = state.encode();
            blob.resize(encoded.len() as u64)
                .await
                .map_err(|e| e.to_string())?;
            blob.write_at(0, encoded.clone())
                .await
                .map_err(|e| e.to_string())?;
            blob.sync().await.map_err(|e| e.to_string())?;
            len = encoded.len() as u64;
            state
        } else {
            read_state_from_blob(&blob, len).await?
        };
        Ok(Self {
            inner: Arc::new(RuntimeKvInner {
                storage: AsyncMutex::new(RuntimeKvBlob { blob, len }),
                initial_sequence: decode_sequence(state.meta.get(SEQ_META_KEY)),
            }),
        })
    }
}

impl<E: Storage> KvBackend for RuntimeKvBackend<E> {
    type Scan = VecRowScan;

    fn initial_sequence(&self) -> u64 {
        self.inner.initial_sequence
    }

    async fn get(&self, column: Column, key: Bytes) -> Result<Option<Vec<u8>>, String> {
        let state = {
            let storage = self.inner.storage.lock().await;
            storage.load_state().await?
        };
        Ok(state.column(column).get(key.as_ref()).cloned())
    }

    async fn get_many(
        &self,
        column: Column,
        keys: Vec<Bytes>,
    ) -> Result<Vec<Option<Vec<u8>>>, String> {
        let state = {
            let storage = self.inner.storage.lock().await;
            storage.load_state().await?
        };
        let column = state.column(column);
        Ok(keys
            .into_iter()
            .map(|key| column.get(key.as_ref()).cloned())
            .collect())
    }

    async fn write_batch(&self, writes: Vec<KvWrite>) -> Result<(), String> {
        if writes.is_empty() {
            return Ok(());
        }
        let mut storage = self.inner.storage.lock().await;
        let mut state = storage.load_state().await?;
        for write in writes {
            match write {
                KvWrite::Put { column, key, value } => {
                    state
                        .column_mut(column)
                        .insert(key.to_vec(), value.to_vec());
                }
                KvWrite::Delete { column, key } => {
                    state.column_mut(column).remove(key.as_ref());
                }
            }
        }
        storage.write_state(&state).await
    }

    async fn scan(&self, column: Column, bounds: ScanBounds) -> Result<Self::Scan, String> {
        let state = {
            let storage = self.inner.storage.lock().await;
            storage.load_state().await?
        };
        Ok(VecRowScan::new(collect_rows(state.column(column), &bounds)))
    }
}

async fn read_state_from_blob<B: Blob>(blob: &B, len: u64) -> Result<RuntimeKvState, String> {
    let len: usize = len
        .try_into()
        .map_err(|_| "runtime KV blob is too large for this platform".to_string())?;
    let raw = blob
        .read_at(0, len)
        .await
        .map_err(|e| e.to_string())?
        .coalesce();
    RuntimeKvState::decode_cfg(raw, &()).map_err(|e| e.to_string())
}

fn collect_rows(rows: &BTreeMap<Vec<u8>, Vec<u8>>, bounds: &ScanBounds) -> Vec<(Bytes, Bytes)> {
    if bounds.limit == 0 {
        return Vec::new();
    }

    let mut out = Vec::new();
    if bounds.forward {
        for (key, value) in rows.range(bounds.start.to_vec()..) {
            if beyond_upper_bound(key, bounds.end.as_deref(), bounds.end_inclusive) {
                break;
            }
            out.push((Bytes::copy_from_slice(key), Bytes::copy_from_slice(value)));
            if out.len() >= bounds.limit {
                break;
            }
        }
    } else if let Some(end) = &bounds.end {
        for (key, value) in rows.range(..=end.to_vec()).rev() {
            if key.as_slice() < bounds.start.as_ref() {
                break;
            }
            out.push((Bytes::copy_from_slice(key), Bytes::copy_from_slice(value)));
            if out.len() >= bounds.limit {
                break;
            }
        }
    } else {
        for (key, value) in rows.iter().rev() {
            if key.as_slice() < bounds.start.as_ref() {
                break;
            }
            out.push((Bytes::copy_from_slice(key), Bytes::copy_from_slice(value)));
            if out.len() >= bounds.limit {
                break;
            }
        }
    }
    out
}

fn decode_sequence(value: Option<&Vec<u8>>) -> u64 {
    match value {
        Some(bytes) if bytes.len() == 8 => {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(bytes);
            u64::from_le_bytes(raw)
        }
        _ => 0,
    }
}
