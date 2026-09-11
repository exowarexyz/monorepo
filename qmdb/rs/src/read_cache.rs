use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{Arc, Mutex, Weak},
};

use bytes::Bytes;
use commonware_codec::DecodeExt;
use commonware_cryptography::Digest;
use commonware_storage::merkle::{Family, Location, Position};
use commonware_utils::cache::Clock;
use tokio::sync::{watch, Mutex as AsyncMutex, OwnedMutexGuard};

const NODE_CAPACITY: usize = 16_384;
const CONTEXT_CAPACITY: usize = 128;

#[derive(Clone, Copy)]
pub(crate) struct RootContext<D: Digest> {
    pub root: D,
    pub inactive_peaks: usize,
}

pub(crate) struct ReadCache<F: Family, D: Digest> {
    state: Mutex<State<F, D>>,
}

struct State<F: Family, D: Digest> {
    nodes: Clock<Position<F>, Bytes>,
    contexts: Clock<Location<F>, RootContext<D>>,
    witnesses: Clock<Location<F>, Bytes>,
    context_gates: HashMap<Location<F>, Weak<AsyncMutex<()>>>,
    flights: HashMap<Position<F>, watch::Receiver<Option<Bytes>>>,
}

pub(crate) struct NodeReservation<F: Family, D: Digest> {
    pub hits: HashMap<Position<F>, Bytes>,
    pub owned: Vec<Position<F>>,
    cache: Arc<ReadCache<F, D>>,
    claims: HashMap<Position<F>, watch::Sender<Option<Bytes>>>,
    waiters: HashMap<Position<F>, watch::Receiver<Option<Bytes>>>,
}

pub(crate) struct NodeWaiters<F: Family> {
    waiters: HashMap<Position<F>, watch::Receiver<Option<Bytes>>>,
}

impl<F: Family, D: Digest> ReadCache<F, D> {
    pub fn new() -> Self {
        Self::with_capacities(NODE_CAPACITY, CONTEXT_CAPACITY)
    }

    fn with_capacities(nodes: usize, contexts: usize) -> Self {
        Self {
            state: Mutex::new(State {
                nodes: Clock::new(NonZeroUsize::new(nodes).unwrap()),
                contexts: Clock::new(NonZeroUsize::new(contexts).unwrap()),
                witnesses: Clock::new(NonZeroUsize::new(contexts).unwrap()),
                context_gates: HashMap::new(),
                flights: HashMap::new(),
            }),
        }
    }

    pub fn cached_context(&self, watermark: Location<F>) -> Option<RootContext<D>> {
        self.state.lock().unwrap().contexts.get(&watermark).copied()
    }

    pub async fn context(
        self: &Arc<Self>,
        watermark: Location<F>,
    ) -> (Option<RootContext<D>>, Option<OwnedMutexGuard<()>>) {
        let gate = {
            let mut state = self.state.lock().unwrap();
            state
                .context_gates
                .retain(|_, gate| gate.strong_count() > 0);
            if let Some(context) = state.contexts.get(&watermark) {
                return (Some(*context), None);
            }

            let entry = state.context_gates.entry(watermark).or_default();
            match entry.upgrade() {
                Some(gate) => gate,
                None => {
                    let gate = Arc::new(AsyncMutex::new(()));
                    *entry = Arc::downgrade(&gate);
                    gate
                }
            }
        };

        // Another request may publish the context while this one waits.
        let guard = gate.lock_owned().await;
        let state = self.state.lock().unwrap();
        match state.contexts.get(&watermark) {
            Some(context) => (Some(*context), None),
            None => (None, Some(guard)),
        }
    }

    pub fn put_context(&self, watermark: Location<F>, context: RootContext<D>) {
        self.state.lock().unwrap().contexts.put(watermark, context);
    }

    pub fn put_nodes(&self, nodes: impl IntoIterator<Item = (Position<F>, Bytes)>) {
        let mut state = self.state.lock().unwrap();
        for (position, bytes) in nodes {
            if state.nodes.get(&position).is_some() {
                continue;
            }
            if bytes.len() == D::SIZE && D::decode(bytes.as_ref()).is_ok() {
                // A digest slice must not retain the rest of its network response.
                state.nodes.put(position, Bytes::copy_from_slice(&bytes));
            }
        }
    }

    pub fn witness(&self, watermark: Location<F>) -> Option<Bytes> {
        self.state
            .lock()
            .unwrap()
            .witnesses
            .get(&watermark)
            .cloned()
    }

    // The caller decodes the witness before caching its bytes.
    pub fn put_witness(&self, watermark: Location<F>, bytes: Bytes) {
        if !bytes.is_empty() {
            self.state
                .lock()
                .unwrap()
                .witnesses
                .put(watermark, Bytes::copy_from_slice(&bytes));
        }
    }

    pub fn reserve(self: &Arc<Self>, positions: &[Position<F>]) -> NodeReservation<F, D> {
        let mut reservation = NodeReservation {
            hits: HashMap::new(),
            owned: Vec::new(),
            cache: self.clone(),
            claims: HashMap::new(),
            waiters: HashMap::new(),
        };
        let mut state = self.state.lock().unwrap();
        for &position in positions {
            if let Some(bytes) = state.nodes.get(&position) {
                reservation.hits.insert(position, bytes.clone());
            } else if let Some(flight) = state.flights.get(&position) {
                reservation.waiters.insert(position, flight.clone());
            } else {
                let (sender, receiver) = watch::channel(None);
                state.flights.insert(position, receiver);
                reservation.claims.insert(position, sender);
                reservation.owned.push(position);
            }
        }
        reservation
    }
}

impl<F: Family, D: Digest> NodeReservation<F, D> {
    // Publish before waiting so overlapping batches cannot wait on each other.
    pub fn complete(
        mut self,
        nodes: impl IntoIterator<Item = (Position<F>, Bytes)>,
    ) -> NodeWaiters<F> {
        let mut state = self.cache.state.lock().unwrap();
        for (position, bytes) in nodes {
            let Some(sender) = self.claims.get(&position) else {
                continue;
            };
            if bytes.len() != D::SIZE || D::decode(bytes.as_ref()).is_err() {
                continue;
            }

            // Receivers retain results even if subsequent inserts evict them.
            let bytes = Bytes::copy_from_slice(&bytes);
            state.nodes.put(position, bytes.clone());
            sender.send_replace(Some(bytes));
        }

        for (position, _) in self.claims.drain() {
            state.flights.remove(&position);
        }
        NodeWaiters {
            waiters: std::mem::take(&mut self.waiters),
        }
    }
}

impl<F: Family> NodeWaiters<F> {
    // Missing follower results must be retried in the caller's own read session.
    pub async fn wait(self) -> HashMap<Position<F>, Bytes> {
        let mut nodes = HashMap::new();
        for (position, mut receiver) in self.waiters {
            let _ = receiver.changed().await;
            if let Some(bytes) = receiver.borrow().clone() {
                nodes.insert(position, bytes);
            }
        }
        nodes
    }
}

impl<F: Family, D: Digest> Drop for NodeReservation<F, D> {
    fn drop(&mut self) {
        if self.claims.is_empty() {
            return;
        }

        let mut state = self.cache.state.lock().unwrap();
        for (position, _) in self.claims.drain() {
            state.flights.remove(&position);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use commonware_cryptography::sha256::Digest;
    use commonware_storage::mmr;
    use tokio::{sync::Barrier, task::JoinSet, time::timeout};

    use super::*;

    type Cache = ReadCache<mmr::Family, Digest>;
    type Node = Position<mmr::Family>;

    fn bytes(position: Node) -> Bytes {
        Bytes::from(vec![position.as_u64() as u8; 32])
    }

    fn context(value: u8) -> RootContext<Digest> {
        RootContext {
            root: Digest([value; 32]),
            inactive_peaks: value as usize,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn overlapping_requests_load_each_node_once() {
        let cache = Arc::new(Cache::new());
        let barrier = Arc::new(Barrier::new(11));
        let mut tasks = JoinSet::new();
        for index in 0..11 {
            let cache = cache.clone();
            let barrier = barrier.clone();
            tasks.spawn(async move {
                let positions = [Node::new(index), Node::new(index + 1), Node::new(20)];
                let mut reservation = cache.reserve(&positions);
                let owned = reservation.owned.clone();
                let mut found = std::mem::take(&mut reservation.hits);
                barrier.wait().await;
                let loaded = owned.iter().map(|&p| (p, bytes(p))).collect::<Vec<_>>();
                let pending = reservation.complete(loaded.clone());
                found.extend(loaded);
                found.extend(pending.wait().await);
                assert!(positions.iter().all(|p| found.get(p) == Some(&bytes(*p))));
                owned
            });
        }

        let mut counts = HashMap::new();
        timeout(Duration::from_secs(5), async {
            while let Some(result) = tasks.join_next().await {
                for position in result.unwrap() {
                    *counts.entry(position).or_insert(0) += 1;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(counts.len(), 13);
        assert!(counts.values().all(|&count| count == 1));
        assert!(cache.state.lock().unwrap().flights.is_empty());
    }

    #[tokio::test]
    async fn completed_results_survive_eviction() {
        let cache = Arc::new(Cache::with_capacities(1, 1));
        let first = Node::new(1);
        let second = Node::new(2);
        let leader = cache.reserve(&[first]);
        let follower = cache.reserve(&[first]).complete([]);
        leader.complete([(first, bytes(first))]);
        cache.reserve(&[second]).complete([(second, bytes(second))]);

        assert_eq!(cache.state.lock().unwrap().nodes.len(), 1);
        assert_eq!(follower.wait().await.get(&first), Some(&bytes(first)));
        assert_eq!(cache.reserve(&[first]).owned, vec![first]);
    }

    #[tokio::test]
    async fn cancellation_releases_claims() {
        let cache = Arc::new(Cache::new());
        let position = Node::new(1);
        let leader = cache.reserve(&[position]);
        let follower = cache.reserve(&[position]).complete([]);
        let task = tokio::spawn(async move {
            let _leader = leader;
            std::future::pending::<()>().await;
        });
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        assert!(timeout(Duration::from_secs(1), follower.wait())
            .await
            .unwrap()
            .is_empty());
        assert_eq!(cache.reserve(&[position]).owned, vec![position]);
        assert!(cache.state.lock().unwrap().flights.is_empty());
    }

    #[tokio::test]
    async fn absent_and_malformed_rows_are_not_cached() {
        let cache = Arc::new(Cache::new());
        let positions = [Node::new(0), Node::new(1)];
        let leader = cache.reserve(&positions);
        let follower = cache.reserve(&positions).complete([]);
        leader.complete([(positions[1], Bytes::from_static(b"invalid"))]);

        assert!(follower.wait().await.is_empty());
        assert!(cache.state.lock().unwrap().nodes.is_empty());
        let retry = cache.reserve(&positions);
        assert_eq!(retry.owned, positions);
        retry.complete([(positions[0], Bytes::from(vec![0; 32]))]);
        let retry = cache.reserve(&positions);
        assert_eq!(retry.owned, vec![positions[1]]);
        assert_eq!(retry.hits[&positions[0]], Bytes::from(vec![0; 32]));
    }

    #[tokio::test]
    async fn empty_completion_releases_owned_claims() {
        let cache = Arc::new(Cache::new());
        let position = Node::new(1);
        let leader = cache.reserve(&[position]);
        let follower = cache.reserve(&[position]).complete([]);
        assert_eq!(leader.owned, vec![position]);
        assert!(leader.complete([]).wait().await.is_empty());
        assert!(timeout(Duration::from_secs(1), follower.wait())
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn independent_watermarks_progress_and_contexts_are_rechecked() {
        let cache = Arc::new(Cache::new());
        let watermark = Location::new(1);
        let (_, guard) = cache.context(watermark).await;
        let mut same = Box::pin(cache.context(watermark));
        assert!(timeout(Duration::from_millis(10), &mut same).await.is_err());
        let (other, other_guard) = timeout(Duration::from_secs(1), cache.context(Location::new(2)))
            .await
            .unwrap();
        assert!(other.is_none());
        assert!(other_guard.is_some());

        cache.put_context(watermark, context(3));
        drop(guard);
        let (found, guard) = timeout(Duration::from_secs(1), same).await.unwrap();
        assert!(guard.is_none());
        let found = found.unwrap();
        assert_eq!(found.root, Digest([3; 32]));
        assert_eq!(found.inactive_peaks, 3);
    }

    #[tokio::test]
    async fn failed_context_initialization_can_retry() {
        let cache = Arc::new(Cache::new());
        let watermark = Location::new(1);
        let (_, guard) = cache.context(watermark).await;
        let mut follower = Box::pin(cache.context(watermark));
        assert!(timeout(Duration::from_millis(10), &mut follower)
            .await
            .is_err());
        drop(guard);

        let (found, guard) = timeout(Duration::from_secs(1), follower).await.unwrap();
        assert!(found.is_none());
        assert!(guard.is_some());
    }

    #[tokio::test]
    async fn cancelled_context_waiter_does_not_split_the_gate() {
        let cache = Arc::new(Cache::new());
        let watermark = Location::new(1);
        let (_, guard) = cache.context(watermark).await;
        let mut cancelled = Box::pin(cache.context(watermark));
        assert!(timeout(Duration::from_millis(10), &mut cancelled)
            .await
            .is_err());
        drop(cancelled);

        let mut follower = Box::pin(cache.context(watermark));
        assert!(timeout(Duration::from_millis(10), &mut follower)
            .await
            .is_err());
        drop(guard);
        let (found, guard) = timeout(Duration::from_secs(1), follower).await.unwrap();
        assert!(found.is_none());
        assert!(guard.is_some());
    }

    #[tokio::test]
    async fn context_eviction_and_gate_cleanup_are_bounded() {
        let cache = Arc::new(Cache::with_capacities(1, 2));
        for index in 0..100 {
            let watermark = Location::new(index);
            let (_, guard) = cache.context(watermark).await;
            cache.put_context(watermark, context(index as u8));
            drop(guard);
        }
        let (_, guard) = cache.context(Location::new(100)).await;
        let state = cache.state.lock().unwrap();
        assert_eq!(state.contexts.len(), 2);
        assert_eq!(state.context_gates.len(), 1);
        assert!(state.contexts.get(&Location::new(0)).is_none());
        drop(state);
        drop(guard);
    }

    #[test]
    fn fallback_nodes_are_validated_and_bounded() {
        let cache = Arc::new(Cache::with_capacities(1, 1));
        let positions = [Node::new(1), Node::new(2)];
        cache.put_nodes([(positions[0], Bytes::new())]);
        assert!(cache.state.lock().unwrap().nodes.is_empty());
        cache.put_nodes(positions.map(|p| (p, bytes(p))));

        let reservation = cache.reserve(&positions);
        assert_eq!(reservation.owned, vec![positions[0]]);
        assert_eq!(reservation.hits[&positions[1]], bytes(positions[1]));
        assert_eq!(cache.state.lock().unwrap().nodes.len(), 1);
    }

    #[test]
    fn witnesses_are_scoped_and_bounded() {
        let cache = Cache::with_capacities(1, 1);
        let first = Location::new(1);
        let second = Location::new(2);
        cache.put_witness(first, Bytes::new());
        assert!(cache.witness(first).is_none());
        cache.put_witness(first, Bytes::from_static(b"first"));
        assert_eq!(cache.witness(first), Some(Bytes::from_static(b"first")));
        assert!(cache.witness(second).is_none());
        cache.put_witness(second, Bytes::from_static(b"second"));
        assert!(cache.witness(first).is_none());
        assert_eq!(cache.witness(second), Some(Bytes::from_static(b"second")));
        assert_eq!(cache.state.lock().unwrap().witnesses.len(), 1);
    }
}
