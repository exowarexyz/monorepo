use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use connectrpc::client::{full_body, ClientTransport};
use exoware_sdk::limits::MAX_PUT_ENTRIES;
use exoware_sdk::transport::ServiceTransport;
use exoware_server::{ingest_service, Ingest, IngestError, IngestState, PutPlan};

struct TrackingAllocator;

static LARGEST_ALLOCATION: AtomicUsize = AtomicUsize::new(0);

// A separate test binary isolates allocation measurements from other server tests.
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST_ALLOCATION.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        LARGEST_ALLOCATION.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        LARGEST_ALLOCATION.fetch_max(size, Ordering::Relaxed);
        unsafe { System.realloc(pointer, layout, size) }
    }
}

struct RejectIngest;

impl Ingest for RejectIngest {
    fn prepare(&self, _: &PutPlan) -> Result<(), IngestError> {
        panic!("malformed JSON must fail before preparation")
    }

    async fn put_batch(&self, _: Vec<(Bytes, Bytes)>) -> Result<u64, IngestError> {
        panic!("malformed JSON must never be written")
    }
}

#[tokio::test]
async fn malformed_json_does_not_materialize_entries_before_admission() {
    let transport = ServiceTransport::new(ingest_service(IngestState::new(Arc::new(RejectIngest))));
    for tail in [b"],\"kvs\":[]}".as_slice(), b",", b"],\"unknown\":[1,]}"] {
        let mut body = Vec::with_capacity(MAX_PUT_ENTRIES * 3 + 64);
        body.extend_from_slice(b"{\"kvs\":[");
        for index in 0..MAX_PUT_ENTRIES {
            if index != 0 {
                body.push(b',');
            }
            body.extend_from_slice(b"{}");
        }
        body.extend_from_slice(tail);
        let wire_len = body.len();
        let request = http::Request::post("http://store.test/log.ingest.v1.Service/Put")
            .header(http::header::CONTENT_TYPE, "application/json")
            .header("connect-protocol-version", "1")
            .body(full_body(Bytes::from(body)))
            .unwrap();

        LARGEST_ALLOCATION.store(0, Ordering::Relaxed);
        let response = transport.send(request).await.unwrap();
        let largest = LARGEST_ALLOCATION.load(Ordering::Relaxed);

        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);

        // Allow transport buffering while detecting entry vectors amplified from tiny JSON rows.
        assert!(
            largest <= wire_len * 2,
            "largest allocation {largest} for {wire_len} wire bytes"
        );
    }
}
