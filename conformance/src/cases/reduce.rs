//! Reductions through the Reduce RPC.

use crate::{
    rpc,
    support::{commit, fresh, stored_row},
    Backend,
};
use bytes::Bytes;
use exoware_sdk::{
    kv_codec::{KvExpr, KvFieldKind, KvFieldRef, KvReducedValue},
    query::{ReduceRequest, ReduceResponseView},
    to_domain_reduce_response, to_proto_reduce_params, RangeReduceOp, RangeReduceRequest,
    RangeReduceResponse, RangeReducerSpec,
};
use exoware_server::{connect_stack, AppState};
use std::sync::Arc;

const fn value_field(index: u16, kind: KvFieldKind) -> KvExpr {
    KvExpr::Field(KvFieldRef::Value {
        index,
        kind,
        nullable: true,
    })
}

/// Sends a Reduce over the `a/` rows and returns its single response.
async fn reduce<S: exoware_server::StoreEngine>(
    store: Arc<S>,
    group_by: Vec<KvExpr>,
) -> RangeReduceResponse {
    let request = ReduceRequest {
        start: b"a/".to_vec(),
        end: b"a/\xff".to_vec(),
        params: Some(to_proto_reduce_params(RangeReduceRequest {
            reducers: vec![
                RangeReducerSpec {
                    op: RangeReduceOp::CountAll,
                    expr: None,
                    filter: None,
                },
                RangeReducerSpec {
                    op: RangeReduceOp::SumField,
                    expr: Some(value_field(0, KvFieldKind::Int64)),
                    filter: None,
                },
            ],
            group_by,
            filter: None,
        }))
        .into(),
        ..Default::default()
    };
    let mut stack = connect_stack(AppState::new(store));
    let mut envelopes = rpc::open_stream(&mut stack, rpc::REDUCE, &request).await;
    let mut responses = Vec::new();
    loop {
        match envelopes
            .next()
            .await
            .expect("the stream must end with an end of stream envelope")
        {
            rpc::Envelope::Message(payload) => {
                let view =
                    <ReduceResponseView<'_> as buffa::MessageView<'_>>::decode_view(&payload)
                        .expect("a Reduce response must decode");
                responses.push(
                    to_domain_reduce_response(&view)
                        .expect("a Reduce response must convert to its domain type"),
                );
            }
            rpc::Envelope::End(error) => {
                assert!(
                    error.is_none(),
                    "the stream must end without an error, got {error:?}"
                );
                break;
            }
        }
    }
    assert_eq!(
        responses.len(),
        1,
        "a Reduce must stream exactly one response, got {responses:?}"
    );
    responses.remove(0)
}

pub async fn rpc_reduce_counts_sums_and_groups<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    commit(
        backend,
        &store,
        vec![
            (Bytes::from_static(b"a/1"), stored_row(10, "Alpha")),
            (Bytes::from_static(b"a/2"), stored_row(20, "ALPHA")),
            (Bytes::from_static(b"a/3"), stored_row(30, "beta")),
            (Bytes::from_static(b"b/1"), stored_row(1000, "outside")),
        ],
    )
    .await;

    let scalar = reduce(Arc::new(store.clone()), Vec::new()).await;
    let values: Vec<_> = scalar
        .results
        .into_iter()
        .map(|result| result.value)
        .collect();
    assert_eq!(
        values,
        vec![
            Some(KvReducedValue::UInt64(3)),
            Some(KvReducedValue::Int64(60))
        ]
    );
    assert!(scalar.groups.is_empty());

    let name = value_field(1, KvFieldKind::Utf8);
    let grouped = reduce(Arc::new(store.clone()), vec![KvExpr::Lower(Box::new(name))]).await;
    let mut groups: Vec<_> = grouped
        .groups
        .into_iter()
        .map(|group| {
            let results: Vec<_> = group
                .results
                .into_iter()
                .map(|result| result.value)
                .collect();
            (group.group_values, results)
        })
        .collect();
    groups.sort_by(|a, b| format!("{:?}", a.0).cmp(&format!("{:?}", b.0)));
    assert_eq!(
        groups,
        vec![
            (
                vec![Some(KvReducedValue::Utf8("alpha".to_string()))],
                vec![
                    Some(KvReducedValue::UInt64(2)),
                    Some(KvReducedValue::Int64(30))
                ]
            ),
            (
                vec![Some(KvReducedValue::Utf8("beta".to_string()))],
                vec![
                    Some(KvReducedValue::UInt64(1)),
                    Some(KvReducedValue::Int64(30))
                ]
            ),
        ]
    );
    backend.close(store).await;
}
