//! SQL context construction and Store read-session lookup.

use std::sync::Arc;

use datafusion::execution::session_state::SessionStateBuilder;
use datafusion::prelude::{SessionConfig, SessionContext};
use exoware_sdk::{PrefixedStoreClient, ReadSession};

use crate::aggregate::{KvAggregatePushdownRule, KvQueryPlanner};

/// Creates a DataFusion context with a monotonic read session and Store aggregate reduction.
pub fn session_context(client: PrefixedStoreClient) -> SessionContext {
    SessionContext::new_with_state(
        session_state_builder(ReadSession::monotonic(client, None)).build(),
    )
}

/// Creates a DataFusion session builder using `session` for Store-backed reads.
///
/// Configure the returned builder before passing its state to
/// [`SessionContext::new_with_state`], then register tables with
/// [`crate::KvSchema::register_all`].
/// Mutate the builder's existing configuration to retain its read session.
///
/// A custom query planner must include [`crate::KvAggregateExtensionPlanner`] in its
/// [`datafusion::physical_planner::DefaultPhysicalPlanner`] to plan Store aggregates.
pub fn session_state_builder(session: ReadSession) -> SessionStateBuilder {
    let mut config = SessionConfig::new();
    config.set_extension(Arc::new(session));
    SessionStateBuilder::new_with_default_features()
        .with_config(config)
        .with_optimizer_rule(Arc::new(KvAggregatePushdownRule::new()))
        .with_query_planner(Arc::new(KvQueryPlanner))
}

/// Copy a DataFusion context and install `session` for Store-backed reads.
///
/// The returned context and all clones of `session` share observations across
/// separately executed SQL statements. All Store-backed providers must use the
/// same Store as `session`.
pub fn with_read_session(ctx: &SessionContext, session: ReadSession) -> SessionContext {
    let mut state = ctx.state();
    state.config_mut().set_extension(Arc::new(session));
    SessionContext::new_with_state(state)
}

// Keep the provider's client while sharing observations from the context.
pub(crate) fn read_session(config: &SessionConfig, client: &PrefixedStoreClient) -> ReadSession {
    config
        .get_extension::<ReadSession>()
        .map(|session| session.with_client(client.clone()))
        .unwrap_or_else(|| ReadSession::monotonic(client.clone(), None))
}
