use std::sync::Arc;

use datafusion::prelude::SessionContext;
use exoware_sdk::ReadSession;

/// Copy a DataFusion context and install `session` for Store-backed reads.
///
/// The returned context and all clones of `session` share observations across
/// separately executed SQL statements.
pub fn query_context_with_session(ctx: &SessionContext, session: ReadSession) -> SessionContext {
    let mut state = ctx.state();
    state.config_mut().set_extension(Arc::new(session));
    SessionContext::new_with_state(state)
}
