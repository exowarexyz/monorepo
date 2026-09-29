//! SQL contexts with shared Store read sessions.

use std::sync::Arc;

use datafusion::catalog::{CatalogProvider, TableProvider};
use datafusion::common::{DataFusionError, Result, TableReference};
use datafusion::dataframe::DataFrame;
use datafusion::execution::runtime_env::RuntimeEnv;
use datafusion::execution::session_state::SessionStateBuilder;
use datafusion::logical_expr::{AggregateUDF, ScalarUDF, WindowUDF};
use datafusion::prelude::{SessionConfig, SessionContext as DataFusionContext};
use exoware_sdk::{PrefixedStoreClient, ReadSession};

use crate::aggregate::{KvAggregatePushdownRule, KvQueryPlanner};
use crate::KvSchema;

/// A SQL context whose Store reads share a read session across statements.
#[derive(Clone)]
pub struct SqlContext {
    inner: DataFusionContext,
}

impl SqlContext {
    /// Creates a context with a monotonic read session and Store aggregate reduction.
    pub fn new(client: PrefixedStoreClient) -> Self {
        Self::builder(client).build()
    }

    pub fn builder(client: PrefixedStoreClient) -> SqlContextBuilder {
        SqlContextBuilder {
            state: SessionStateBuilder::new_with_default_features()
                .with_optimizer_rule(Arc::new(KvAggregatePushdownRule::new()))
                .with_query_planner(Arc::new(KvQueryPlanner)),
            session: ReadSession::monotonic(client, None),
        }
    }

    /// Accesses DataFusion functionality beyond the SQL context's convenience methods.
    pub fn datafusion(&self) -> &DataFusionContext {
        &self.inner
    }

    pub fn read_session(&self) -> Arc<ReadSession> {
        self.inner
            .copied_config()
            .get_extension::<ReadSession>()
            .expect("SQL context has a read session")
    }

    /// Copies the context with `session`, sharing its registered catalogs.
    /// Store-backed providers must use the same Store as the supplied session.
    pub fn with_read_session(&self, session: ReadSession) -> Self {
        let mut state = self.inner.state();
        state.config_mut().set_extension(Arc::new(session));
        Self {
            inner: DataFusionContext::new_with_state(state),
        }
    }

    pub async fn sql(&self, sql: &str) -> Result<DataFrame> {
        self.inner.sql(sql).await
    }

    pub fn register_schema(&self, schema: KvSchema) -> Result<()> {
        schema.register_all(self)
    }

    pub fn register_table(
        &self,
        name: impl Into<TableReference>,
        provider: Arc<dyn TableProvider>,
    ) -> Result<Option<Arc<dyn TableProvider>>> {
        self.inner.register_table(name, provider)
    }

    pub fn deregister_table(
        &self,
        name: impl Into<TableReference>,
    ) -> Result<Option<Arc<dyn TableProvider>>> {
        self.inner.deregister_table(name)
    }

    pub async fn table(&self, name: impl Into<TableReference>) -> Result<DataFrame> {
        self.inner.table(name).await
    }

    pub async fn table_provider(
        &self,
        name: impl Into<TableReference>,
    ) -> Result<Arc<dyn TableProvider>> {
        self.inner.table_provider(name).await
    }

    pub fn register_catalog(
        &self,
        name: impl Into<String>,
        catalog: Arc<dyn CatalogProvider>,
    ) -> Option<Arc<dyn CatalogProvider>> {
        self.inner.register_catalog(name, catalog)
    }

    pub fn register_udf(&self, function: ScalarUDF) {
        self.inner.register_udf(function);
    }

    pub fn register_udaf(&self, function: AggregateUDF) {
        self.inner.register_udaf(function);
    }

    pub fn register_udwf(&self, function: WindowUDF) {
        self.inner.register_udwf(function);
    }
}

/// Configures a SQL context, installing its read session when built.
pub struct SqlContextBuilder {
    state: SessionStateBuilder,
    session: ReadSession,
}

impl SqlContextBuilder {
    pub fn with_read_session(mut self, session: ReadSession) -> Self {
        self.session = session;
        self
    }

    pub fn with_config(mut self, config: SessionConfig) -> Self {
        self.state = self.state.with_config(config);
        self
    }

    pub fn with_runtime_env(mut self, runtime: Arc<RuntimeEnv>) -> Self {
        self.state = self.state.with_runtime_env(runtime);
        self
    }

    /// Customizes DataFusion planning and execution before the read session is installed.
    /// A custom query planner must include [`crate::KvAggregateExtensionPlanner`].
    pub fn configure_datafusion(
        mut self,
        configure: impl FnOnce(SessionStateBuilder) -> SessionStateBuilder,
    ) -> Self {
        self.state = configure(self.state);
        self
    }

    pub fn build(self) -> SqlContext {
        let mut state = self.state.build();
        state.config_mut().set_extension(Arc::new(self.session));
        SqlContext {
            inner: DataFusionContext::new_with_state(state),
        }
    }
}

// Keep the provider's client while sharing observations from the context.
pub(crate) fn read_session(
    config: &SessionConfig,
    client: &PrefixedStoreClient,
) -> Result<ReadSession> {
    config
        .get_extension::<ReadSession>()
        .map(|session| session.with_client(client.clone()))
        .ok_or_else(|| {
            DataFusionError::Configuration(
                "Store reads require a ReadSession; use exoware_sql::SqlContext".into(),
            )
        })
}
