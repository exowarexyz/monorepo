//! Nesting limits for SQL that remote callers submit.
//!
//! sqlparser and DataFusion parse, plan, and run a statement with recursion that follows the
//! statement's shape, and a stack overflow aborts the whole process. A parser builds some
//! shapes in a loop, such as a chain of operators, of subscripts, of set operations, or of
//! joins, so its recursion limit does not bound how deep they nest. Other shapes are small in
//! the text and large in the plan, such as a common table expression that is read many times.
//!
//! The service checks a statement three times. It reads the tokens before parsing, because
//! the parsers recurse through data types and wrapped statements before there is a syntax
//! tree. It measures the syntax tree before planning, because DataFusion recurses through
//! expressions, queries, and set operations while it plans. It measures the plan before
//! anything optimizes or runs it, because the optimizer and the operators recurse through
//! every step of the plan. A predicate is one expression, so it is checked the first two
//! times.

use datafusion::{
    arrow::datatypes::DataType as ArrowType,
    common::{
        config::Dialect,
        plan_err,
        tree_node::{TreeNode, TreeNodeRecursion, TreeNodeVisitor},
        DFSchema, Result as DataFusionResult,
    },
    execution::session_state::SessionState,
    logical_expr::{Expr as PlanExpr, ExprSchemable, LogicalPlan},
    sql::{
        parser::{CopyToSource, Statement as ParsedStatement},
        sqlparser::{
            ast::{
                DataType, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments,
                ObjectName, Query, SetExpr, Statement, TableFactor, UnaryOperator, Value, Visit,
                Visitor, WindowType,
            },
            dialect::dialect_from_str,
            keywords::Keyword,
            tokenizer::{Token, Tokenizer},
        },
    },
};
use std::{
    future::{poll_fn, Future},
    ops::ControlFlow,
    pin::pin,
};

/// Budget for nesting the expressions and queries of one statement or predicate. Every
/// expression spends [`NESTING_COST`] of it on itself and what it encloses, so expressions
/// nest 24 deep, which is an operand inside 23 function calls, `CASE` expressions, pairs of
/// parentheses, or unary operators. A binary operator spends [`OPERATOR_COST`] and a query
/// inside another [`QUERY_COST`]. The costs follow the stack that a debug build needs to plan
/// one more level of each kind, and they share one budget so that a statement that mixes them
/// is bounded as well.
pub(crate) const NESTING_BUDGET: usize = 96;

/// Share of [`NESTING_BUDGET`] that an expression spends on what it encloses. A dotted name
/// and a chain of field accesses spend it once for every part, because DataFusion plans each
/// part as a function call around the parts before it.
pub(crate) const NESTING_COST: usize = 4;

/// Share of [`NESTING_BUDGET`] that a binary operator spends on its operands, whether it is
/// `AND`, `OR`, a comparison, arithmetic, or `||`. DataFusion plans a chain of operators in
/// a loop and walks it afterwards with about a quarter of the stack that a level of any
/// other expression takes. A searched `CASE` that may return Booleans spends it for every
/// `WHEN`, because DataFusion rewrites such a `CASE` into an `OR` of its branches.
pub(crate) const OPERATOR_COST: usize = 1;

/// Share of [`NESTING_BUDGET`] that a query spends on what it holds when it is inside
/// another query, as a derived table, a subquery, or a common table expression.
pub(crate) const QUERY_COST: usize = 8;

/// Budget for nesting a statement's plan, measured on the plan that DataFusion makes of the
/// statement before it optimizes it. The steps between the result and each table spend it,
/// which are the projections, filters, joins, set operations, and other nodes of the plan.
/// DataFusion's optimizer and operators recurse through a plan one step at a time, and some
/// of them do not grow the stack. A step spends one level, or [`JOIN_COST`] or
/// [`FILTER_COST`], and one more for every level that its deepest expression nests. The
/// optimizer merges the expressions of consecutive projections into one and moves filters
/// through them, and the levels of every step on a path bound whatever it merges. The costs
/// follow the stack that a debug build needs to run one more step of each kind, and the
/// budget is the largest at which a plan takes no more stack than an expression at its
/// limit does.
pub(crate) const PLAN_BUDGET: usize = 192;

/// Share of [`PLAN_BUDGET`] that a join, an aggregation, a `DISTINCT`, a window, and a limit
/// spend. Each subquery in a step's expressions spends it as well, on that step, because the
/// optimizer turns the subquery into a join above the step's input.
pub(crate) const JOIN_COST: usize = 3;

/// Share of [`PLAN_BUDGET`] that a filter spends. The optimizer moves a filter through the
/// steps under it and joins it with the filters it meets.
pub(crate) const FILTER_COST: usize = 5;

/// Deepest nesting of queries, counting the statement's own query, each derived table and
/// common table expression, and each subquery in an expression. A nested query costs more
/// stack to plan than a join does, and each subquery that an expression nests in another
/// doubles the time planning takes.
pub(crate) const MAX_QUERY_DEPTH: usize = 8;

/// Deepest nesting of statements. An `EXPLAIN`, a `DESCRIBE`, and a `PREPARE` each nest the
/// statement they wrap one level deeper.
pub(crate) const MAX_STATEMENT_DEPTH: usize = 3;

/// Deepest nesting of a data type. A type nests through a constructor such as `ARRAY<...>`,
/// `STRUCT<...>`, or `Nullable(...)`, through each `[]` suffix, and through each
/// parenthesis of a type that `arrow_cast` reads from a string. Neither parser limits that
/// recursion, and Arrow builds and drops a nested type with recursion of its own.
pub(crate) const MAX_TYPE_DEPTH: usize = 8;

/// Most relations a statement reads once every common table expression it names is replaced
/// by the relations that expression reads. DataFusion plans a copy of the expression at each
/// place that names it, so a chain of expressions that each read the previous one several
/// times multiplies into a plan far larger than its text, and the time to plan it grows with
/// the relations.
pub(crate) const MAX_RELATIONS: usize = 1024;

/// Most expressions and relations a statement holds once every common table expression it
/// names is replaced by its body. A common table expression that reads no table still
/// copies its rows or its select list to every place that names it. Each expression and
/// relation takes at least a character, so a statement of the greatest length the service
/// admits never holds more than this without common table expressions.
pub(crate) const MAX_NODES: usize = 64 * 1024;

/// Stack that parsing and planning reserve before they read a statement.
const STACK_BYTES: usize = 512 * 1024;

/// Further stack that parsing and planning reserve for each byte of a statement.
const STACK_BYTES_PER_SQL_BYTE: usize = 256;

/// Further stack that parsing reserves for each level of the parser's recursion limit when
/// a statement may hold a list of statements. A debug build of the parser takes up to 75 KiB
/// to read a statement inside another.
const STACK_BYTES_PER_STATEMENT: usize = 96 * 1024;

/// Words that begin a statement that holds no other statement in any dialect.
const PLAIN_STATEMENTS: [Keyword; 6] = [
    Keyword::SELECT,
    Keyword::WITH,
    Keyword::VALUES,
    Keyword::INSERT,
    Keyword::UPDATE,
    Keyword::DELETE,
];

/// Functions whose second argument is a data type written in a string.
const TYPE_STRING_FUNCTIONS: [&str; 2] = ["arrow_cast", "arrow_try_cast"];

/// Limit that a statement or predicate exceeds.
enum Exceeded {
    Expression,
    Plan,
    Nodes,
    Query,
    Relations,
    Statement,
    Type,
    TypeString,
}

impl Exceeded {
    fn into_error<T>(self) -> DataFusionResult<T> {
        let (what, limit) = match self {
            Self::Expression => {
                let levels = NESTING_BUDGET / NESTING_COST;
                return plan_err!(
                    "expressions nested more than {levels} deep, where a binary operator counts \
                     as {OPERATOR_COST}/{NESTING_COST} of a level and a query inside another \
                     adds {} levels, are not supported by the SQL service",
                    QUERY_COST / NESTING_COST
                );
            }
            Self::Plan => {
                return plan_err!(
                    "plans nested more than {PLAN_BUDGET} levels deep, where a join, an \
                     aggregation, a window, a limit, and a subquery count as {JOIN_COST} \
                     levels, a filter as {FILTER_COST}, and the deepest expression of each \
                     step as the levels it nests, are not supported by the SQL service"
                );
            }
            Self::Nodes => {
                return plan_err!(
                    "statements that hold more than {MAX_NODES} expressions and relations, \
                     counting those of a common table expression wherever it is named, are \
                     not supported by the SQL service"
                );
            }
            Self::Relations => {
                return plan_err!(
                    "statements that read more than {MAX_RELATIONS} relations, counting those \
                     of a common table expression wherever it is named, are not supported by \
                     the SQL service"
                );
            }
            Self::TypeString => {
                return plan_err!(
                    "a data type that arrow_cast is not given as a string literal is not \
                     supported by the SQL service"
                );
            }
            Self::Query => ("queries", MAX_QUERY_DEPTH),
            Self::Statement => ("statements", MAX_STATEMENT_DEPTH),
            Self::Type => ("data types", MAX_TYPE_DEPTH),
        };
        plan_err!("{what} nested more than {limit} deep are not supported by the SQL service")
    }
}

/// What a statement or a common table expression holds, counting what the expressions it
/// names hold at every place that names them.
#[derive(Clone, Copy, Default)]
struct Size {
    /// Relations it reads.
    relations: usize,
    /// Expressions and relations in it.
    nodes: usize,
}

/// A common table expression that the relations being visited can name.
struct CommonTable {
    /// Name the `WITH` clause gives the expression.
    name: String,
    size: Size,
}

/// What the walk has seen of a query it is inside.
#[derive(Default)]
struct QueryScope {
    /// Common table expressions that were in scope when the query began.
    tables: usize,
    /// Name the query defines when it is the body of a common table expression.
    name: Option<String>,
    /// What the query holds so far when it is the body of a common table expression.
    size: Size,
    /// Share of [`NESTING_BUDGET`] the query spends on what it holds.
    cost: usize,
    /// Windows that the query's window functions are computed over.
    windows: Vec<WindowType>,
}

/// Measures nesting while sqlparser walks a syntax tree, and stops the walk at the first
/// node past a limit so that it descends no further than the limits allow.
#[derive(Default)]
struct NestingVisitor {
    /// Share of [`NESTING_BUDGET`] spent by the expressions and queries that enclose the
    /// node being visited.
    spent: usize,
    /// Queries that enclose the node being visited, innermost last.
    queries: Vec<QueryScope>,
    /// What the statement holds outside any query.
    statement: QueryScope,
    /// Common table expressions in scope, innermost `WITH` clause last.
    tables: Vec<CommonTable>,
    /// Bodies of common table expressions that the walk has yet to reach, each with the name
    /// it defines. The pointers identify the bodies and are never read through.
    bodies: Vec<(*const Query, String)>,
    /// Statements that enclose the node being visited.
    statements: usize,
}

impl NestingVisitor {
    /// Spends part of [`NESTING_BUDGET`] on what the node being visited holds.
    const fn spend(&mut self, cost: usize) -> ControlFlow<Exceeded> {
        self.spent += cost;
        if self.spent > NESTING_BUDGET {
            return ControlFlow::Break(Exceeded::Expression);
        }
        ControlFlow::Continue(())
    }

    /// Adds what the node being visited holds to the common table expression being visited,
    /// or to the statement when there is none. A statement's plan holds a copy of an
    /// expression at every place that names the expression and nowhere else.
    fn hold(&mut self, relations: usize, nodes: usize) -> ControlFlow<Exceeded> {
        let scope = self
            .queries
            .iter_mut()
            .rev()
            .find(|query| query.name.is_some())
            .unwrap_or(&mut self.statement);
        scope.size.relations = scope.size.relations.saturating_add(relations);
        scope.size.nodes = scope.size.nodes.saturating_add(nodes);
        if scope.size.relations > MAX_RELATIONS {
            return ControlFlow::Break(Exceeded::Relations);
        }
        if scope.size.nodes > MAX_NODES {
            return ControlFlow::Break(Exceeded::Nodes);
        }
        ControlFlow::Continue(())
    }

    /// Size of the common table expression that `name` may refer to. DataFusion looks
    /// an expression up by the parts of the name joined with dots, so a name of several
    /// parts finds an expression whose quoted name has the same dots. Names compare without
    /// case, and the largest match counts, so a quoted name or an inner `WITH` clause that
    /// reuses a name never counts for less than DataFusion plans.
    fn common_table(&self, name: &ObjectName) -> Option<Size> {
        let parts: Option<Vec<_>> = name
            .0
            .iter()
            .map(|part| part.as_ident().map(|part| part.value.as_str()))
            .collect();
        let name = parts?.join(".");
        self.tables
            .iter()
            .filter(|table| table.name.eq_ignore_ascii_case(&name))
            .map(|table| table.size)
            .reduce(|largest, size| Size {
                relations: largest.relations.max(size.relations),
                nodes: largest.nodes.max(size.nodes),
            })
    }

    /// Counts the window of a window function toward the query that computes it. DataFusion
    /// plans one window step for every distinct partitioning and ordering among a query's
    /// windows, and it takes time that grows with the cube of their number to do so, so a
    /// query with more of them than a plan has room for is rejected before it is planned.
    fn compute(&mut self, expr: &Expr) -> ControlFlow<Exceeded> {
        let Expr::Function(Function {
            over: Some(window), ..
        }) = expr
        else {
            return ControlFlow::Continue(());
        };
        let mut window = window.clone();
        if let WindowType::WindowSpec(window) = &mut window {
            window.window_frame = None;
        }
        let scope = self.queries.last_mut().unwrap_or(&mut self.statement);
        if !scope.windows.contains(&window) {
            scope.windows.push(window);
        }
        if scope.windows.len() > PLAN_BUDGET / JOIN_COST {
            return ControlFlow::Break(Exceeded::Plan);
        }
        ControlFlow::Continue(())
    }

    fn verify(&mut self, node: &impl Visit) -> DataFusionResult<()> {
        match node.visit(self) {
            ControlFlow::Continue(()) => Ok(()),
            ControlFlow::Break(exceeded) => exceeded.into_error(),
        }
    }
}

impl Visitor for NestingVisitor {
    type Break = Exceeded;

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Exceeded> {
        self.spend(expression_cost(expr))?;
        self.hold(0, 1)?;
        verify_type_string(expr)
    }

    fn post_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Exceeded> {
        self.spent -= expression_cost(expr);
        // The expressions of the window are within the budget by now, so the copy is small.
        self.compute(expr)
    }

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Exceeded> {
        if self.queries.len() == MAX_QUERY_DEPTH {
            return ControlFlow::Break(Exceeded::Query);
        }
        // DataFusion plans set operations with recursion and each pipe operator as a step,
        // so a query with more of either than a plan has levels is rejected before it is
        // planned.
        if set_operation_depth(&query.body).max(query.pipe_operators.len()) > PLAN_BUDGET {
            return ControlFlow::Break(Exceeded::Plan);
        }
        let name = self
            .bodies
            .iter()
            .position(|(body, _)| std::ptr::eq(*body, query))
            .map(|body| self.bodies.swap_remove(body).1);
        for table in query.with.iter().flat_map(|with| &with.cte_tables) {
            let body = std::ptr::from_ref::<Query>(&table.query);
            self.bodies.push((body, table.alias.name.value.clone()));
        }
        let cost = if self.queries.is_empty() {
            0
        } else {
            QUERY_COST
        };
        self.queries.push(QueryScope {
            tables: self.tables.len(),
            name,
            cost,
            ..Default::default()
        });
        self.spend(cost)
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Exceeded> {
        let Some(query) = self.queries.pop() else {
            return ControlFlow::Continue(());
        };
        self.spent -= query.cost;
        // The expressions this query defined go out of scope, and the query itself comes
        // into scope when it is one.
        self.tables.truncate(query.tables);
        if let Some(name) = query.name {
            self.tables.push(CommonTable {
                name,
                size: query.size,
            });
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, relation: &TableFactor) -> ControlFlow<Exceeded> {
        // A derived table and a parenthesized join read through the relations inside them,
        // and a common table expression is at least the one relation that names it.
        let size = match relation {
            TableFactor::Table { name, .. } => self.common_table(name).unwrap_or_default(),
            TableFactor::Derived { .. } | TableFactor::NestedJoin { .. } => {
                return self.hold(0, 1);
            }
            _ => Size::default(),
        };
        self.hold(size.relations.max(1), size.nodes.max(1))
    }

    fn pre_visit_statement(&mut self, _statement: &Statement) -> ControlFlow<Exceeded> {
        self.statements += 1;
        if self.statements > MAX_STATEMENT_DEPTH {
            return ControlFlow::Break(Exceeded::Statement);
        }
        ControlFlow::Continue(())
    }

    fn post_visit_statement(&mut self, _statement: &Statement) -> ControlFlow<Exceeded> {
        self.statements -= 1;
        ControlFlow::Continue(())
    }
}

/// Share of [`NESTING_BUDGET`] that `expr` spends on the expressions inside it.
fn expression_cost(expr: &Expr) -> usize {
    match expr {
        Expr::BinaryOp { .. } => OPERATOR_COST,
        Expr::CompoundIdentifier(parts) => NESTING_COST * parts.len(),
        Expr::CompoundFieldAccess { access_chain, .. } => NESTING_COST * access_chain.len().max(1),
        // DataFusion turns a searched `CASE` into `OR`s when every result simplifies to a
        // Boolean literal, which no result of another type can.
        Expr::Case {
            operand: None,
            conditions,
            ..
        } if !conditions.iter().any(|when| is_other_literal(&when.result)) => {
            NESTING_COST + OPERATOR_COST * conditions.len()
        }
        _ => NESTING_COST,
    }
}

/// Whether `expr` is a literal of a type other than Boolean, which no simplification turns
/// into a Boolean. A `NULL` and a placeholder can stand for a Boolean, and a type with a
/// name of the caller's choosing may be one.
fn is_other_literal(expr: &Expr) -> bool {
    let is_other_type = |data_type: &DataType| {
        !matches!(
            data_type,
            DataType::Bool | DataType::Boolean | DataType::Custom(..)
        )
    };
    match expr {
        Expr::Value(literal) => !matches!(
            literal.value,
            Value::Boolean(_) | Value::Null | Value::Placeholder(_)
        ),
        Expr::UnaryOp {
            op: UnaryOperator::Minus | UnaryOperator::Plus,
            expr,
        } => {
            matches!(expr.as_ref(), Expr::Value(literal) if matches!(literal.value, Value::Number(..)))
        }
        Expr::TypedString(literal) => is_other_type(&literal.data_type),
        Expr::Cast {
            expr, data_type, ..
        } => matches!(expr.as_ref(), Expr::Value(_)) && is_other_type(data_type),
        _ => false,
    }
}

/// Rejects a call that has a function parse a data type nested past [`MAX_TYPE_DEPTH`], or
/// parse one from anything but a string literal. DataFusion folds a constant argument into a
/// literal before the function reads it, so only a literal shows the type the function gets.
fn verify_type_string(expr: &Expr) -> ControlFlow<Exceeded> {
    let Expr::Function(function) = expr else {
        return ControlFlow::Continue(());
    };
    let name = function.name.0.last().and_then(|part| part.as_ident());
    if !name.is_some_and(|name| {
        TYPE_STRING_FUNCTIONS
            .iter()
            .any(|function| name.value.eq_ignore_ascii_case(function))
    }) {
        return ControlFlow::Continue(());
    }
    let FunctionArguments::List(arguments) = &function.args else {
        return ControlFlow::Continue(());
    };
    let Some(argument) = arguments.args.get(1) else {
        return ControlFlow::Continue(());
    };
    let FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(literal))) = argument else {
        return ControlFlow::Break(Exceeded::TypeString);
    };
    let Some(data_type) = literal.value.clone().into_string() else {
        return ControlFlow::Break(Exceeded::TypeString);
    };
    if type_string_depth(&data_type) > MAX_TYPE_DEPTH {
        return ControlFlow::Break(Exceeded::Type);
    }
    ControlFlow::Continue(())
}

/// Deepest nesting of parentheses that Arrow's parser sees in a data type written as a
/// string. That parser reads a name between quotes as one token, so a parenthesis inside
/// the quotes nests nothing. After a backslash it reads on past the quote that would end
/// the name, and how far depends on the rest of the string. From the first backslash in a
/// name on, every `(` therefore counts and no `)` does.
fn type_string_depth(data_type: &str) -> usize {
    let (mut open, mut deepest) = (0usize, 0);
    let (mut quote, mut escaped) = (None, false);
    for character in data_type.chars() {
        match (quote, character) {
            (None, '"' | '\'') => quote = Some(character),
            (None, ')') => open = open.saturating_sub(1),
            (Some(_), '\\') => escaped = true,
            (Some(closing), _) if character == closing && !escaped => quote = None,
            (_, '(') if quote.is_none() || escaped => {
                open += 1;
                deepest = deepest.max(open);
            }
            _ => {}
        }
    }
    deepest
}

/// Deepest nesting of set operations in a query body. A parser chains `UNION`, `INTERSECT`,
/// and `EXCEPT` in a loop and no visitor hook fires between their operands, so the tree is
/// measured here without recursion.
fn set_operation_depth(body: &SetExpr) -> usize {
    let mut deepest = 0;
    let mut pending = vec![(body, 0)];
    while let Some((operand, depth)) = pending.pop() {
        if let SetExpr::SetOperation { left, right, .. } = operand {
            deepest = deepest.max(depth + 1);
            pending.push((left, depth + 1));
            pending.push((right, depth + 1));
        }
    }
    deepest
}

/// What a word may nest when a bracket follows it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Constructor {
    /// A data type inside `<` or `(`, depending on the dialect.
    Angled,
    /// A data type inside `(`.
    Parenthesized,
    /// A data type inside `(` in some places and a query or a table function in others.
    Shared,
}

impl Constructor {
    const fn of(keyword: Keyword) -> Option<Self> {
        match keyword {
            Keyword::ARRAY | Keyword::STRUCT | Keyword::MAP => Some(Self::Angled),
            Keyword::NULLABLE | Keyword::LOWCARDINALITY | Keyword::NESTED | Keyword::TUPLE => {
                Some(Self::Parenthesized)
            }
            Keyword::UNION | Keyword::TABLE => Some(Self::Shared),
            _ => None,
        }
    }
}

/// A bracket that is open at a token.
enum Bracket {
    /// `<` of a type, with the words read since it or since its last comma.
    Angle(usize),
    /// `(` of a type.
    Type,
    /// `(` after a word that is [`Constructor::Shared`].
    Shared,
    /// Any other `(`.
    Group,
    /// `[`, with the nesting of the type it follows.
    Suffix(usize),
}

/// The tokens of `sql` other than white space and comments, or nothing when the SQL has no
/// dialect or does not split into tokens, which fails the same way in the parser.
fn tokens(dialect: &Dialect, sql: &str) -> Option<Vec<Token>> {
    let dialect = dialect_from_str(dialect)?;
    let mut tokens = Tokenizer::new(dialect.as_ref(), sql).tokenize().ok()?;
    tokens.retain(|token| !matches!(token, Token::Whitespace(_)));
    Some(tokens)
}

/// Rejects SQL that writes a data type nested past [`MAX_TYPE_DEPTH`].
///
/// The check reads tokens because the parser recurses through a type without counting or
/// growing the stack, and it tries to read a type wherever an expression may begin. A type
/// nests one level inside each `<` or `(` that follows the word of a [`Constructor`] and one
/// level for each `[]` group after it, as in `ARRAY<INT[]>[]`, which nests three deep.
///
/// Tokens cannot tell every type from what looks like one, so these count as well:
/// - A function call that a constructor's word names, such as `struct(...)`.
/// - A chain of subscripts, such as `x[1][2]`.
/// - A `<` between a column named `array`, `struct`, or `map` and another name. It stays
///   open until a `>` or the parenthesis around it closes it, and a second one counts only
///   where a type could begin inside the first, which is after its `<`, after a comma, or
///   after one name. A select list of nine such comparisons is therefore rejected.
///
/// `UNION (` and `TABLE (` begin a type in some places and a query or a table function in
/// others. They are counted apart from the rest and up to the same limit, so a type that
/// nests through them and through other constructors can be twice as deep as the limit.
fn verify_type_nesting(tokens: &[Token]) -> DataFusionResult<()> {
    // Open brackets, each with the deepest type completed inside it.
    let mut open: Vec<(Bracket, usize)> = Vec::new();
    // Open brackets that are certainly, and that are possibly, those of a type.
    let (mut types, mut shared) = (0usize, 0usize);
    // The previous token may have named a constructor or completed a type nested this deep.
    let (mut constructor, mut completed) = (None, 0);
    for (index, token) in tokens.iter().enumerate() {
        let (named, followed) = (constructor.take(), std::mem::take(&mut completed));
        match token {
            Token::Word(word) => {
                // A type begins an angle's field or follows the field's name.
                let begins = match open.last_mut() {
                    Some((Bracket::Angle(words), _)) => {
                        *words += 1;
                        *words <= 2
                    }
                    _ => true,
                };
                if begins && word.quote_style.is_none() {
                    constructor = Constructor::of(word.keyword);
                }
            }
            Token::Comma => {
                if let Some((Bracket::Angle(words), _)) = open.last_mut() {
                    *words = 0;
                }
            }
            // A type begins with a word, so nothing else after `<` makes it a type's.
            Token::Lt
                if named == Some(Constructor::Angled)
                    && matches!(tokens.get(index + 1), Some(Token::Word(_))) =>
            {
                open.push((Bracket::Angle(0), 0));
                types += 1;
            }
            // An angle closes where it opened. Inside a parenthesis that it encloses, `>`
            // compares two values.
            Token::Gt | Token::ShiftRight => {
                for _ in 0..if matches!(token, Token::Gt) { 1 } else { 2 } {
                    let Some((Bracket::Angle(_), inner)) = open.last() else {
                        break;
                    };
                    completed = inner + 1;
                    open.pop();
                    types -= 1;
                    if let Some((_, inner)) = open.last_mut() {
                        *inner = (*inner).max(completed);
                    }
                }
            }
            Token::LParen => {
                let bracket = match named {
                    Some(Constructor::Shared) => {
                        shared += 1;
                        Bracket::Shared
                    }
                    Some(_) => {
                        types += 1;
                        Bracket::Type
                    }
                    None => Bracket::Group,
                };
                open.push((bracket, 0));
            }
            Token::LBracket => open.push((Bracket::Suffix(followed), 0)),
            // A closing bracket also ends the angles that are open inside it, which were
            // comparisons.
            Token::RParen | Token::RBracket => {
                while let Some((bracket, inner)) = open.pop() {
                    match (bracket, token) {
                        (Bracket::Angle(_), _) => {
                            types -= 1;
                            continue;
                        }
                        (Bracket::Type, Token::RParen) => {
                            types -= 1;
                            completed = inner + 1;
                        }
                        (Bracket::Shared, Token::RParen) => {
                            shared -= 1;
                            completed = inner;
                        }
                        (Bracket::Suffix(follows), Token::RBracket) => completed = follows + 1,
                        (Bracket::Group, Token::RParen) => {}
                        // The brackets do not pair, which the parser rejects.
                        (bracket, _) => open.push((bracket, inner)),
                    }
                    break;
                }
                if let Some((_, inner)) = open.last_mut() {
                    *inner = (*inner).max(completed);
                }
            }
            _ => {}
        }
        let suffixes = match open.last() {
            Some((Bracket::Suffix(follows), _)) => follows + 1,
            _ => 0,
        };
        if types + suffixes > MAX_TYPE_DEPTH || shared > MAX_TYPE_DEPTH {
            return Exceeded::Type.into_error();
        }
    }
    Ok(())
}

/// Rejects SQL that wraps statements past [`MAX_STATEMENT_DEPTH`], and returns whether a
/// statement in it may hold a list of statements.
///
/// The check reads tokens because the parsers recurse through a wrapper before there is a
/// syntax tree, and DataFusion's parser does so through `EXPLAIN` without counting. A wrapper
/// is an `EXPLAIN`, a `DESCRIBE` or `DESC`, or a `PREPARE ... AS` where a statement begins,
/// which is at the start of the SQL, after a `;`, and after the words of another wrapper. The
/// same words anywhere else are names. The first word after the wrappers decides the rest.
/// Unless it is one of [`PLAIN_STATEMENTS`], the statement may hold others, as an `IF` and a
/// `CREATE PROCEDURE` do.
fn verify_wrapper_nesting(tokens: &[Token]) -> DataFusionResult<bool> {
    let keyword = |index: usize| match tokens.get(index) {
        Some(Token::Word(word)) if word.quote_style.is_none() => word.keyword,
        _ => Keyword::NoKeyword,
    };
    // The index after the parenthesis that opens at `index`, or `index` when none does.
    let after_group = |index: usize| {
        let mut open = 0usize;
        for (offset, token) in tokens.iter().enumerate().skip(index) {
            match token {
                Token::LParen => open += 1,
                Token::RParen if open > 1 => open -= 1,
                Token::RParen if open == 1 => return offset + 1,
                _ if open == 0 => return index,
                _ => {}
            }
        }
        tokens.len()
    };
    let mut holds = false;
    let mut index = 0;
    loop {
        let mut wrappers = 0;
        loop {
            // A word that ends its statement, or that a dot follows, is the name of a table.
            if matches!(
                tokens.get(index + 1),
                None | Some(Token::SemiColon | Token::Period)
            ) {
                break;
            }
            match keyword(index) {
                Keyword::EXPLAIN | Keyword::DESCRIBE | Keyword::DESC => {
                    // Options in parentheses or in words come before the statement.
                    index = after_group(index + 1);
                    loop {
                        match keyword(index) {
                            Keyword::QUERY
                            | Keyword::PLAN
                            | Keyword::ESTIMATE
                            | Keyword::ANALYZE
                            | Keyword::VERBOSE => index += 1,
                            Keyword::FORMAT => {
                                index += 1 + usize::from(tokens.get(index + 1) == Some(&Token::Eq));
                                index += 1;
                            }
                            _ => break,
                        }
                    }
                }
                Keyword::PREPARE => {
                    // The name and the parameter types come before `AS` and the statement.
                    let after = after_group(index + 2);
                    if keyword(after) != Keyword::AS {
                        break;
                    }
                    index = after + 1;
                }
                _ => break,
            }
            wrappers += 1;
            if wrappers == MAX_STATEMENT_DEPTH {
                return Exceeded::Statement.into_error();
            }
        }
        holds |= match tokens.get(index) {
            None | Some(Token::LParen | Token::SemiColon) => false,
            _ => !PLAIN_STATEMENTS.contains(&keyword(index)),
        };
        let Some(end) = tokens
            .iter()
            .skip(index)
            .position(|token| *token == Token::SemiColon)
        else {
            return Ok(holds);
        };
        index += end + 1;
    }
}

/// Stack that reading `sql` reserves. A parser nests an operator chain one level for every
/// two bytes of SQL, DataFusion plans a step for as few as six, and dropping a syntax tree
/// or a plan recurses once per level, so the reserve grows with the statement's length.
const fn reserved_stack(sql: &str) -> usize {
    sql.len()
        .saturating_mul(STACK_BYTES_PER_SQL_BYTE)
        .saturating_add(STACK_BYTES)
}

/// Parses one statement in the session's dialect and rejects it when its text or its syntax
/// tree nests past a limit.
///
/// A statement of any length the service admits is built, measured, and dropped on the
/// reserved stack, even when it is rejected. sqlparser stops statements inside statements at
/// its recursion limit, and the reserve covers that many when the statement may hold any.
fn parse_statement(state: &SessionState, sql: &str) -> DataFusionResult<ParsedStatement> {
    let options = &state.config().options().sql_parser;
    let mut stack = reserved_stack(sql);
    if let Some(tokens) = tokens(&options.dialect, sql) {
        verify_type_nesting(&tokens)?;
        if verify_wrapper_nesting(&tokens)? {
            let statements = options.recursion_limit.get();
            stack = stack.saturating_add(statements.saturating_mul(STACK_BYTES_PER_STATEMENT));
        }
    }
    stacker::maybe_grow(stack, stack, || {
        let statement = state.sql_to_statement(sql, &options.dialect)?;
        verify_statement_nesting(&statement)?;
        Ok(statement)
    })
}

/// Rejects a statement whose syntax tree exceeds a limit of this module.
fn verify_statement_nesting(statement: &ParsedStatement) -> DataFusionResult<()> {
    // DataFusion parses `EXPLAIN` into a wrapper of its own that no visitor hook sees, so the
    // wrappers are counted in a loop.
    let mut visitor = NestingVisitor::default();
    let mut statement = statement;
    while let ParsedStatement::Explain(explain) = statement {
        visitor.statements += 1;
        if visitor.statements == MAX_STATEMENT_DEPTH {
            return Exceeded::Statement.into_error();
        }
        statement = &explain.statement;
    }
    match statement {
        ParsedStatement::Statement(statement) => visitor.verify(statement.as_ref()),
        ParsedStatement::CopyTo(copy) => match &copy.source {
            CopyToSource::Query(query) => visitor.verify(query.as_ref()),
            CopyToSource::Relation(_) => Ok(()),
        },
        ParsedStatement::CreateExternalTable(table) => {
            visitor.verify(&table.columns)?;
            visitor.verify(&table.order_exprs)?;
            visitor.verify(&table.constraints)
        }
        ParsedStatement::Explain(_) | ParsedStatement::Reset(_) => Ok(()),
    }
}

/// Measures how deep an expression of the plan nests while DataFusion walks it.
#[derive(Default)]
struct ExpressionVisitor {
    /// Expressions that enclose the one being visited, itself included.
    depth: usize,
    /// Deepest nesting seen so far.
    deepest: usize,
}

impl TreeNodeVisitor<'_> for ExpressionVisitor {
    type Node = PlanExpr;

    fn f_down(&mut self, expr: &PlanExpr) -> DataFusionResult<TreeNodeRecursion> {
        self.depth += expression_levels(expr);
        self.deepest = self.deepest.max(self.depth);
        Ok(TreeNodeRecursion::Continue)
    }

    fn f_up(&mut self, expr: &PlanExpr) -> DataFusionResult<TreeNodeRecursion> {
        self.depth -= expression_levels(expr);
        Ok(TreeNodeRecursion::Continue)
    }
}

/// Levels that `expr` nests what it holds, once DataFusion has simplified it. A name for an
/// expression nests nothing. A searched `CASE` nests two levels more for every `WHEN` when
/// all its results are constant Booleans. The optimizer folds those into literals and then
/// rewrites the `CASE` into an `OR` of its branches, each of which holds the conditions
/// before it, and a debug build takes twice the stack of another level to do so.
fn expression_levels(expr: &PlanExpr) -> usize {
    let folds_to_boolean = |result: &PlanExpr| {
        !result.any_column_refs()
            && matches!(
                result.get_type(&DFSchema::empty()),
                Ok(ArrowType::Boolean | ArrowType::Null)
            )
    };
    match expr {
        PlanExpr::Alias(_) => 0,
        PlanExpr::Case(case)
            if case.expr.is_none()
                && case
                    .when_then_expr
                    .iter()
                    .all(|(_, result)| folds_to_boolean(result)) =>
        {
            1 + 2 * case.when_then_expr.len()
        }
        _ => 1,
    }
}

/// Measures how much of [`PLAN_BUDGET`] a plan spends while DataFusion walks it, and stops
/// the walk at the first step past the budget.
#[derive(Default)]
struct PlanVisitor {
    /// Share of the budget spent by the steps that enclose the step being visited, itself
    /// included.
    spent: usize,
    /// Share that each of those steps spends, innermost last.
    costs: Vec<usize>,
}

impl TreeNodeVisitor<'_> for PlanVisitor {
    type Node = LogicalPlan;

    fn f_down(&mut self, step: &LogicalPlan) -> DataFusionResult<TreeNodeRecursion> {
        let mut cost = match step {
            LogicalPlan::Join(_)
            | LogicalPlan::Aggregate(_)
            | LogicalPlan::Distinct(_)
            | LogicalPlan::Window(_)
            | LogicalPlan::Limit(_) => JOIN_COST,
            LogicalPlan::Filter(_) => FILTER_COST,
            _ => 1,
        };
        step.apply_subqueries(|_| {
            cost += JOIN_COST;
            Ok(TreeNodeRecursion::Continue)
        })?;
        // The operand at the bottom of an expression is not a level of nesting.
        let mut expressions = ExpressionVisitor::default();
        step.apply_expressions(|expr| expr.visit(&mut expressions))?;
        cost += expressions.deepest.saturating_sub(1);
        self.spent += cost;
        self.costs.push(cost);
        if self.spent > PLAN_BUDGET {
            return Exceeded::Plan.into_error();
        }
        Ok(TreeNodeRecursion::Continue)
    }

    fn f_up(&mut self, _step: &LogicalPlan) -> DataFusionResult<TreeNodeRecursion> {
        self.spent -= self.costs.pop().unwrap_or_default();
        Ok(TreeNodeRecursion::Continue)
    }
}

/// Parses and plans one statement in the session's dialect and rejects it when it nests past
/// a limit. A plan this returns is within every limit of this module.
///
/// The plan is measured before DataFusion optimizes it, which is the first place where
/// something recurses through every step without growing the stack. The walk that measures
/// it grows the stack. A plan that is rejected is dropped on the reserved stack, as is one
/// that DataFusion gives up on halfway. The statement that an `EXECUTE` names is not part
/// of the plan and is not measured, and neither is a view, which DataFusion plans in place
/// of its name when it optimizes.
pub(crate) async fn plan_statement(
    state: &SessionState,
    sql: &str,
) -> DataFusionResult<LogicalPlan> {
    let statement = parse_statement(state, sql)?;
    let stack = reserved_stack(sql);
    let mut planning = pin!(state.statement_to_plan(statement));
    poll_fn(|context| {
        stacker::maybe_grow(stack, stack, || {
            planning.as_mut().poll(context).map(|plan| {
                let plan = plan?;
                plan.visit_with_subqueries(&mut PlanVisitor::default())?;
                Ok(plan)
            })
        })
    })
    .await
}

/// Parses a predicate in the session's dialect and rejects it when it exceeds a limit of this
/// module.
pub(crate) fn verify_predicate_nesting(state: &SessionState, sql: &str) -> DataFusionResult<()> {
    let dialect = state.config().options().sql_parser.dialect;
    if let Some(tokens) = tokens(&dialect, sql) {
        verify_type_nesting(&tokens)?;
    }
    NestingVisitor::default().verify(&state.sql_to_expr(sql, &dialect)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::{
        arrow::{array::Int64Array, record_batch::RecordBatch},
        prelude::SessionContext,
    };
    use std::sync::{Arc, LazyLock};

    /// A statement shape that nests one level deeper with each repetition.
    type Shape = Box<dyn Fn(usize) -> String>;

    /// Session with DataFusion's default dialect and parser recursion limit, and a table `t`
    /// with the columns `x` and `y`.
    static STATE: LazyLock<SessionState> = LazyLock::new(|| {
        let context = SessionContext::new();
        let column = || Arc::new(Int64Array::from(vec![1, 2, 3])) as _;
        let batch = RecordBatch::try_from_iter([("x", column()), ("y", column())]).unwrap();
        context.register_batch("t", batch).unwrap();
        context.state()
    });

    /// Checks the text and the syntax tree of one statement the way `Query` does.
    fn verify_sql(sql: &str) -> DataFusionResult<()> {
        parse_statement(&STATE, sql).map(|_| ())
    }

    /// Checks one statement the way `Query` does, its plan included.
    fn plan_sql(sql: &str) -> DataFusionResult<()> {
        futures::executor::block_on(plan_statement(&STATE, sql)).map(|_| ())
    }

    /// Asserts that the statement `shape` builds from `accepted` repetitions passes `check`
    /// and that one more repetition fails naming `what`.
    fn assert_limit_of(
        check: fn(&str) -> DataFusionResult<()>,
        name: &str,
        what: &str,
        accepted: usize,
        shape: impl Fn(usize) -> String,
    ) {
        check(&shape(accepted))
            .unwrap_or_else(|error| panic!("{name} at its limit must pass: {error}"));
        let error = check(&shape(accepted + 1))
            .expect_err(&format!("{name} past its limit must fail"))
            .to_string();
        assert!(error.contains(what), "{name}: {error}");
    }

    fn assert_limit(name: &str, what: &str, accepted: usize, shape: impl Fn(usize) -> String) {
        assert_limit_of(verify_sql, name, what, accepted, shape);
    }

    fn wrap(prefix: &str, body: &str, suffix: &str, times: usize) -> String {
        format!("{}{body}{}", prefix.repeat(times), suffix.repeat(times))
    }

    /// A chain of common table expressions that each read the one before `fan` times.
    fn fan_out(tables: usize, fan: usize) -> String {
        let chained: String = (1..=tables)
            .map(|table| {
                let reads: Vec<_> = (0..fan)
                    .map(|read| format!("c{} r{read}", table - 1))
                    .collect();
                format!(", c{table} AS (SELECT r0.x FROM {})", reads.join(", "))
            })
            .collect();
        format!("WITH c0 AS (SELECT 1 AS x){chained} SELECT count(*) FROM c{tables}")
    }

    /// The chain of [`fan_out`] with a dot in every name. Each name is quoted where it is
    /// defined and written in two parts where it is read.
    fn dotted_fan_out(tables: usize, fan: usize) -> String {
        let chained: String = (1..=tables)
            .map(|table| {
                let reads: Vec<_> = (0..fan)
                    .map(|read| format!("q.c{} r{read}", table - 1))
                    .collect();
                format!(
                    ", \"q.c{table}\" AS (SELECT r0.x FROM {})",
                    reads.join(", ")
                )
            })
            .collect();
        format!("WITH \"q.c0\" AS (SELECT 1 AS x){chained} SELECT count(*) FROM Q.c{tables}")
    }

    /// A chain of `tables` common table expressions that each select `expr` from the one
    /// before, the first from `t`.
    fn chain_of(tables: usize, expr: &str) -> String {
        let chained: String = (1..tables)
            .map(|table| format!(", c{table} AS (SELECT {expr} AS x FROM c{})", table - 1))
            .collect();
        format!(
            "WITH c0 AS (SELECT {expr} AS x FROM t){chained} SELECT x FROM c{}",
            tables - 1
        )
    }

    #[test]
    fn expressions_nest_within_the_budget() {
        // Each repetition of these shapes encloses the operand in one more expression that is
        // not a binary operator. The parser builds the first two in a loop, where its recursion
        // limit does not apply.
        let levels = NESTING_BUDGET / NESTING_COST - 1;
        let nested: [(&str, Shape); 8] = [
            (
                "a cast chain",
                Box::new(|n| wrap("", "SELECT 1", "::bigint", n)),
            ),
            (
                "an IS NULL chain",
                Box::new(|n| wrap("", "SELECT 1", " IS NULL", n)),
            ),
            (
                "parentheses",
                Box::new(|n| format!("SELECT {}", wrap("(", "1", ")", n))),
            ),
            (
                "a NOT chain",
                Box::new(|n| format!("SELECT {}", wrap("NOT ", "true", "", n))),
            ),
            (
                "a negation chain",
                Box::new(|n| format!("SELECT {}", wrap("- ", "1", "", n))),
            ),
            (
                "function calls",
                Box::new(|n| format!("SELECT {}", wrap("abs(", "1", ")", n))),
            ),
            (
                "simple CASE expressions",
                Box::new(|n| format!("SELECT {}", wrap("CASE 1 WHEN 1 THEN ", "1", " END", n))),
            ),
            (
                "IN lists",
                Box::new(|n| format!("SELECT {}", wrap("1 IN (", "1", ")", n))),
            ),
        ];
        for (name, shape) in nested {
            assert_limit(name, "expressions nested", levels, shape);
        }

        // Each repetition of these shapes adds one binary operator above one operand.
        let operators = (NESTING_BUDGET - NESTING_COST) / OPERATOR_COST;
        let chained: [(&str, Shape); 6] = [
            (
                "an arithmetic chain",
                Box::new(|n| wrap("", "SELECT 1", "+1", n)),
            ),
            (
                "a concatenation chain",
                Box::new(|n| wrap("", "SELECT 'a'", " || ','", n)),
            ),
            (
                "an AND chain",
                Box::new(|n| wrap("", "SELECT true", " AND true", n)),
            ),
            (
                "an OR chain",
                Box::new(|n| wrap("", "SELECT true", " OR false", n)),
            ),
            (
                "a comparison chain",
                Box::new(|n| wrap("", "SELECT true", " = true", n)),
            ),
            (
                "an INSERT value",
                Box::new(|n| format!("INSERT INTO t VALUES ({})", wrap("", "1", "+1", n))),
            ),
        ];
        for (name, shape) in chained {
            assert_limit(name, "expressions nested", operators, shape);
        }

        // A comparison is an operator above its operand, so a WHERE clause joins this many
        // comparisons with AND or OR.
        let comparisons = (NESTING_BUDGET - NESTING_COST - OPERATOR_COST) / OPERATOR_COST + 1;
        for operator in ["AND", "OR"] {
            assert_limit(operator, "expressions nested", comparisons, |n| {
                let terms = vec!["x = 1"; n].join(&format!(" {operator} "));
                format!("SELECT 1 FROM t WHERE {terms}")
            });
        }

        // A lookup by a composite key is an OR of parenthesized ANDs with one branch per key.
        let keys = (NESTING_BUDGET - 2 * NESTING_COST - 2 * OPERATOR_COST) / OPERATOR_COST + 1;
        assert_limit("an OR of ANDs", "expressions nested", keys, |n| {
            let branches: Vec<_> = (0..n)
                .map(|key| format!("(a = {key} AND b = {key})"))
                .collect();
            format!("SELECT 1 FROM t WHERE {}", branches.join(" OR "))
        });

        // A term of a chain nests from where the chain puts it. Half the budget goes to the
        // operators and the rest to function calls around one operand.
        let half = NESTING_BUDGET / 2;
        let calls = (NESTING_BUDGET - half) / NESTING_COST - 1;
        assert_limit(
            "a chain of nested terms",
            "expressions nested",
            calls,
            |n| {
                let term = wrap("abs(", "1", ")", n);
                format!(
                    "SELECT {term}{}",
                    format!(" + {term}").repeat(half / OPERATOR_COST)
                )
            },
        );
    }

    #[test]
    fn field_access_chains_nest_once_for_every_part() {
        // DataFusion plans each field of a dotted name as a function call around the parts
        // before it, though the parser keeps the whole chain in one node.
        let fields = (NESTING_BUDGET - NESTING_COST) / NESTING_COST;
        assert_limit("a dotted name", "expressions nested", fields, |n| {
            format!("SELECT x{} FROM t", ".f".repeat(n))
        });
        assert_limit(
            "fields of a subscript",
            "expressions nested",
            fields - 1,
            |n| format!("SELECT x[1]{} FROM t", ".f".repeat(n)),
        );

        // A chain of subscripts is a run of bracket groups, like the suffixes of an array
        // type, and the type limit bounds both.
        for subscript in ["['a']", "[1]"] {
            assert_limit(subscript, "data types nested", MAX_TYPE_DEPTH, |n| {
                format!("SELECT x{} FROM t", subscript.repeat(n))
            });
        }
    }

    #[test]
    fn a_case_that_may_return_booleans_nests_once_for_every_when() {
        // Each WHEN is one operator of the OR that DataFusion makes of the CASE, above the
        // comparison and operand of its condition.
        let whens = (NESTING_BUDGET - 2 * NESTING_COST - OPERATOR_COST) / OPERATOR_COST;
        let case = |result: &'static str| {
            move |n: usize| {
                let whens: String = (0..n)
                    .map(|when| format!(" WHEN x = {when} THEN {result}"))
                    .collect();
                format!("SELECT CASE{whens} END FROM t")
            }
        };
        for result in ["false", "NULL", "y"] {
            assert_limit(result, "expressions nested", whens, case(result));
        }
        for result in [
            "(1 = 0)",
            "CAST(0 AS BOOLEAN)",
            "BOOLEAN 'true'",
            "CAST(y AS BIGINT)",
            "-y",
        ] {
            let error = verify_sql(&case(result)(whens + 1))
                .unwrap_err()
                .to_string();
            assert!(error.contains("expressions nested"), "{result}: {error}");
        }

        // A result that is a literal of another type keeps the CASE a CASE, however wide it
        // is.
        for result in [
            "1",
            "'one'",
            "-1",
            "+1.5",
            "DATE '2026-01-01'",
            "CAST(0 AS BIGINT)",
            "NULL::INT",
            "TRY_CAST('1' AS INT)",
        ] {
            verify_sql(&case(result)(1_000)).unwrap_or_else(|error| panic!("{result}: {error}"));
        }
    }

    #[test]
    fn wide_statements_are_not_deep() {
        let items = |n: usize| vec!["1"; n].join(", ");
        let tables: Vec<_> = (0..30)
            .map(|i| format!("c{i} AS (SELECT x FROM t)"))
            .collect();
        let windows = |window: &dyn Fn(usize) -> String| {
            let functions: Vec<_> = (0..200)
                .map(|i| format!("sum(x + {i}) {}", window(i)))
                .collect();
            format!("SELECT {} FROM t", functions.join(", "))
        };
        for sql in [
            format!("SELECT 1 IN ({})", items(5_000)),
            format!("SELECT {}", items(5_000)),
            format!("SELECT coalesce({})", items(5_000)),
            format!("SELECT CASE 1 {} END", "WHEN 1 THEN 1 ".repeat(1_000)),
            format!("INSERT INTO t VALUES {}", vec!["(1, 2)"; 5_000].join(", ")),
            format!("SELECT 1 WHERE {}", vec!["1 < 2"; 60].join(" AND ")),
        ] {
            verify_sql(&sql).unwrap_or_else(|error| panic!("{sql:.40} must pass: {error}"));
        }
        for sql in [
            // Common table expressions that do not read one another are siblings.
            format!("WITH {} SELECT c0.x FROM c0, c29", tables.join(", ")),
            // Window functions over one partitioning and ordering share a step of the plan,
            // whatever their frames are.
            windows(&|_| "OVER (PARTITION BY y ORDER BY x)".to_string()),
            windows(&|i| format!("OVER (ORDER BY x ROWS {i} PRECEDING)")),
            format!(
                "{} WINDOW w AS (ORDER BY x)",
                windows(&|_| "OVER w".to_string())
            ),
        ] {
            plan_sql(&sql).unwrap_or_else(|error| panic!("{sql:.40} must pass: {error}"));
        }
    }

    #[test]
    fn plans_nest_within_the_budget() {
        let joined = |join: &'static str, on: &'static str| {
            move |n: usize| {
                let joins: String = (1..=n)
                    .map(|i| format!("{join} t a{i}{}", on.replace("{i}", &i.to_string())))
                    .collect();
                format!("SELECT a0.x FROM t a0{joins}")
            }
        };
        let piped = |operator: &'static str| {
            move |n: usize| {
                let operators: String = (0..n)
                    .map(|i| operator.replace("{i}", &i.to_string()))
                    .collect();
                format!("SELECT x FROM t{operators}")
            }
        };
        let listed = |item: &'static str, from: &'static str| {
            move |n: usize| {
                let items: Vec<_> = (0..n)
                    .map(|i| item.replace("{i}", &i.to_string()))
                    .collect();
                format!("SELECT {} FROM {from}", items.join(", "))
            }
        };
        // Around each chain are the projection that selects from it and the table it reads,
        // and around the joins the name of that table as well.
        let steps = PLAN_BUDGET - 2;
        // A subquery that adds to an aggregate is a name, a projection of one level, an
        // aggregation of one level, and a table. One that also compares a column with the
        // row around it filters with one more level and names its table.
        let subquery = 1 + 2 + (JOIN_COST + 1) + 1;
        let correlated = subquery + (FILTER_COST + 1) + 1;
        let shapes: [(&str, usize, Shape); 17] = [
            (
                "a UNION ALL chain",
                steps,
                Box::new(|n| wrap("", "SELECT 1", " UNION ALL SELECT 1", n)),
            ),
            // A UNION removes duplicates in a step that costs as an aggregation, and an
            // INTERSECT and an EXCEPT join their operands after that.
            (
                "a UNION chain",
                steps / (JOIN_COST + 1),
                Box::new(|n| wrap("", "SELECT x FROM t", " UNION SELECT x FROM t", n)),
            ),
            (
                "an INTERSECT chain",
                steps / (2 * JOIN_COST),
                Box::new(|n| wrap("", "SELECT x FROM t", " INTERSECT SELECT x FROM t", n)),
            ),
            (
                "an EXCEPT chain",
                steps / (2 * JOIN_COST),
                Box::new(|n| wrap("", "SELECT x FROM t", " EXCEPT SELECT x FROM t", n)),
            ),
            // The comparison of a join's condition is one level of an expression.
            (
                "a join chain",
                (steps - 1) / (JOIN_COST + 1),
                Box::new(joined(" JOIN", " ON a{i}.x = a0.x")),
            ),
            (
                "an outer join chain",
                (steps - 1) / (JOIN_COST + 1),
                Box::new(joined(" LEFT JOIN", " ON a{i}.x = a0.x")),
            ),
            (
                "a FROM list",
                (steps - 1) / JOIN_COST,
                Box::new(joined(",", "")),
            ),
            (
                "pipe operators that rename",
                steps,
                Box::new(piped(" |> AS a{i}")),
            ),
            (
                "pipe operators that filter",
                steps / (FILTER_COST + 1),
                Box::new(piped(" |> WHERE x > {i}")),
            ),
            (
                "pipe operators that limit",
                steps / JOIN_COST,
                Box::new(piped(" |> LIMIT 100")),
            ),
            (
                "pipe operators that aggregate",
                steps / (JOIN_COST + 1),
                Box::new(piped(" |> AGGREGATE max(x) AS x")),
            ),
            // A window step holds the function, and under it the sum that orders the rows.
            (
                "windows over different orderings",
                steps / (JOIN_COST + 2),
                Box::new(listed("count(*) OVER (ORDER BY x + {i})", "t")),
            ),
            // The plan of a subquery nests under the projection that holds it.
            (
                "subqueries side by side",
                (PLAN_BUDGET - 1 - subquery) / JOIN_COST,
                Box::new(listed("(SELECT max(x) + {i} FROM t)", "t")),
            ),
            (
                "correlated subqueries side by side",
                (PLAN_BUDGET - 1 - correlated) / JOIN_COST,
                Box::new(listed(
                    "(SELECT max(i.x) + {i} FROM t i WHERE i.x = o.x)",
                    "t o",
                )),
            ),
            // Each common table expression is a projection and a name around the one it
            // reads.
            (
                "a chain of common table expressions",
                steps / 2,
                Box::new(|n| chain_of(n, "x")),
            ),
            // A DISTINCT costs as the aggregation it becomes.
            (
                "a chain of common table expressions that remove duplicates",
                steps / (JOIN_COST + 2),
                Box::new(|n| chain_of(n, "DISTINCT x")),
            ),
            // The optimizer merges the sums of a chain into one sum, so each spends a level.
            (
                "a chain of common table expressions that compute",
                steps / 3,
                Box::new(|n| chain_of(n, "x + 1")),
            ),
        ];
        for (name, accepted, shape) in shapes {
            assert_limit_of(plan_sql, name, "plans nested", accepted, shape);
        }
    }

    #[test]
    fn ordinary_statements_fit_the_plan_budget() {
        // A pipeline of common table expressions that each filter on two conditions and
        // group, and the same with a join in every step.
        let pipeline = |steps: usize, join: &str| {
            let chained: String = (2..=steps)
                .map(|step| {
                    let from = format!("s{} s{}", step - 1, join.replace("{}", "s"));
                    format!(
                        ", s{step} AS (SELECT s.x, sum(s.y) AS y FROM {from}                          WHERE s.y <> 0 AND s.x IS NOT NULL GROUP BY s.x)"
                    )
                })
                .collect();
            format!(
                "WITH s1 AS (SELECT x, sum(y) AS y FROM t WHERE x > 0 AND y > 0 GROUP BY x)                 {chained} SELECT * FROM s{steps} ORDER BY x LIMIT 100"
            )
        };
        // A filter of as many comparisons as an expression may join, under a select
        // expression of 30 operators.
        let comparisons: Vec<_> = (0..92).map(|bound| format!("x < {bound}")).collect();
        let filtered = format!(
            "SELECT x{} AS total FROM t WHERE {} ORDER BY x LIMIT 10",
            " + y".repeat(30),
            comparisons.join(" AND ")
        );
        // Counts of whole tables side by side.
        let counts: Vec<_> = (0..45)
            .map(|count| format!("(SELECT count(*) FROM t) AS c{count}"))
            .collect();
        for sql in [
            pipeline(10, ""),
            pipeline(10, " JOIN t d ON d.x = {}.x"),
            filtered,
            format!("SELECT {}", counts.join(", ")),
        ] {
            plan_sql(&sql).unwrap_or_else(|error| panic!("{sql:.60} must pass: {error}"));
        }
    }

    #[test]
    fn the_expressions_of_a_path_share_the_plan_budget() {
        // Each of these is within the expression budget by itself. The optimizer merges the
        // projections of a chain into one, whose expression nests as deep as all of them
        // together, so the chain spends the plan budget on every level of each.
        for (levels, expr) in [
            (10, format!("x{}", " + 1".repeat(10))),
            (10, wrap("abs(", "x", ")", 10)),
            (5, wrap("CAST(", "x", " AS BIGINT)", 5)),
        ] {
            assert_limit_of(
                plan_sql,
                &expr,
                "plans nested",
                (PLAN_BUDGET - 2) / (levels + 2),
                |n| chain_of(n, &expr),
            );
        }

        // A searched CASE whose results are constant Booleans becomes an OR of its branches,
        // and the ORs of consecutive projections merge. Each step holds the CASE, two levels
        // for each WHEN, and a comparison, and the query that the steps follow is two steps.
        let step = |n: usize, result: &str| {
            let whens: String = (0..20)
                .map(|when| format!(" WHEN y > {} THEN {result}", n * 100 + when))
                .collect();
            format!(" |> SELECT CASE{whens} END AS x, y")
        };
        for result in ["false", "true", "NULL", "(1 = 1)", "CAST(0 AS BOOLEAN)"] {
            assert_limit_of(
                plan_sql,
                result,
                "plans nested",
                (PLAN_BUDGET - 2) / (2 * 20 + 3),
                |n| {
                    let steps: String = (0..n).map(|n| step(n, result)).collect();
                    format!("SELECT x, y FROM t{steps}")
                },
            );
        }
        // A CASE with a result of another type stays a CASE, one level however wide it is.
        for result in ["y", "1", "'one'", "y > 0"] {
            let steps: String = (0..40).map(|n| step(n, result)).collect();
            plan_sql(&format!("SELECT x, y FROM t{steps}"))
                .unwrap_or_else(|error| panic!("{result}: {error}"));
        }

        // An expression that no step encloses spends nothing, however many there are.
        let sums: Vec<_> = (0..500).map(|i| format!("x + y + {i}")).collect();
        plan_sql(&format!(
            "SELECT {} FROM t WHERE x + y > 0",
            sums.join(", ")
        ))
        .unwrap();
    }

    #[test]
    fn plans_past_the_budget_are_rejected_before_they_are_planned_where_planning_is_slow() {
        // DataFusion plans these in time that grows with the square or the cube of their
        // size, and with recursion for the set operations.
        let windows: Vec<_> = (0..=PLAN_BUDGET / JOIN_COST)
            .map(|i| format!("count(*) OVER (ORDER BY x + {i})"))
            .collect();
        for sql in [
            wrap("", "SELECT 1", " UNION ALL SELECT 1", PLAN_BUDGET + 1),
            wrap("", "SELECT 1 AS x", " |> AS a", PLAN_BUDGET + 1),
            format!("SELECT {} FROM t", windows.join(", ")),
        ] {
            let error = verify_sql(&sql).unwrap_err().to_string();
            assert!(error.contains("plans nested"), "{sql:.40}: {error}");
        }
    }

    #[test]
    fn queries_nest_up_to_the_limit() {
        // Every shape nests one query per repetition inside the statement's own query.
        let shapes: [(&str, Shape); 6] = [
            (
                "scalar subqueries",
                Box::new(|n| format!("SELECT {}", wrap("(SELECT ", "1", ")", n))),
            ),
            (
                "derived tables",
                Box::new(|n| wrap("SELECT 1 FROM (", "SELECT 1", ") d", n)),
            ),
            (
                "IN subqueries",
                Box::new(|n| wrap("SELECT 1 WHERE 1 IN (", "SELECT 1", ")", n)),
            ),
            (
                "EXISTS subqueries",
                Box::new(|n| wrap("SELECT 1 WHERE EXISTS (", "SELECT 1", ")", n)),
            ),
            (
                "common table expressions",
                Box::new(|n| wrap("WITH c AS (", "SELECT 1", ") SELECT 1", n)),
            ),
            (
                "parenthesized set operands",
                Box::new(|n| wrap("(", "SELECT 1", ") UNION ALL SELECT 1", n)),
            ),
        ];
        for (name, shape) in shapes {
            assert_limit(name, "queries nested", MAX_QUERY_DEPTH - 1, shape);
        }
    }

    #[test]
    fn subqueries_continue_the_nesting_around_them() {
        // A subquery spends the budget of the expressions around it and its own share as a
        // nested query, and an operator chain inside it continues from there.
        let operators = (NESTING_BUDGET - 3 * NESTING_COST - 2 * QUERY_COST) / OPERATOR_COST;
        assert_limit(
            "a chain in a subquery",
            "expressions nested",
            operators,
            |n| format!("SELECT (SELECT (SELECT {}))", wrap("", "1", "+1", n)),
        );

        // A projection that holds a subquery, the subquery, its projection, and the name and
        // projection of the derived table enclose the set operation chain and its operands.
        assert_limit_of(
            plan_sql,
            "a chain in a derived table",
            "plans nested",
            PLAN_BUDGET - (1 + JOIN_COST) - 3 - 2,
            |n| {
                format!(
                    "SELECT (SELECT 1 FROM (SELECT 1{}) d)",
                    " UNION ALL SELECT 1".repeat(n)
                )
            },
        );
    }

    #[test]
    fn common_table_expressions_count_the_relations_they_expand_to() {
        // Each expression reads the one before it four times, so the last reads four to the
        // power of the chain's length.
        let (fan, chain) = (4usize, 5);
        assert_eq!(fan.pow(chain), MAX_RELATIONS);
        let chain = chain as usize;
        assert_limit("a chain", "relations", chain, |n| fan_out(n, fan));

        // One more relation beside the expression at the limit is one too many, also when
        // the name differs in case or is quoted and when a subquery does the reading.
        let limit = fan_out(chain, fan);
        let last = format!("c{chain}");
        for from in [
            format!("{last}, t"),
            format!("{}, t", last.to_uppercase()),
            format!("\"{last}\", t"),
            format!("(SELECT x FROM {last}) d, t"),
            format!("t WHERE EXISTS (SELECT 1 FROM {last})"),
        ] {
            let sql = limit.replace(&format!("FROM {last}"), &format!("FROM {from}"));
            assert_ne!(sql, limit, "{from}");
            let error = verify_sql(&sql).unwrap_err().to_string();
            assert!(error.contains("relations"), "{from}: {error}");
        }

        // DataFusion finds an expression by the parts of a name joined with dots, so a name
        // of two parts reads the expression whose quoted name has the dot.
        assert_limit("a chain of dotted names", "relations", chain, |n| {
            dotted_fan_out(n, fan)
        });

        // Subqueries in one expression read side by side, so they multiply the relations
        // without nesting the plan any deeper.
        let reads = |reads: usize| {
            let read = |table: usize| vec![format!("(SELECT max(x) FROM c{table})"); reads];
            format!(
                "WITH c0 AS (SELECT 1 AS x), c1 AS (SELECT {} AS x), c2 AS (SELECT {} AS x) \
                 SELECT x FROM c2",
                read(0).join(" + "),
                read(1).join(" + ")
            )
        };
        let side = MAX_RELATIONS.isqrt();
        assert_eq!(side * side, MAX_RELATIONS);
        assert_limit("subqueries", "relations", side, reads);

        // A name is in scope only inside the query whose WITH clause defines it. Outside it
        // the same name is one relation.
        let inner = fan_out(chain - 1, fan);
        let last = format!("c{}", chain - 1);
        verify_sql(&format!(
            "SELECT 1 FROM ({inner}) d, {last} e, {last} f, {last} g, {last} h"
        ))
        .unwrap();
    }

    #[test]
    fn common_table_expressions_count_what_they_copy() {
        // The first expression reads no table. Every place that names it holds a copy of its
        // rows or of its select list, and four to the power of five places name it.
        let copies = |body: String| {
            let chained: String = (1..=5)
                .map(|table| {
                    let read = format!("SELECT * FROM c{}", table - 1);
                    format!(", c{table} AS ({})", vec![read; 4].join(" UNION ALL "))
                })
                .collect();
            format!("WITH c0 AS ({body}){chained} SELECT * FROM c5")
        };
        assert_eq!(4usize.pow(5), MAX_RELATIONS);
        let each = MAX_NODES / MAX_RELATIONS;
        assert_limit("rows", "expressions and relations", each, |n| {
            copies(format!("VALUES {}", vec!["(1)"; n].join(", ")))
        });
        assert_limit("a select list", "expressions and relations", each, |n| {
            copies(format!("SELECT {}", vec!["1"; n].join(", ")))
        });

        // A statement of the greatest length holds fewer without such expressions.
        let widest = format!("SELECT {}1", "-1,".repeat(21_842));
        assert_eq!(widest.len(), 65_534);
        verify_sql(&widest).unwrap();
    }

    #[test]
    fn relations_are_counted_across_the_whole_statement() {
        // Each subquery reads a quarter of the relations a statement may, wherever the
        // statement holds it. The table that a DELETE or an UPDATE changes is one more.
        let subquery = fan_out(4, 4).replace("count(*)", "x");
        let quarter = MAX_RELATIONS / 4;
        assert_eq!(4usize.pow(4), quarter);
        for (sql, subqueries, separator, own) in [
            ("SELECT 1 WHERE {}", "1 IN ({q})", " OR ", 0),
            ("DELETE FROM t WHERE {}", "x IN ({q})", " OR ", 1),
            ("UPDATE t SET y = 0 WHERE {}", "x IN ({q})", " OR ", 1),
            ("EXECUTE p({})", "({q})", ", ", 0),
            ("INSERT INTO t VALUES ({})", "({q})", ", ", 0),
        ] {
            assert_limit(sql, "relations", (MAX_RELATIONS - own) / quarter, |n| {
                let held = vec![subqueries.replace("{q}", &subquery); n].join(separator);
                sql.replace("{}", &held)
            });
        }
    }

    #[test]
    fn statements_nest_up_to_the_limit() {
        // Each wrapper nests the statement it wraps one level deeper.
        let prepares =
            |n: usize| -> String { (0..n).map(|i| format!("PREPARE p{i} AS ")).collect() };
        let wrapped = MAX_STATEMENT_DEPTH - 1;
        assert_limit("EXPLAIN", "statements nested", wrapped, |n| {
            format!("{}SELECT 1", "EXPLAIN ".repeat(n))
        });
        assert_limit("PREPARE", "statements nested", wrapped, |n| {
            format!("{}SELECT 1", prepares(n))
        });
        assert_limit("EXPLAIN PREPARE", "statements nested", wrapped - 1, |n| {
            format!("EXPLAIN {}SELECT 1", prepares(n))
        });

        // The parsers recurse through these wrappers before there is a syntax tree, so the
        // tokens are counted before parsing, with every option a wrapper takes.
        let mixed = ["EXPLAIN VERBOSE ", "PREPARE p(INT, INT[]) AS ", "DESC "];
        assert_eq!(mixed.len(), MAX_STATEMENT_DEPTH);
        for wrappers in [
            "EXPLAIN ",
            "EXPLAIN ANALYZE ",
            "EXPLAIN ANALYZE VERBOSE ",
            "EXPLAIN FORMAT TREE ",
            "EXPLAIN VERBOSE FORMAT 'tree' ",
            "EXPLAIN (ANALYZE, FORMAT JSON) ",
            "EXPLAIN (x (y), z) ",
            "DESCRIBE ",
            "DESC ",
            "DESCRIBE QUERY PLAN ",
            "DESC ANALYZE FORMAT = JSON ",
            "PREPARE p AS ",
            "PREPARE p(INT, STRUCT<a INT>) AS ",
        ]
        .map(|wrapper| wrapper.repeat(MAX_STATEMENT_DEPTH))
        .into_iter()
        .chain([mixed.concat(), mixed.iter().rev().copied().collect()])
        {
            for sql in [
                format!("{wrappers}SELECT 1"),
                // A statement begins after every semicolon.
                format!("SELECT 1; {wrappers}SELECT 1"),
                format!(";;{wrappers}SELECT 1"),
            ] {
                let error = verify_sql(&sql).unwrap_err().to_string();
                assert!(error.contains("statements nested"), "{sql}: {error}");
            }
        }
    }

    #[test]
    fn the_words_of_wrappers_are_names_elsewhere() {
        let sorted = vec!["x DESC"; 100].join(", ");
        for sql in [
            "SELECT a AS describe, b AS explain, c AS prepare FROM t".to_string(),
            "SELECT a AS desc, b AS desc, c AS desc FROM t".to_string(),
            "SELECT explain FROM t WHERE explain IS NOT NULL AND explain <> ''".to_string(),
            "SELECT explain, describe, prepare, desc FROM explain, describe, prepare".to_string(),
            "SELECT max(explain), min(describe), sum(prepare) FROM t".to_string(),
            "SELECT 1 FROM describe JOIN explain ON describe.prepare = explain.prepare".to_string(),
            "INSERT INTO describe (explain, prepare) VALUES (1, 2)".to_string(),
            format!("EXPLAIN ANALYZE SELECT x FROM t ORDER BY {sorted}"),
            "EXPLAIN SELECT describe, explain, prepare FROM t".to_string(),
            "PREPARE prepare AS SELECT explain FROM describe".to_string(),
            // The last word of a statement names a table, as does one before a dot.
            "DESCRIBE describe".to_string(),
            "DESC desc".to_string(),
            "EXPLAIN DESCRIBE describe".to_string(),
            "EXPLAIN DESCRIBE explain.describe".to_string(),
            "DESCRIBE t; DESCRIBE t; DESCRIBE t".to_string(),
        ] {
            let Some(tokens) = tokens(&STATE.config().options().sql_parser.dialect, &sql) else {
                panic!("{sql} must split into tokens");
            };
            verify_wrapper_nesting(&tokens).unwrap_or_else(|error| panic!("{sql}: {error}"));
        }
        // These also parse.
        for sql in [
            "SELECT a AS describe, b AS explain, c AS prepare FROM t",
            "SELECT explain FROM t WHERE explain IS NOT NULL AND explain <> ''",
            "DESCRIBE describe",
            "EXPLAIN DESCRIBE describe",
        ] {
            verify_sql(sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
        }
    }

    #[test]
    fn statements_inside_statements_are_parsed_on_the_reserved_stack() {
        // The parser nests these up to its recursion limit, which takes more than the 2 MiB
        // stack of a test thread in a debug build.
        let limit = STATE.config().options().sql_parser.recursion_limit.get();
        for (opening, closing) in [
            ("IF true THEN ", "; END IF"),
            ("CASE WHEN true THEN ", "; END"),
            ("WHILE true ", ""),
            ("CREATE PROCEDURE p AS ", ""),
            ("CREATE TRIGGER g BEFORE INSERT ON t FOR EACH ROW ", ""),
        ] {
            for (prefix, statements) in [
                ("", limit - 1),
                ("", 4 * limit),
                ("SELECT 1; EXPLAIN ", limit - 3),
            ] {
                let sql = format!("{prefix}{}", wrap(opening, "SELECT 1", closing, statements));
                let error = verify_sql(&sql).unwrap_err().to_string();
                let rejected = [
                    "statements nested",
                    "RecursionLimitExceeded",
                    "Expected",
                    "single SQL statement",
                ];
                assert!(
                    rejected.iter().any(|message| error.contains(message)),
                    "{sql:.40}: {error}"
                );
            }
        }

        // A statement that begins with one of these words holds no list of statements.
        for sql in [
            "SELECT 1",
            "(SELECT 1)",
            "WITH c AS (SELECT 1) SELECT 1",
            "EXPLAIN SELECT 1",
        ] {
            let tokens = tokens(&STATE.config().options().sql_parser.dialect, sql).unwrap();
            assert!(!verify_wrapper_nesting(&tokens).unwrap(), "{sql}");
        }
        for sql in [
            "IF true THEN SELECT 1; END IF",
            "EXPLAIN CREATE TABLE c (x INT)",
            "SELECT 1; BEGIN",
        ] {
            let tokens = tokens(&STATE.config().options().sql_parser.dialect, sql).unwrap();
            assert!(verify_wrapper_nesting(&tokens).unwrap(), "{sql}");
        }
    }

    #[test]
    fn data_types_nest_up_to_the_limit() {
        // Every shape nests the type one level per repetition, wherever a type is written.
        let shapes: [(&str, Shape); 12] = [
            (
                "array suffixes",
                Box::new(|n| format!("SELECT CAST(NULL AS INT{})", "[]".repeat(n))),
            ),
            (
                "sized array suffixes",
                Box::new(|n| format!("SELECT NULL::INT{}", "[3]".repeat(n))),
            ),
            (
                "ARRAY",
                Box::new(|n| format!("SELECT CAST(NULL AS {})", wrap("ARRAY<", "INT", ">", n))),
            ),
            (
                "STRUCT",
                Box::new(|n| format!("SELECT CAST(NULL AS {})", wrap("STRUCT<a ", "INT", ">", n))),
            ),
            (
                "Nullable",
                Box::new(|n| format!("SELECT CAST(NULL AS {})", wrap("Nullable(", "INT", ")", n))),
            ),
            (
                "Tuple",
                Box::new(|n| format!("SELECT CAST(NULL AS {})", wrap("Tuple(a ", "INT", ")", n))),
            ),
            (
                "Map",
                Box::new(|n| format!("SELECT CAST(NULL AS {})", wrap("Map(INT, ", "INT", ")", n))),
            ),
            (
                "a PREPARE parameter",
                Box::new(|n| format!("PREPARE p(INT{}) AS SELECT $1", "[]".repeat(n))),
            ),
            (
                "a column",
                Box::new(|n| format!("CREATE TABLE c (x {})", wrap("ARRAY<", "INT", ">", n))),
            ),
            (
                "a type string",
                Box::new(|n| format!("SELECT arrow_cast(1, '{}')", wrap("List(", "Int64", ")", n))),
            ),
            // A > that compares two values inside a field's options closes no type.
            (
                "STRUCT fields with options",
                Box::new(|n| {
                    let fields = wrap("STRUCT<a INT OPTIONS(o = 1 > 0), b ", "INT", ">", n);
                    format!("SELECT CAST(NULL AS {fields})")
                }),
            ),
            // A parenthesis inside the quoted name of a field closes no type either.
            (
                "a type string with quoted names",
                Box::new(|n| {
                    let fields = wrap("Struct(\")\": ", "Int64", ")", n);
                    format!("SELECT arrow_cast(NULL, '{fields}')")
                }),
            ),
        ];
        for (name, shape) in shapes {
            assert_limit(name, "data types nested", MAX_TYPE_DEPTH, shape);
        }

        // A suffix nests the type it follows, and a constructor the type inside it, so the
        // suffixes after each closed constructor count with the ones inside it.
        let mixed = |inner: usize, outer: usize| {
            let element = format!("INT{}", "[]".repeat(inner));
            let arrays = wrap("ARRAY<", &element, ">", 3);
            format!("SELECT CAST(NULL AS {arrays}{})", "[]".repeat(outer))
        };
        for (inner, outer) in [(MAX_TYPE_DEPTH - 3, 0), (0, MAX_TYPE_DEPTH - 3), (2, 3)] {
            verify_sql(&mixed(inner, outer)).unwrap();
            for (inner, outer) in [(inner + 1, outer), (inner, outer + 1)] {
                let error = verify_sql(&mixed(inner, outer)).unwrap_err().to_string();
                assert!(
                    error.contains("data types nested"),
                    "{inner} {outer}: {error}"
                );
            }
        }

        // UNION ( and TABLE ( are counted apart, up to the same limit.
        let shared = |n: usize| format!("SELECT CAST(NULL AS {})", wrap("UNION(a ", "INT", ")", n));
        assert_limit("UNION", "data types nested", MAX_TYPE_DEPTH, shared);
        let both = wrap("UNION(a ARRAY<", "INT", ">)", MAX_TYPE_DEPTH);
        verify_sql(&format!("SELECT CAST(NULL AS {both})")).unwrap();
    }

    #[test]
    fn type_strings_must_be_literals() {
        // DataFusion folds a constant argument before the function parses it, so only a
        // literal shows the type the function will read.
        for sql in [
            "SELECT arrow_cast(1, 'Int' || '8')",
            "SELECT arrow_cast(1, repeat('List(', 3000) || 'Int64' || repeat(')', 3000))",
            "SELECT 1 WHERE ARROW_TRY_CAST(1, lower('INT8')) IS NULL",
            "SELECT arrow_cast(1, ('Int8'))",
            "SELECT arrow_cast(1, 8)",
        ] {
            let error = verify_sql(sql).unwrap_err().to_string();
            assert!(error.contains("string literal"), "{sql}: {error}");
        }
        for sql in [
            "SELECT arrow_cast(1, 'Int8')",
            "SELECT arrow_cast(x + 1, 'Timestamp(Nanosecond, Some(\"UTC\"))') FROM t",
            "SELECT arrow_try_cast(x, 'Dictionary(Int8, Utf8)') FROM t",
        ] {
            verify_sql(sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
        }
    }

    #[test]
    fn type_strings_are_read_the_way_arrow_reads_them() {
        // Arrow's parser decides what nests. Each string is as deep as the walk says when
        // Arrow accepts it.
        for (data_type, depth) in [
            ("Int64", 0),
            ("List(Int64)", 1),
            ("Struct(\"a\": Int64, \"b\": List(Int64))", 2),
            ("Struct(\"(((\": Int64)", 1),
            ("Struct(\")\": Struct(\")\": Int64))", 2),
            ("Struct(\"a'b(\": Int64)", 1),
            ("Timestamp(Nanosecond, Some(\"UTC\"))", 2),
            ("Dictionary(Int8, Utf8)", 1),
        ] {
            assert_eq!(type_string_depth(data_type), depth, "{data_type}");
            let parsed: datafusion::arrow::datatypes::DataType = data_type.parse().unwrap();
            assert!(!parsed.is_null(), "{data_type}");
        }

        // After a backslash in a name, Arrow reads past the next quote, so every later
        // parenthesis may open a level and none is known to close one.
        assert_eq!(type_string_depth("Struct(\"a\\\"((\": Int64)"), 3);
        assert_eq!(type_string_depth("Struct(\"a\\\\\": List(List(Int64)))"), 3);
    }

    #[test]
    fn words_and_brackets_outside_types_are_not_types() {
        // These nest queries, calls, comparisons, and literals with the words and brackets
        // that types use, and none of them is a nested type.
        let compared = |term: &str, operator: &str| vec![term; 20].join(operator);
        let unions = MAX_QUERY_DEPTH - 3;
        let arrays = wrap("ARRAY<", "INT", ">", MAX_TYPE_DEPTH - unions + 1);
        for sql in [
            wrap("SELECT 1 UNION (", "SELECT 1", ")", MAX_QUERY_DEPTH - 1),
            format!("SELECT {}", wrap("struct(", "1", ")", MAX_TYPE_DEPTH)),
            format!("SELECT 1 FROM t WHERE {}", compared("x < 1", " AND ")),
            format!("SELECT {}", vec!["x[1][2]"; 100].join(", ")),
            format!("SELECT {}", wrap("[", "1", "]", 20)),
            "SELECT 1 >> 2, 3 > 2, ARRAY[1, 2][1]".to_string(),
            // A column may have the name of a constructor.
            format!("SELECT 1 FROM t WHERE {}", compared("map < 1", " OR ")),
            format!("SELECT 1 FROM t WHERE {}", compared("array < $1", " OR ")),
            format!("SELECT 1 FROM t WHERE {}", compared("tuple < a", " OR ")),
            format!("SELECT 1 FROM t WHERE {}", compared("nested < 1", " AND ")),
            format!("SELECT 1 FROM t WHERE {}", compared("map < a", " OR ")),
            format!("SELECT 1 FROM t WHERE {}", compared("(array < a)", " AND ")),
            format!("SELECT {} FROM t", compared("f(map < a)", ", ")),
            // Parenthesized operands of a set operation hold types of their own.
            wrap(
                "SELECT 1 UNION (",
                &format!("SELECT CAST(NULL AS {arrays})"),
                ")",
                unions,
            ),
        ] {
            verify_sql(&sql).unwrap_or_else(|error| panic!("{sql:.40} must pass: {error}"));
        }

        // A list of such comparisons reads like a type that nests at every comma.
        let listed = |n: usize| format!("SELECT {} FROM t", vec!["map < a"; n].join(", "));
        assert_limit("comparisons", "data types nested", MAX_TYPE_DEPTH, listed);
    }

    #[test]
    fn every_statement_kind_is_measured() {
        // Each statement holds an operator chain one past the limit.
        let operators = (NESTING_BUDGET - NESTING_COST) / OPERATOR_COST;
        let deep = wrap("", "1", "+1", operators + 1);
        for sql in [
            format!("SELECT {deep}"),
            format!("SELECT 1 WHERE {deep} > 0"),
            format!("SELECT 1 FROM t JOIN u ON {deep} > 0"),
            format!("SELECT 1 GROUP BY {deep}"),
            format!("SELECT 1 ORDER BY {deep}"),
            format!("SELECT 1 LIMIT {deep}"),
            format!("SELECT sum(1) OVER (ORDER BY {deep})"),
            format!("WITH c AS (SELECT {deep}) SELECT 1"),
            format!("VALUES ({deep})"),
            format!("EXPLAIN SELECT {deep}"),
            format!("EXPLAIN ANALYZE SELECT {deep}"),
            format!("INSERT INTO t SELECT {deep}"),
            format!("UPDATE t SET x = {deep}"),
            format!("DELETE FROM t WHERE x = {deep}"),
            format!("PREPARE p AS SELECT {deep}"),
            format!("EXECUTE p({deep})"),
            format!("SET x = {deep}"),
            format!("CREATE TABLE c AS SELECT {deep}"),
            format!("CREATE VIEW v AS SELECT {deep}"),
            format!("COPY (SELECT {deep}) TO 'file.csv'"),
            format!(
                "CREATE EXTERNAL TABLE e (x INT) STORED AS CSV WITH ORDER ({deep}) LOCATION 'x'"
            ),
        ] {
            let error = verify_sql(&sql)
                .expect_err(&format!("{sql:.40} must fail"))
                .to_string();
            assert!(error.contains("expressions nested"), "{sql:.40}: {error}");
        }
    }

    #[test]
    fn statements_far_past_a_limit_fail_before_they_are_planned() {
        // Planning or parsing each of these overflows the 2 MiB stack of a test thread, or
        // does not finish.
        let whens: String = (0..2_500)
            .map(|i| format!(" WHEN x = {i} THEN false"))
            .collect();
        let windows: Vec<_> = (0..1_600)
            .map(|i| format!("count(*) OVER (ORDER BY x + {i})"))
            .collect();
        for (sql, what) in [
            (wrap("", "SELECT 1", "+1", 2_047), "expressions nested"),
            (
                format!("SELECT NULL{}", "['a']".repeat(5_000)),
                "data types nested",
            ),
            (
                format!("SELECT CASE{whens} END FROM t"),
                "expressions nested",
            ),
            (
                wrap("", "SELECT 1", " UNION ALL SELECT 1", 2_000),
                "plans nested",
            ),
            (wrap("", "SELECT 1 AS x", " |> AS a", 8_000), "plans nested"),
            (
                format!("SELECT {} FROM t", windows.join(", ")),
                "plans nested",
            ),
            (wrap("", "SELECT 1 FROM t", ", t", 5_000), "relations"),
            (fan_out(20, 3), "relations"),
            (
                format!(
                    "WITH c0 AS (VALUES {}), c1 AS (SELECT * FROM c0 UNION ALL SELECT * FROM c0)                      SELECT * FROM c1 a, c1 b, c1 c, c1 d",
                    vec!["(1)"; 15_000].join(", ")
                ),
                "expressions and relations",
            ),
            (dotted_fan_out(20, 4), "relations"),
            (
                format!("{}SELECT 1", "EXPLAIN ".repeat(8_000)),
                "statements nested",
            ),
            (
                format!("{}SELECT 1", "DESCRIBE ".repeat(40)),
                "statements nested",
            ),
            (
                format!("SELECT CAST(NULL AS INT{})", "[]".repeat(30_000)),
                "data types nested",
            ),
            (
                format!("SELECT CAST(NULL AS {}INT", "ARRAY<".repeat(9_000)),
                "data types nested",
            ),
            (
                format!("SELECT CAST(NULL AS {}INT", "STRUCT<a ".repeat(5_000)),
                "data types nested",
            ),
            (
                format!(
                    "SELECT CAST(NULL AS {}INT",
                    "STRUCT<a INT OPTIONS(o = 1 > 0), b ".repeat(1_800)
                ),
                "data types nested",
            ),
            (
                format!("SELECT CAST(NULL AS {}INT", "Nullable(".repeat(6_000)),
                "data types nested",
            ),
            (
                format!(
                    "SELECT arrow_cast(1, '{}')",
                    wrap("List(", "Int64", ")", 10_000)
                ),
                "data types nested",
            ),
            (
                format!(
                    "SELECT arrow_cast(1, '{}')",
                    wrap("Struct(\")\": ", "Int64", ")", 5_000)
                ),
                "data types nested",
            ),
        ] {
            let error = plan_sql(&sql).unwrap_err().to_string();
            assert!(error.contains(what), "{sql:.40}: {error}");
        }
    }

    #[test]
    fn plans_far_past_the_budget_are_measured_and_dropped() {
        // Every expression of the chain renames its rows as often as a query may, so
        // DataFusion builds a plan ten thousand steps deep in a loop. Dropping such a plan
        // recurses through every step, whether the service rejects it or DataFusion gives up
        // on the statement after building it.
        let renames = " |> AS a".repeat(PLAN_BUDGET - 2);
        let chained: String = (1..80)
            .map(|table| format!(", c{table} AS (SELECT x FROM c{}{renames})", table - 1))
            .collect();
        for (column, what) in [("x", "plans nested"), ("z", "No field named z")] {
            let error = plan_sql(&format!(
                "WITH c0 AS (SELECT x FROM t{renames}){chained} SELECT {column} FROM c79"
            ))
            .unwrap_err()
            .to_string();
            assert!(error.contains(what), "{column}: {error}");
        }
    }

    #[test]
    fn statements_of_the_greatest_length_are_rejected_and_dropped() {
        // An operator chain nests deepest for its length. One as long as a request may be
        // overflows a 2 MiB stack when its syntax tree is dropped, even though it is never
        // planned.
        let sql = wrap("", "SELECT 1", "+1", 32_763);
        assert_eq!(sql.len(), 65_534);
        let error = parse_statement(&STATE, &sql).unwrap_err().to_string();
        assert!(error.contains("expressions nested"), "{error}");

        // The same chain followed by a syntax error is dropped inside the parser.
        let error = parse_statement(&STATE, &format!("{sql})")).unwrap_err();
        assert!(error.to_string().contains("Expected"), "{error}");

        // A statement within the limits parses to itself.
        let statement = parse_statement(&STATE, "SELECT 1 + 1").unwrap();
        assert_eq!(statement.to_string(), "SELECT 1 + 1");
    }

    #[test]
    fn predicates_are_measured_like_statements() {
        let operators = (NESTING_BUDGET - NESTING_COST) / OPERATOR_COST;
        verify_predicate_nesting(&STATE, &wrap("", "x", " + 1", operators - 1)).unwrap();
        for (sql, what) in [
            (wrap("", "x", " + 1", operators + 1), "expressions nested"),
            (
                format!("x{} IS NULL", "['a']".repeat(800)),
                "data types nested",
            ),
            (
                format!("CAST(x AS INT{}) IS NULL", "[]".repeat(MAX_TYPE_DEPTH + 1)),
                "data types nested",
            ),
            (
                format!(
                    "arrow_cast(x, '{}') IS NULL",
                    wrap("List(", "Int8", ")", 600)
                ),
                "data types nested",
            ),
            (
                format!(
                    "x IN ({})",
                    wrap("", "SELECT 1", " UNION ALL SELECT 1", 200)
                ),
                "plans nested",
            ),
        ] {
            let error = verify_predicate_nesting(&STATE, &sql)
                .unwrap_err()
                .to_string();
            assert!(error.contains(what), "{sql:.40}: {error}");
        }
    }
}
