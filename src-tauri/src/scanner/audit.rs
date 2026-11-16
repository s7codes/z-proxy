//! Static reliability audit of route handlers.
//!
//! Lexical, like the extractors. Each route gets the source regions of its handler: the
//! declaration up to the next route or top-level declaration, the bodies of handlers it
//! names that are defined in the same file (functions, and methods or arrow properties of
//! classes, `new` instances and object literals, whatever their parameter lists hold:
//! defaults that call functions, NestJS parameter decorators) and, for JavaScript, the
//! bodies of handlers it imports from modules inside the scan root: relative specifiers,
//! `tsconfig.json` / `jsconfig.json` `paths` aliases and `baseUrl` specifiers, `package.json`
//! subpath imports (`#handlers/orders`), Next.js re-exports (`export { POST } from
//! "@/handlers/orders"`) and assigned exports (`export const POST = withAuth(create)`). An
//! import that lands on a module without the handler is followed up to two modules further:
//! through `export ... from` and `export *` barrels, re-exported imports, and exported
//! instances of classes defined elsewhere. Six checks then run over the comment-masked text
//! of those regions. Every check needs positive evidence (a body read, a collection query, a
//! dropped call, an unguarded write, an interpolated query, a blocking call), so a handler
//! the pass cannot resolve yields no risk rather than a guess.

use std::cell::{OnceCell, RefCell};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::{Captures, Regex};

use super::lex::{self, Lang, Source};
use super::routes::{compile, relative, RawRoute, MAX_SOURCE_BYTES};
use super::tsconfig::{PathAliases, SubpathImports};
use crate::engine::types::{RouteMethod, RouteRisk, RouteRiskKind, RouteSource};

/// A handler region never extends past this many lines, so a route at the end of a long
/// file without further declarations is not judged by unrelated code.
const MAX_REGION_LINES: usize = 160;
const MAX_NAMED_HANDLERS: usize = 3;
const EVIDENCE_CHARS: usize = 120;
/// Bytes after a query call searched for a chained `.limit(` / `.then(`.
const CHAIN_WINDOW: usize = 400;
/// Modules read per audited file, imported or reached through re-exports; each is read once
/// however many routes use it.
const MAX_IMPORTED_MODULES: usize = 16;
/// Modules followed past the one an import names when that one does not define the handler.
const MAX_HOPS: usize = 2;
/// `export * from` modules tried for one name.
const MAX_STAR_EXPORTS: usize = 4;
/// Extensions tried, in order, for an import specifier written without one.
const JS_EXTENSIONS: [&str; 8] = ["ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts"];
/// Writes named in a risk's detail before the rest is summarized.
const LISTED_WRITES: usize = 3;

static JS_DECLARATIONS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?m)^(?:export[ \t]+)?(?:default[ \t]+)?(?:async[ \t]+)?function[ \t]*\*?[ \t]*([A-Za-z_$][\w$]*)?",
        r"(?m)^(?:export[ \t]+)?(?:const|let|var)[ \t]+([A-Za-z_$][\w$]*)[ \t]*(?::[^=\n]+)?=[ \t]*(?:async(?-u:\b)|function(?-u:\b)|\(|[A-Za-z_$][\w$]*[ \t]*=>)",
        // One level of nested parentheses: `create(@Body() dto)`, `list(limit = cap())`.
        r"(?m)^[ \t]+(?:(?:public|private|protected|static|override)[ \t]+)*(?:async[ \t]+)?([A-Za-z_$][\w$]*)[ \t]*\((?:[^()\n]|\([^()\n]*\))*\)[ \t]*(?::[^{\n]+)?\{",
        r"(?m)^(?:export[ \t]+)?(?:default[ \t]+)?class(?-u:\b)",
        // CommonJS exports: `exports.create = ...`, `module.exports.create = ...` name a
        // handler; a bare `module.exports = ...` only ends the previous region.
        r"(?m)^(?:module\.)?exports(?:\.([A-Za-z_$][\w$]*))?[ \t]*=",
    ]
    .iter()
    .filter_map(|pattern| compile(pattern))
    .collect()
});
static RUST_DECLARATIONS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    compile(r"(?m)^[ \t]*(?:pub(?:\([^)\n]*\))?[ \t]+)?(?:async[ \t]+)?fn[ \t]+([A-Za-z_]\w*)")
        .into_iter()
        .collect()
});
static GO_DECLARATIONS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    compile(r"(?m)^func[ \t]+(?:\([^)\n]*\)[ \t]*)?([A-Za-z_]\w*)")
        .into_iter()
        .collect()
});
/// Words that look like a method declaration (`if (x) {`) inside a function body.
const NOT_DECLARATIONS: [&str; 8] = [
    "if", "for", "while", "switch", "catch", "function", "return", "with",
];

static AXUM_HANDLER: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(r"(?-u:\b)(get|post|put|patch|delete|head|options|any)\s*\(\s*([A-Za-z_][\w:]*)\s*\)")
});
static IDENTIFIER: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*"));
/// A handler passed through an async wrapper: `asyncHandler(createOrder)`.
static WRAPPED_HANDLER: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?-u:\b)(?:asyncHandler|catchAsync|wrapAsync|asyncWrap|expressAsyncHandler|catchErrors)\s*\(\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\)",
    )
});

// ---- imports --------------------------------------------------------------------------

/// `import x, { a, b as c } from "m"`, `import * as ns from "m"`. Any specifier: whether it
/// names a project file (relative, `paths` alias, `baseUrl`) is decided on resolution.
static ESM_IMPORT: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(r#"(?m)^[ \t]*import[ \t]+([^;'"`]+?)[ \t]+from[ \t]*['"]([^'"\n]+)['"]"#)
});
/// `const x = require("m")`, `const { a, b: c } = require("m")`, `require("m").a`.
static CJS_REQUIRE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r#"(?m)^[ \t]*(?:const|let|var)[ \t]+(\{[^}]*\}|[A-Za-z_$][\w$]*)[ \t]*=[ \t]*require\(\s*['"]([^'"\n]+)['"]\s*\)(?:\.([A-Za-z_$][\w$]*))?"#,
    )
});
/// `export { POST, x as PUT } from "m"`; the list may span lines.
static EXPORT_FROM: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(r#"(?-u:\b)export[ \t]*\{([^}]*)\}[ \t]*from[ \t]*['"]([^'"\n]+)['"]"#)
});
static EXPORT_LIST: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"(?-u:\b)export[ \t]*\{([^}]*)\}"));
/// `export * from "m"`; a namespace re-export (`export * as ns from`) does not match.
static EXPORT_STAR: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r#"(?m)^[ \t]*export[ \t]*\*[ \t]*from[ \t]*['"]([^'"\n]+)['"]"#));
/// `[export] const NAME = <expression>` up to the end of the line.
static ASSIGNMENT: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?m)^[ \t]*(?:export[ \t]+)?(?:const|let|var)[ \t]+([A-Za-z_$][\w$]*)[ \t]*(?::[^=\n]+)?=[ \t]*([^;\n]+)",
    )
});
/// `wrapper(handler, ...)`: the first argument when it is a plain reference.
static WRAPPED_REFERENCE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(r"^[A-Za-z_$][\w$.]*\s*\(\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*[,)]")
});

// ---- classes, instances and object literals --------------------------------------------

/// `class Name ... {`; the match ends at the body's `{`.
static CLASS_DECL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?m)^[ \t]*(?:export[ \t]+)?(?:default[ \t]+)?(?:abstract[ \t]+)?class[ \t]+([A-Za-z_$][\w$]*)[^{\n]*\{",
    )
});
/// `const name = {`; the match ends at the literal's `{`.
static OBJECT_DECL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?m)^[ \t]*(?:export[ \t]+)?(?:const|let|var)[ \t]+([A-Za-z_$][\w$]*)[ \t]*(?::[^=\n]+)?=[ \t]*\{",
    )
});
/// `const name = new Class(`; group 2 may be namespaced (`new controllers.Orders(`).
static INSTANCE_DECL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?m)^[ \t]*(?:export[ \t]+)?(?:const|let|var)[ \t]+([A-Za-z_$][\w$]*)[ \t]*(?::[^=\n]+)?=[ \t]*new[ \t]+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)",
    )
});
/// The default export as a container: a class (ends at its `{`), a `new` instance (group 1),
/// an object literal (ends at its `{`), or a name (group 2).
static DEFAULT_CONTAINER: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(concat!(
        r"(?m)^(?:export[ \t]+default|module\.exports[ \t]*=)[ \t]*",
        r"(?:(?:abstract[ \t]+)?class(?-u:\b)[^{\n]*\{|new[ \t]+([A-Za-z_$][\w$]*)|\{|([A-Za-z_$][\w$]*)[ \t]*;?[ \t]*\r?$)",
    ))
});
/// The head of a member at the start of a line inside a class body or object literal, up to
/// the `(` of its parameter list: a method (group 2), a property holding a function (group
/// 3) or a parenthesized arrow (group 4); or a one-parameter arrow through its `=>` (group
/// 5). The parameter list itself is matched by bracket, so defaults that call functions and
/// parameter decorators (`@Body() dto`, `@Param('id') id`) do not hide the member. Decorators
/// on the same line (`@Post(':id') async create(`) are allowed.
static MEMBER_HEAD: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(concat!(
        r"(?m)^[ \t]*(?:@[A-Za-z_$][\w$.]*(?:\((?:[^()\n]|\([^()\n]*\))*\))?[ \t]+)*",
        r"(?:(?:public|private|protected|static|readonly|override|async)[ \t]+)*\*?[ \t]*",
        r"([A-Za-z_$][\w$]*)[ \t]*(?:<[^>\n]*>)?[ \t]*",
        r"(?:(\()|[:=][ \t]*(?:async[ \t]+)?(?:function(?-u:\b)[ \t]*\*?[ \t]*(?:[A-Za-z_$][\w$]*)?[ \t]*(\()|(\()|[A-Za-z_$][\w$]*[ \t]*(=>)))",
    ))
});
/// A default export defined in place, or naming a declaration (group 1).
static DEFAULT_EXPORT: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?m)^(?:export[ \t]+default|module\.exports[ \t]*=)[ \t]*(?:(?:async[ \t]+)?(?:function(?-u:\b)|\(|[A-Za-z_$][\w$]*[ \t]*=>)|([A-Za-z_$][\w$]*)[ \t]*;?[ \t]*\r?$)",
    )
});

// ---- unvalidated mutation -------------------------------------------------------------

/// Express / Koa / Next body reads, and Hono's `c.req` readers. `c.req.valid(...)` returns
/// what a validator middleware already checked; it counts as a read and as validation.
static JS_BODY_READ: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(concat!(
        r"(?-u:\b)(?:req|request|ctx\.request)\.body(?-u:\b)|\.(?:json|formData)\(\s*\)",
        r"|(?-u:\b)(?:c|ctx|context)\.req\.(?:parseBody|valid|text|arrayBuffer)\(",
    ))
});
static JS_VALIDATOR: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(concat!(
        r"(?-u:\b)z\.[a-z]+\(|(?-u:\b)(?:zod|valibot|yup|ajv|Ajv|superstruct|class-validator)(?-u:\b)",
        r"|(?-u:\b)(?:Joi|v)\.(?:object|parse)\(|(?-u:\b)Type\.Object\(|(?-u:\b)schema\s*:",
        r"|(?-u:\b)(?:validate|validator|validation|validationResult)|[a-z]Validat(?:e|or|ion)",
        r"|\.req\.valid\(",
    ))
});
/// `Schema.parse(` and friends; the receiver decides whether it is a schema.
static PARSE_CALL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(r"([A-Za-z_$][\w$]*)\s*\.\s*(?:safeParse|parse|parseAsync|safeParseAsync)\s*\(")
});
const NON_SCHEMA_PARSERS: [&str; 9] = [
    "JSON",
    "Date",
    "url",
    "URL",
    "qs",
    "querystring",
    "path",
    "Number",
    "BigInt",
];
static RUST_BODY_READ: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?-u:\b)(?:Json|Form)\s*<|(?-u:\b)Bytes(?-u:\b)|serde_json::from_(?:slice|str)|(?-u:\b)Multipart(?-u:\b)",
    )
});
/// A typed extractor or decode target; the type is checked for untyped maps separately.
static RUST_TYPED: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(r"(?-u:\b)(?:Json|Form)\s*<\s*([\w:]+)|from_(?:slice|str)\s*::\s*<\s*([\w:]+)")
});
static RUST_VALIDATOR: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"\.validate\(\s*\)|(?-u:\b)Valid(?:ated)?(?:Json)?\s*<|#\[validate"));
const UNTYPED_RUST: [&str; 4] = ["Value", "Map", "HashMap", "BTreeMap"];
static GO_BODY_READ: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?-u:\b)(?:r|req)\.Body(?-u:\b)|\.(?:Bind|ShouldBind)\w*\(|\.BodyParser\(|(?-u:\b)c\.Body\(\)",
    )
});
static GO_VALIDATOR: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"ShouldBind|BindJSON|\.Bind\(|(?-u:\b)validator\.|\.Validate\(|\.Struct\(|DisallowUnknownFields|\.Decode\(\s*&|json\.Unmarshal\(",
    )
});

// ---- unbounded query ------------------------------------------------------------------

/// ORM collection reads; group 1 is the call name, the match ends at its `(`.
static ORM_COLLECTION: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"\.(findMany|findAll|find|Find)\s*\("));
static ORM_BOUND: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"(?-u:\b)(?:take|limit|first|last|Limit|paginate|Paginate)(?-u:\b)"));
static SQL_SELECT: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"(?i)(?-u:\b)select(?-u:\b)"));
static SQL_FROM: LazyLock<Option<Regex>> = LazyLock::new(|| compile(r"(?i)(?-u:\b)from(?-u:\b)"));
static SQL_BOUND: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(concat!(
        r"(?i)(?-u:\b)(?:limit|top|fetch\s+(?:first|next)|count|sum|avg|min|max|exists)(?-u:\b)",
        r"|(?i)(?-u:\b)where(?-u:\b)[^;]*(?:^|[\s.(])(?:id|uuid)\s*=",
    ))
});

// ---- floating async -------------------------------------------------------------------

/// A statement-level call; the receiver chain may break across lines (`prisma.order` /
/// `  .create(`), so group 1 can hold whitespace.
static JS_FLOATING: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(concat!(
        r"(?m)^[ \t]*((?:this\.)?[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\.\s*",
        r"(save|create|createMany|update|updateMany|upsert|delete|deleteMany|insert|insertOne|insertMany|updateOne|deleteOne|destroy|execute|query|publish|sendMail|enqueue|commit)[ \t]*\(",
        r"|(?m)^[ \t]*()(fetch)[ \t]*\(",
    ))
});
/// Receivers whose CRUD-named methods are I/O even with a one-segment chain. Anything else
/// needs a model segment (`prisma.order.create`), since `map.delete(key)` is synchronous.
const IO_RECEIVERS: [&str; 16] = [
    "db",
    "prisma",
    "knex",
    "sql",
    "pool",
    "client",
    "tx",
    "trx",
    "repo",
    "repository",
    "em",
    "manager",
    "collection",
    "queue",
    "mailer",
    "transporter",
];
static GO_DROPPED: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?m)^[ \t]*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.(?:Exec|ExecContext|Commit|Create|Save|Delete|Update|Updates)\(",
    )
});
static AWAIT: LazyLock<Option<Regex>> = LazyLock::new(|| compile(r"(?-u:\b)await(?-u:\b)"));
/// `try {}` or handing the error to Express. A `.catch(` on some other promise in the
/// handler does not guard the awaited ones.
static ERROR_PATH: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"(?-u:\b)try\s*\{|(?-u:\b)next\s*\(|\.catch\(\s*next\s*\)"));
const ASYNC_WRAPPERS: [&str; 5] = [
    "asyncHandler",
    "catchAsync",
    "wrapAsync",
    "asyncWrap",
    "expressAsyncHandler",
];

// ---- non-atomic multi-write -----------------------------------------------------------

/// A write call on a receiver chain, optionally through one call (`db.collection("o")`);
/// group 1 is the receiver, group 2 the method, and the match ends at the method's `(`. The
/// chain may break across lines (`prisma.order` / `  .create(`), so group 1 can hold
/// whitespace.
static WRITE_CALL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(concat!(
        r"((?:this\.)?[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)(?:\s*\([^()\n]*\))?\s*\.\s*",
        r"(create|createMany|update|updateMany|upsert|delete|deleteMany|insert|insertOne|insertMany|updateOne|deleteOne|replaceOne|save|destroy|execute|Exec|ExecContext|Create|Save|Delete|Update|Updates|UpdateColumn|UpdateColumns)[ \t]*\(",
    ))
});
static SQL_WRITE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(r#"(?i)(?-u:\b)(?:insert\s+into|delete\s+from|update\s+[\w."`\[\]]+\s+set)(?-u:\b)"#)
});
/// A call whose arguments run inside a transaction: Prisma `$transaction`, Knex, Sequelize,
/// TypeORM, Drizzle and Mongoose `transaction` / `withTransaction`, GORM `Transaction`,
/// Diesel and SeaORM `transaction::<..>`. Without arguments it returns a handle instead.
static TX_CALL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(concat!(
        r"\$transaction\s*\(",
        r"|(?-u:\b)(?:transaction|withTransaction|runInTransaction|Transaction)\s*(?:::\s*<[^>\n]*>\s*)?\(",
    ))
});
/// A handle-style begin; writes after it in the same region are taken to use the handle.
static TX_BEGIN: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?-u:\b)(?:begin|Begin|BeginTx|beginTransaction|startTransaction|start_transaction)\s*\(",
    )
});
/// A transaction handle among a write's arguments: `.execute(&mut *tx)`,
/// `Model.create(row, { transaction: t })`.
static TX_HANDLE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"(?-u:\b)(?:tx|trx|txn)(?-u:\b)|(?-u:\b)transaction\s*:"));
/// The call a SQL string is passed to runs on a handle: `tx.query(`.
static TX_RECEIVER: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(r"(?-u:\b)(?:tx|trx|txn|transaction)\s*\.\s*[A-Za-z_$][\w$]*\s*\(\s*$")
});
/// Receiver roots that are transaction handles (`tx.order.create(`). A model that happens to
/// be called `transaction` (`prisma.transaction.create(`) has another root.
const TX_ROOTS: [&str; 4] = ["tx", "trx", "txn", "transaction"];
/// A decorator or attribute that wraps the whole handler in a transaction.
static TX_DECORATOR: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"@Transactional|#\[\s*transactional"));
static SQL_TX: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"(?-u:\b)(?:BEGIN|START TRANSACTION)(?-u:\b)"));
/// A transaction begun into a binding: `const tx = await db.begin()`, `const t = await
/// sequelize.transaction()`, `let mut tx = pool.begin().await?`. Group 1 is the handle,
/// group 2 the connection it was begun on, group 3 the begin call.
static TX_BOUND: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(concat!(
        r"(?-u:\b)(?:const|let|var)[ \t]+(?:mut[ \t]+)?([A-Za-z_$][\w$]*)[ \t]*(?::[^=\n]+)?=[ \t]*(?:await[ \t]+)?",
        r"((?:this\.|self\.)?[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*?)[ \t]*\.[ \t]*",
        r"(begin|beginTransaction|startTransaction|transaction|start_transaction)[ \t]*\(",
    ))
});
/// Go: `tx, err := db.Begin()`, `tx := db.BeginTx(ctx, nil)`.
static GO_TX_BOUND: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(concat!(
        r"(?-u:\b)([A-Za-z_]\w*)(?:[ \t]*,[ \t]*[A-Za-z_]\w*)?[ \t]*:?=[ \t]*",
        r"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*?)[ \t]*\.[ \t]*(Begin|BeginTx)[ \t]*\(",
    ))
});

// ---- blocking calls in async handlers ---------------------------------------------------

/// Node calls that block the event loop: synchronous file system and child process calls,
/// and the synchronous key derivation of `crypto` and bcrypt.
static JS_BLOCKING: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(concat!(
        r"(?-u:\b)(readFileSync|writeFileSync|appendFileSync|existsSync|statSync|readdirSync",
        r"|execSync|execFileSync|spawnSync|pbkdf2Sync|scryptSync|hashSync|compareSync|genSaltSync)[ \t]*\(",
    ))
});
/// Calls that block a Tokio worker thread: a thread sleep, `std::fs`, and bcrypt's CPU-bound
/// hash.
static RUST_BLOCKING: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(r"(?-u:\b)((?:std::)?thread::sleep|std::fs::[a-z_]+|bcrypt::(?:hash|verify))[ \t]*\(")
});
/// A blocking call inside these runs on a thread meant for it.
static OFFLOADED: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"(?-u:\b)(?:spawn_blocking|block_in_place)[ \t]*\("));
/// Loop headers; the match ends at the `(` of the condition or callback, or at the body's
/// `{`. The first group that took part names the loop.
static JS_LOOP: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?-u:\b)(for(?:[ \t]+await)?)[ \t]*\(|(?-u:\b)(while)[ \t]*\(|(?-u:\b)(do)[ \t]*\{|\.\s*(forEach|map|flatMap)\s*\(",
    )
});
static RUST_LOOP: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?-u:\b)(for)[ \t]+[^{};]+?[ \t]+in[ \t]+[^{;]+\{|(?-u:\b)(while)[ \t]+[^{;]+\{|(?-u:\b)(loop)[ \t]*\{|\.\s*(for_each|try_for_each)\s*\(",
    )
});
static GO_LOOP: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"(?m)(?-u:\b)(for)(?:[ \t]+[^{\n]*)?[ \t]*\{"));
/// Receiver segments that hold request, response or in-memory state, never a database.
const NON_DB_SEGMENTS: [&str; 18] = [
    "searchParams",
    "headers",
    "cookies",
    "session",
    "params",
    "query",
    "body",
    "locals",
    "classList",
    "dataset",
    "map",
    "set",
    "cache",
    "storage",
    "localStorage",
    "sessionStorage",
    "formData",
    "res",
];
/// Capitalized receivers that are runtime globals, not models (`Object.create`).
const GLOBAL_OBJECTS: [&str; 18] = [
    "Object",
    "Array",
    "Promise",
    "Reflect",
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
    "JSON",
    "Math",
    "Date",
    "Number",
    "String",
    "Symbol",
    "Buffer",
    "URL",
    "URLSearchParams",
    "React",
];
/// Go packages whose `Create` / `Delete` touch files or templates, not a database.
const GO_NON_DB: [&str; 8] = [
    "os", "ioutil", "fs", "afero", "filepath", "zip", "tar", "template",
];

// ---- unsafe SQL interpolation ---------------------------------------------------------

/// SQL statement shapes: keywords in the order a query uses them, so prose that merely
/// contains "select" or "update" does not qualify.
static SQL_SHAPE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(concat!(
        r#"(?is)(?-u:\b)select(?-u:\b).{1,200}?(?-u:\b)from(?-u:\b)"#,
        r#"|(?-u:\b)(?:insert\s+into|delete\s+from|update\s+[\w."`\[\]]+\s+set)(?-u:\b)"#,
        r#"|(?-u:\b)where\s+[\w."`\[\]]+\s*(?:=|<|>|!=|<>|(?-u:\b)like(?-u:\b)|(?-u:\b)in(?-u:\b))"#,
    ))
});
/// Words after which a backtick opens an untagged template, not a tag's argument.
const TEMPLATE_PRECEDERS: [&str; 11] = [
    "return", "await", "yield", "typeof", "case", "in", "of", "void", "throw", "new", "else",
];

/// What cross-file resolution needs to know about the scanned project.
pub struct Project<'p> {
    /// Canonical scan root; resolved modules must stay inside it.
    pub root: &'p Path,
    /// Directory of the file being audited.
    pub dir: &'p Path,
    /// The nearest `package.json` declares Express 5, which forwards a rejected handler
    /// promise to the error middleware by itself.
    pub express_native_async: bool,
    /// `paths` / `baseUrl` of the nearest `tsconfig.json` or `jsconfig.json`.
    pub aliases: Option<&'p PathAliases>,
    /// Subpath `imports` of the nearest `package.json`.
    pub imports: Option<&'p SubpathImports>,
}

impl<'p> Project<'p> {
    /// The file a specifier names: relative to the audited file, a `#` subpath import of the
    /// package, else through the config's `paths` and `baseUrl`. A package name that no
    /// alias covers resolves to nothing.
    fn resolve(&self, spec: &str) -> Option<PathBuf> {
        if spec.starts_with('.') {
            return self.probe(&self.dir.join(spec));
        }
        if spec.starts_with('#') {
            return self
                .imports?
                .candidates(spec)
                .iter()
                .find_map(|base| self.probe(base));
        }
        self.aliases?
            .candidates(spec)
            .iter()
            .find_map(|base| self.probe(base))
    }

    /// The same project seen from another directory, for a module's own imports.
    fn at<'d>(&self, dir: &'d Path) -> Project<'d>
    where
        'p: 'd,
    {
        Project {
            root: self.root,
            dir,
            express_native_async: self.express_native_async,
            aliases: self.aliases,
            imports: self.imports,
        }
    }

    /// `base` as written, with each JavaScript extension, or as a directory index. A `.js`
    /// path also tries the TypeScript source beside it (`./orders.js` compiled from
    /// `./orders.ts`). `None` outside the scan root.
    fn probe(&self, base: &Path) -> Option<PathBuf> {
        let base = base.to_path_buf();
        let extension = base
            .extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_ascii_lowercase);
        let mut candidates = Vec::with_capacity(2 * JS_EXTENSIONS.len() + 1);
        match extension.as_deref() {
            Some(ext) if JS_EXTENSIONS.contains(&ext) => {
                candidates.push(base.clone());
                if matches!(ext, "js" | "jsx" | "mjs" | "cjs") {
                    candidates
                        .extend(["ts", "tsx", "mts", "cts"].map(|ts| base.with_extension(ts)));
                }
            }
            _ => {
                candidates.extend(JS_EXTENSIONS.map(|ext| {
                    let mut name = base.as_os_str().to_owned();
                    name.push(".");
                    name.push(ext);
                    PathBuf::from(name)
                }));
                candidates.extend(JS_EXTENSIONS.map(|ext| base.join(format!("index.{ext}"))));
            }
        }
        let found = candidates
            .into_iter()
            .find(|candidate| candidate.is_file())?;
        // Canonical form resolves `..` and symlinks before the containment check.
        let canonical = std::fs::canonicalize(found).ok()?;
        canonical.starts_with(self.root).then_some(canonical)
    }

    fn load(&self, path: &Path) -> Option<(String, Source)> {
        if std::fs::metadata(path).ok()?.len() > MAX_SOURCE_BYTES {
            return None;
        }
        let text = String::from_utf8(std::fs::read(path).ok()?).ok()?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        Some((relative(self.root, path), Source::new(text, Lang::Js)))
    }
}

/// What an import binding stands for in its module.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Export {
    Default,
    Named(String),
    /// A namespace import or a whole `require`d module: used bare it is the default export,
    /// used with a member (`orders.create`) the named one.
    Module,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Default,
    Named(String),
    /// `member` of the class, `new` instance or object literal the module declares as
    /// `container`, or of its default export when `None`.
    Member {
        container: Option<String>,
        member: String,
    },
}

/// A handler a route names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Reference {
    /// As written in this file: a declaration, a member (`controller.create`) or an import.
    Name(String),
    /// A re-export: module specifier and the export there.
    Module { spec: String, target: Target },
}

#[derive(Debug)]
struct Binding {
    local: String,
    module: String,
    export: Export,
}

fn import_bindings(source: &Source) -> Vec<Binding> {
    let text = source.text.as_str();
    let mut bindings = Vec::new();
    if let Some(re) = ESM_IMPORT.as_ref() {
        for caps in re.captures_iter(text) {
            let (Some(whole), Some(clause), Some(module)) = (caps.get(0), caps.get(1), caps.get(2))
            else {
                continue;
            };
            if !source
                .in_string(whole.start() + whole.as_str().len() - whole.as_str().trim_start().len())
            {
                esm_bindings(clause.as_str(), module.as_str(), &mut bindings);
            }
        }
    }
    if let Some(re) = CJS_REQUIRE.as_ref() {
        for caps in re.captures_iter(text) {
            let (Some(whole), Some(pattern), Some(module)) =
                (caps.get(0), caps.get(1), caps.get(2))
            else {
                continue;
            };
            if source
                .in_string(whole.start() + whole.as_str().len() - whole.as_str().trim_start().len())
            {
                continue;
            }
            let module = module.as_str();
            let pattern = pattern.as_str();
            match pattern.strip_prefix('{').and_then(|p| p.strip_suffix('}')) {
                Some(list) => {
                    for item in list.split(',').map(str::trim).filter(|i| !i.is_empty()) {
                        let (imported, local) = item
                            .split_once(':')
                            .map_or((item, item), |(a, b)| (a.trim(), b.trim()));
                        if is_js_identifier(imported) && is_js_identifier(local) {
                            bindings.push(Binding {
                                local: local.to_owned(),
                                module: module.to_owned(),
                                export: Export::Named(imported.to_owned()),
                            });
                        }
                    }
                }
                None => bindings.push(Binding {
                    local: pattern.to_owned(),
                    module: module.to_owned(),
                    export: caps.get(3).map_or(Export::Module, |member| {
                        Export::Named(member.as_str().to_owned())
                    }),
                }),
            }
        }
    }
    bindings
}

fn esm_bindings(clause: &str, module: &str, out: &mut Vec<Binding>) {
    let clause = clause.trim();
    if clause.starts_with("type ") || clause.starts_with("type{") {
        return;
    }
    let (head, list) = match clause.split_once('{') {
        Some((head, rest)) => (head, rest.split('}').next()),
        None => (clause, None),
    };
    let mut push = |local: &str, export: Export| {
        if is_js_identifier(local) {
            out.push(Binding {
                local: local.to_owned(),
                module: module.to_owned(),
                export,
            });
        }
    };
    for part in head.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part.strip_prefix('*') {
            Some(rest) => {
                if let Some(local) = rest.trim().strip_prefix("as") {
                    push(local.trim(), Export::Module);
                }
            }
            None => push(part, Export::Default),
        }
    }
    for item in list
        .into_iter()
        .flat_map(|list| list.split(','))
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        // Type-only specifiers are erased at compile time; no handler can come from them.
        if item.starts_with("type ") {
            continue;
        }
        let (imported, local) = item
            .split_once(" as ")
            .map_or((item, item), |(a, b)| (a.trim(), b.trim()));
        let export = if imported == "default" {
            Export::Default
        } else {
            Export::Named(imported.to_owned())
        };
        push(local, export);
    }
}

/// Module specifier and export a handler reference (`create`, `orders.create`) points at.
/// A member of a whole-module import is that module's named export; a member of a default
/// or named import belongs to the class instance or object literal exported under it.
fn import_target<'b>(bindings: &'b [Binding], reference: &str) -> Option<(&'b str, Target)> {
    match reference.rsplit_once('.') {
        Some((head, member)) => {
            let root = head.split('.').next().unwrap_or(head);
            let binding = bindings.iter().find(|b| b.local == root)?;
            let member = member.to_owned();
            let target = match &binding.export {
                _ if head.contains('.') => Target::Named(member),
                Export::Module => Target::Named(member),
                Export::Default => Target::Member {
                    container: None,
                    member,
                },
                Export::Named(name) => Target::Member {
                    container: Some(name.clone()),
                    member,
                },
            };
            Some((binding.module.as_str(), target))
        }
        None => {
            let binding = bindings.iter().find(|b| b.local == reference)?;
            let target = match &binding.export {
                Export::Default | Export::Module => Target::Default,
                Export::Named(name) => Target::Named(name.clone()),
            };
            Some((binding.module.as_str(), target))
        }
    }
}

/// Module and container of a class a file imports, for the members of its `new` instances:
/// `Orders` from `import { Orders }` is the named export, from `import Orders` the default
/// one, and `ns.Orders` from `import * as ns` the named export of that module.
fn class_import<'b>(bindings: &'b [Binding], class: &str) -> Option<(&'b str, Option<String>)> {
    match class.split_once('.') {
        Some((namespace, name)) => {
            let binding = bindings
                .iter()
                .find(|b| b.local == namespace && b.export == Export::Module)?;
            Some((binding.module.as_str(), Some(name.to_owned())))
        }
        None => {
            let binding = bindings.iter().find(|b| b.local == class)?;
            let container = match &binding.export {
                Export::Named(name) => Some(name.clone()),
                Export::Default | Export::Module => None,
            };
            Some((binding.module.as_str(), container))
        }
    }
}

/// The name an export list (`GET, create as POST, type T`) binds to `exported`.
fn exported_as<'l>(list: &'l str, exported: &str) -> Option<&'l str> {
    list.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty() && !item.starts_with("type "))
        .find_map(|item| {
            let (local, name) = item
                .split_once(" as ")
                .map_or((item, item), |(local, name)| (local.trim(), name.trim()));
            (name == exported).then_some(local)
        })
}

/// The handler an assigned expression stands for: a plain reference (`create`,
/// `orders.create`) or the first argument of a wrapper call (`withAuth(create)`). `None`
/// for a function written in place.
fn wrapped_reference(expression: &str) -> Option<String> {
    let expression = expression.trim();
    if expression.starts_with("async")
        || expression.starts_with("function")
        || expression.contains("=>")
    {
        return None;
    }
    if expression
        .split('.')
        .all(|segment| is_js_identifier(segment.trim()))
    {
        return Some(expression.replace(char::is_whitespace, ""));
    }
    WRAPPED_REFERENCE
        .as_ref()?
        .captures(expression)?
        .get(1)
        .map(|m| m.as_str().to_owned())
}

fn is_js_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// Annotates `routes` with the risks found in their handlers. With a `project`, handlers a
/// JavaScript file imports or re-exports from modules inside the scan root are read and
/// audited as well; their evidence carries the module's path.
pub fn annotate(
    source: &Source,
    lang: Lang,
    routes: &mut [RawRoute],
    project: Option<&Project<'_>>,
) {
    if routes.is_empty() {
        return;
    }
    let native_async = project.is_some_and(|p| p.express_native_async);
    let home = FileContext::new(source, lang, routes, None, native_async);
    let bindings = match lang {
        Lang::Js => import_bindings(source),
        Lang::Rust | Lang::Go => Vec::new(),
    };

    // Every route's imported handlers are located first, so a module shared by several
    // routes (or reached through the same barrel) is read once.
    let modules = ModuleSet::default();
    let contexts = Contexts::new(&modules, native_async);
    let mut wanted: Vec<Vec<(usize, Target)>> = vec![Vec::new(); routes.len()];
    if let (Some(project), Lang::Js) = (project, lang) {
        for (index, route) in routes.iter().enumerate() {
            let line = usize::try_from(route.line).unwrap_or(0);
            for (spec, target) in home.imported_targets(route, line, &bindings) {
                let found = contexts.locate(project, &spec, target, 0);
                if let (Some(found), Some(slot)) = (found, wanted.get_mut(index)) {
                    slot.push(found);
                }
            }
        }
    }

    for (index, route) in routes.iter_mut().enumerate() {
        let mut regions = home.handler_regions(route, &bindings);
        for (slot, target) in wanted.get(index).into_iter().flatten() {
            let Some(module) = contexts.get(*slot) else {
                continue;
            };
            let ctx = &module.ctx;
            if let Some(range) = ctx.export_region(target) {
                let known = regions
                    .iter()
                    .any(|r| std::ptr::eq(r.ctx, ctx) && r.range == range);
                if !known {
                    regions.push(Region { ctx, range });
                }
            }
        }
        route.risks = audit(&home, route, &regions);
    }
}

/// One imported module as the audit reads it.
struct Module {
    rel: String,
    source: Source,
    /// Where the module's own relative imports resolve.
    dir: PathBuf,
}

/// Modules read for one audited file. Each slot is filled on first use and never moved, so
/// the contexts borrowing a module stay valid while later modules are read.
#[derive(Default)]
struct ModuleSet {
    paths: RefCell<Vec<PathBuf>>,
    loaded: [OnceCell<Option<Module>>; MAX_IMPORTED_MODULES],
}

impl ModuleSet {
    /// Slot of `path`, registering it while slots remain.
    fn slot(&self, path: PathBuf) -> Option<usize> {
        let mut paths = self.paths.borrow_mut();
        if let Some(known) = paths.iter().position(|known| *known == path) {
            return Some(known);
        }
        (paths.len() < MAX_IMPORTED_MODULES).then(|| {
            paths.push(path);
            paths.len() - 1
        })
    }

    fn module(&self, slot: usize, project: &Project<'_>) -> Option<&Module> {
        self.loaded
            .get(slot)?
            .get_or_init(|| {
                let path = self.paths.borrow().get(slot)?.clone();
                let (rel, source) = project.load(&path)?;
                Some(Module {
                    rel,
                    source,
                    dir: path.parent()?.to_path_buf(),
                })
            })
            .as_ref()
    }
}

struct ModuleContext<'s> {
    ctx: FileContext<'s>,
    bindings: Vec<Binding>,
}

/// File contexts over a `ModuleSet`, built when a module is first located.
struct Contexts<'s> {
    modules: &'s ModuleSet,
    native_async: bool,
    built: [OnceCell<Option<ModuleContext<'s>>>; MAX_IMPORTED_MODULES],
}

impl<'s> Contexts<'s> {
    fn new(modules: &'s ModuleSet, native_async: bool) -> Self {
        Self {
            modules,
            native_async,
            built: Default::default(),
        }
    }

    /// The context of a module `locate` already read.
    fn get(&self, slot: usize) -> Option<&ModuleContext<'s>> {
        self.built.get(slot)?.get()?.as_ref()
    }

    fn build(&self, slot: usize, project: &Project<'_>) -> Option<&ModuleContext<'s>> {
        let modules = self.modules;
        self.built
            .get(slot)?
            .get_or_init(|| {
                let module = modules.module(slot, project)?;
                Some(ModuleContext {
                    ctx: FileContext::new(
                        &module.source,
                        Lang::Js,
                        &[],
                        Some(module.rel.clone()),
                        self.native_async,
                    ),
                    bindings: import_bindings(&module.source),
                })
            })
            .as_ref()
    }

    /// Slot and export of the module that defines what `project`'s file imports as `target`
    /// from `spec`, following re-exports and imported classes up to `MAX_HOPS` modules on.
    fn locate(
        &self,
        project: &Project<'_>,
        spec: &str,
        target: Target,
        hops: usize,
    ) -> Option<(usize, Target)> {
        let slot = self.modules.slot(project.resolve(spec)?)?;
        let module = self.build(slot, project)?;
        if module.ctx.export_region(&target).is_some() {
            return Some((slot, target));
        }
        if hops >= MAX_HOPS {
            return None;
        }
        let from = project.at(&self.modules.module(slot, project)?.dir);
        module
            .ctx
            .forward(&target, &module.bindings)
            .into_iter()
            .find_map(|(next, forwarded)| self.locate(&from, &next, forwarded, hops + 1))
    }
}

/// Where a class body or object literal sits, for member lookups.
enum Container {
    Body(Range<usize>),
    Name(String),
}

/// The transactions that cover writes in one region.
#[derive(Default)]
struct TxScope {
    /// A transactional decorator or attribute wraps the whole handler.
    whole: bool,
    /// Argument spans of transaction calls (`$transaction(...)`, `db.transaction(cb)`).
    calls: Vec<Range<usize>>,
    /// Earliest begin whose handle is not bound to a name (`client.query("BEGIN")`,
    /// `session.startTransaction()`); writes after it are taken to run inside it.
    begun: Option<usize>,
    /// Transactions begun into a binding; only writes through the binding run inside them.
    handles: Vec<TxHandle>,
}

impl TxScope {
    fn begin(&mut self, at: usize) {
        self.begun = Some(self.begun.map_or(at, |begun| begun.min(at)));
    }
}

/// `const tx = await db.begin()`: handle `tx`, begun on `db`.
struct TxHandle {
    name: String,
    /// Receiver chain of the begin, compacted (`db`, `this.pool`, `state.db`).
    conn: String,
    at: usize,
}

/// A database write, labelled for the risk detail.
struct WriteSite {
    at: usize,
    label: String,
    /// Runs on a transaction handle: its receiver, or the call it is passed to, is one, or
    /// one is among its arguments.
    handle: bool,
    /// Receiver chain of the write call, or of the call a SQL string is passed to; compacted.
    receiver: String,
    /// The call's arguments, or the rest of the statement after a SQL string.
    args: Range<usize>,
}

/// How a write stands against the transactions of its region.
enum Coverage {
    Covered,
    /// A write on the connection a bound transaction was begun on, not on its handle: it
    /// commits on its own and survives the rollback.
    Bypass {
        conn: String,
        handle: String,
    },
    Uncovered,
}

struct Loop {
    body: Range<usize>,
    kind: &'static str,
}

struct FileContext<'a> {
    source: &'a Source,
    lang: Lang,
    /// Byte offset of each line start; index 0 is line 1.
    starts: Vec<usize>,
    /// Sorted, deduplicated 1-based lines where a handler region ends.
    boundaries: Vec<usize>,
    /// Top-level and method declarations by name, for handlers referenced by name.
    declarations: Vec<(String, usize)>,
    /// Line of the module's default export, when it is a function or names one.
    default_export: Option<usize>,
    /// JavaScript class bodies (between the braces) by class name.
    classes: Vec<(String, Range<usize>)>,
    /// JavaScript object literal bodies by the binding that holds them.
    objects: Vec<(String, Range<usize>)>,
    /// `const name = new Class(...)`: binding and class as written.
    instances: Vec<(String, String)>,
    /// The default export, when it is a class, an instance or an object literal.
    default_container: Option<Container>,
    /// Rejected handler promises reach Express's error middleware without a try/catch:
    /// `express-async-errors` patches Express 4, Express 5 does it natively.
    native_async: bool,
    /// Scan-root-relative path for an imported module; `None` for the route's own file.
    origin: Option<String>,
}

impl<'a> FileContext<'a> {
    fn new(
        source: &'a Source,
        lang: Lang,
        routes: &[RawRoute],
        origin: Option<String>,
        express_native_async: bool,
    ) -> Self {
        let text = source.text.as_str();
        let mut starts = vec![0];
        starts.extend(text.match_indices('\n').map(|(at, _)| at + 1));
        let line_of = |offset: usize| starts.partition_point(|&start| start <= offset);

        let patterns: &[Regex] = match lang {
            Lang::Js => &JS_DECLARATIONS,
            Lang::Rust => &RUST_DECLARATIONS,
            Lang::Go => &GO_DECLARATIONS,
        };
        let mut boundaries: Vec<usize> = routes
            .iter()
            .filter_map(|route| usize::try_from(route.line).ok())
            .collect();
        let mut declarations = Vec::new();
        for pattern in patterns {
            for caps in pattern.captures_iter(text) {
                let Some(whole) = caps.get(0) else {
                    continue;
                };
                if source.in_string(whole.start()) {
                    continue;
                }
                let name = caps.get(1).map(|m| m.as_str());
                if name.is_some_and(|name| NOT_DECLARATIONS.contains(&name)) {
                    continue;
                }
                let line = line_of(whole.start());
                boundaries.push(line);
                if let Some(name) = name {
                    declarations.push((name.to_owned(), line));
                }
            }
        }
        boundaries.sort_unstable();
        boundaries.dedup();
        let default_export = match (lang, DEFAULT_EXPORT.as_ref()) {
            (Lang::Js, Some(re)) => re
                .captures_iter(text)
                .find(|caps| caps.get(0).is_some_and(|m| !source.in_string(m.start())))
                .and_then(|caps| match caps.get(1) {
                    Some(named) => declarations
                        .iter()
                        .find(|(declared, _)| declared == named.as_str())
                        .map(|(_, line)| *line),
                    None => caps.get(0).map(|m| line_of(m.start())),
                }),
            _ => None,
        };
        let mut context = Self {
            source,
            lang,
            starts,
            boundaries,
            declarations,
            default_export,
            classes: Vec::new(),
            objects: Vec::new(),
            instances: Vec::new(),
            default_container: None,
            native_async: express_native_async || text.contains("express-async-errors"),
            origin,
        };
        if lang == Lang::Js {
            context.classes = context.bodies(CLASS_DECL.as_ref());
            context.objects = context.bodies(OBJECT_DECL.as_ref());
            context.instances = INSTANCE_DECL.as_ref().map_or_else(Vec::new, |re| {
                re.captures_iter(text)
                    .filter(|caps| caps.get(0).is_some_and(|m| !source.in_string(m.start())))
                    .filter_map(|caps| {
                        Some((
                            caps.get(1)?.as_str().to_owned(),
                            caps.get(2)?.as_str().to_owned(),
                        ))
                    })
                    .collect()
            });
            context.default_container = context.find_default_container();
        }
        context
    }

    /// Name and brace-delimited body of each match of `re`, which ends at the body's `{`.
    fn bodies(&self, re: Option<&Regex>) -> Vec<(String, Range<usize>)> {
        let Some(re) = re else {
            return Vec::new();
        };
        let text = self.text();
        re.captures_iter(text)
            .filter_map(|caps| {
                let (whole, name) = (caps.get(0)?, caps.get(1)?);
                if self.source.in_string(whole.start()) {
                    return None;
                }
                let open = whole.end() - 1;
                let close = lex::matching_bracket(text, open, self.lang)?;
                Some((name.as_str().to_owned(), open + 1..close))
            })
            .collect()
    }

    fn find_default_container(&self) -> Option<Container> {
        let text = self.text();
        let caps = DEFAULT_CONTAINER
            .as_ref()?
            .captures_iter(text)
            .find(|caps| {
                caps.get(0)
                    .is_some_and(|m| !self.source.in_string(m.start()))
            })?;
        if let Some(class) = caps.get(1) {
            return Some(Container::Name(class.as_str().to_owned()));
        }
        if let Some(name) = caps.get(2) {
            return Some(Container::Name(name.as_str().to_owned()));
        }
        let whole = caps.get(0)?;
        let open = whole.end() - 1;
        let close = lex::matching_bracket(text, open, self.lang)?;
        Some(Container::Body(open + 1..close))
    }

    fn text(&self) -> &'a str {
        self.source.text.as_str()
    }

    fn line_of(&self, offset: usize) -> usize {
        self.starts.partition_point(|&start| start <= offset)
    }

    fn line_start(&self, offset: usize) -> usize {
        self.starts
            .get(self.line_of(offset).saturating_sub(1))
            .copied()
            .unwrap_or(0)
    }

    /// Bytes of line `line` up to the region end at the next boundary.
    fn region(&self, line: usize) -> Range<usize> {
        let start = self
            .starts
            .get(line.saturating_sub(1))
            .copied()
            .unwrap_or(0);
        let next = self
            .boundaries
            .iter()
            .copied()
            .find(|boundary| *boundary > line)
            .unwrap_or(usize::MAX)
            .min(line + MAX_REGION_LINES);
        let end = self
            .starts
            .get(next.saturating_sub(1))
            .copied()
            .unwrap_or(self.text().len());
        start..end.max(start)
    }

    fn line_text(&self, line: usize) -> &'a str {
        let start = self
            .starts
            .get(line.saturating_sub(1))
            .copied()
            .unwrap_or(0);
        let end = self.starts.get(line).copied().unwrap_or(self.text().len());
        self.text().get(start..end).unwrap_or_default()
    }

    /// Line of the declaration named `name`, other than `line` itself.
    fn defined(&self, name: &str, line: usize) -> Option<usize> {
        self.declarations
            .iter()
            .find(|(declared, at)| declared == name && *at != line)
            .map(|(_, at)| *at)
    }

    /// Region of a handler this file defines: a declaration named `reference`, or a member
    /// of a class, `new` instance or object literal this file declares (`controller.create`).
    /// A member of an import, or of an instance of an imported class, belongs to that
    /// module whatever this file declares.
    fn local_region(
        &self,
        reference: &str,
        line: usize,
        bindings: &[Binding],
    ) -> Option<Range<usize>> {
        let Some((head, member)) = reference.rsplit_once('.') else {
            return self.defined(reference, line).map(|at| self.region(at));
        };
        if let Some(range) = self
            .container_body(head)
            .and_then(|body| self.member_range(body, member))
        {
            return Some(range);
        }
        let root = head.split('.').next().unwrap_or(head);
        if bindings.iter().any(|b| b.local == root) || self.instance_class(head).is_some() {
            return None;
        }
        self.defined(member, line).map(|at| self.region(at))
    }

    /// Module and export of each handler a route takes from another file: imported names,
    /// members of instances of imported classes, and Next.js re-exports.
    fn imported_targets(
        &self,
        route: &RawRoute,
        line: usize,
        bindings: &[Binding],
    ) -> Vec<(String, Target)> {
        let mut out = Vec::new();
        for reference in self.references(route, line) {
            match reference {
                Reference::Module { spec, target } => out.push((spec, target)),
                Reference::Name(name) => {
                    if self.local_region(&name, line, bindings).is_some() {
                        continue;
                    }
                    let class_member = name.rsplit_once('.').and_then(|(head, member)| {
                        let (module, container) =
                            class_import(bindings, self.instance_class(head)?)?;
                        Some((
                            module.to_owned(),
                            Target::Member {
                                container,
                                member: member.to_owned(),
                            },
                        ))
                    });
                    if let Some(found) = class_member.or_else(|| {
                        import_target(bindings, &name)
                            .map(|(module, target)| (module.to_owned(), target))
                    }) {
                        out.push(found);
                    }
                }
            }
        }
        out
    }

    /// Region an import of `target` lands on in this module.
    fn export_region(&self, target: &Target) -> Option<Range<usize>> {
        let declared = |name: &str| {
            self.declarations
                .iter()
                .find(|(declared, _)| declared == name)
                .map(|(_, line)| self.region(*line))
        };
        match target {
            Target::Default => self.default_export.map(|line| self.region(line)),
            // `module.exports = { create: async (req, res) => ... }` names no declaration.
            Target::Named(name) => declared(name).or_else(|| self.member_of(None, name)),
            Target::Member { container, member } => self
                .member_of(container.as_deref(), member)
                .or_else(|| declared(member)),
        }
    }

    /// Region of `member` in the container this module declares as `container`, or in its
    /// default export.
    fn member_of(&self, container: Option<&str>, member: &str) -> Option<Range<usize>> {
        let body = match container {
            Some(name) => self.container_body(name)?,
            None => match self.default_container.as_ref()? {
                Container::Body(body) => body.clone(),
                Container::Name(name) => self.container_body(name)?,
            },
        };
        self.member_range(body, member)
    }

    /// Body of the class or object literal `name` declares, or of the class a `new`
    /// instance bound to `name` was built from.
    fn container_body(&self, name: &str) -> Option<Range<usize>> {
        let find = |list: &[(String, Range<usize>)], wanted: &str| {
            list.iter()
                .find(|(declared, _)| declared == wanted)
                .map(|(_, body)| body.clone())
        };
        find(&self.classes, name)
            .or_else(|| find(&self.objects, name))
            .or_else(|| find(&self.classes, self.instance_class(name)?))
    }

    fn instance_class(&self, name: &str) -> Option<&str> {
        self.instances
            .iter()
            .find(|(instance, _)| instance == name)
            .map(|(_, class)| class.as_str())
    }

    /// From the start of the member's line to the end of its function body, or of its
    /// expression for an arrow without braces. Only direct members of `body` count.
    fn member_range(&self, body: Range<usize>, member: &str) -> Option<Range<usize>> {
        let re = MEMBER_HEAD.as_ref()?;
        let text = self.text();
        let slice = text.get(body.clone())?;
        for caps in re.captures_iter(slice) {
            let Some(name) = caps.get(1) else {
                continue;
            };
            let at = body.start + name.start();
            if name.as_str() != member
                || self.source.in_string(at)
                || self.depth_between(body.start, at) != 0
            {
                continue;
            }
            if let Some(end) = self.member_end(&caps, body.start) {
                return Some(self.line_start(at)..end.min(text.len()));
            }
        }
        None
    }

    /// End of the member whose head `caps` matched in a slice starting at `offset`: past the
    /// closing brace of its body, or the end of an arrow's expression. `None` for a head that
    /// is no function after all (`value: (a + b)`, an overload signature).
    fn member_end(&self, caps: &Captures<'_>, offset: usize) -> Option<usize> {
        let text = self.text();
        if let Some(arrow) = caps.get(5) {
            return Some(self.arrow_end(offset + arrow.end()));
        }
        let arrow = caps.get(4).is_some();
        let open = caps
            .get(2)
            .or_else(|| caps.get(3))
            .or_else(|| caps.get(4))?;
        let close = lex::matching_paren(text, offset + open.start(), self.lang)?;
        let mut at = lex::skip_ws(text, close + 1);
        if text.as_bytes().get(at) == Some(&b':') {
            at = annotation_end(text, at + 1, arrow)?;
        }
        if arrow {
            return text
                .get(at..)?
                .starts_with("=>")
                .then(|| self.arrow_end(at + 2));
        }
        if text.as_bytes().get(at) != Some(&b'{') {
            return None;
        }
        Some(lex::matching_bracket(text, at, self.lang)? + 1)
    }

    /// End of an arrow function whose `=>` ends right before `from`.
    fn arrow_end(&self, from: usize) -> usize {
        let text = self.text();
        let next = lex::skip_ws(text, from);
        if text.as_bytes().get(next) == Some(&b'{') {
            if let Some(close) = lex::matching_bracket(text, next, self.lang) {
                return close + 1;
            }
        }
        statement_end(text, from, CHAIN_WINDOW)
    }

    /// Where an export this module does not define comes from, most specific first: a
    /// re-export (`export { create } from "./orders"`), an import it passes on (`import {
    /// create } from "./orders"; export { create }`), the class of an exported instance
    /// defined in another module (`export const orders = new OrdersController()`), or the
    /// `export *` modules that may hold it.
    fn forward(&self, target: &Target, bindings: &[Binding]) -> Vec<(String, Target)> {
        let mut out = Vec::new();
        match target {
            Target::Named(name) => {
                out.extend(self.reexported(name));
                if let Some((module, found)) = import_target(bindings, name) {
                    out.push((module.to_owned(), found));
                }
                out.extend(
                    self.star_exports()
                        .into_iter()
                        .map(|spec| (spec, Target::Named(name.clone()))),
                );
            }
            Target::Default => {
                out.extend(self.reexported("default"));
                if let Some(found) = self
                    .default_name()
                    .and_then(|name| import_target(bindings, &name))
                {
                    out.push((found.0.to_owned(), found.1));
                }
            }
            Target::Member { container, member } => {
                let name = match (container, self.default_container.as_ref()) {
                    (Some(name), _) => Some(name.as_str()),
                    (None, Some(Container::Name(name))) => Some(name.as_str()),
                    (None, _) => None,
                };
                if let Some(name) = name {
                    let class = self.instance_class(name).unwrap_or(name);
                    if let Some((module, class_container)) = class_import(bindings, class) {
                        out.push((
                            module.to_owned(),
                            Target::Member {
                                container: class_container,
                                member: member.clone(),
                            },
                        ));
                    }
                    if container.is_some() {
                        out.extend(self.reexported(name).into_iter().map(|(spec, inner)| {
                            let container = match inner {
                                Target::Named(original) => Some(original),
                                _ => None,
                            };
                            (
                                spec,
                                Target::Member {
                                    container,
                                    member: member.clone(),
                                },
                            )
                        }));
                    }
                }
            }
        }
        out
    }

    /// `export { x as exported } from "m"` entries for `exported`: the module and what it
    /// exports there.
    fn reexported(&self, exported: &str) -> Vec<(String, Target)> {
        let Some(re) = EXPORT_FROM.as_ref() else {
            return Vec::new();
        };
        re.captures_iter(self.text())
            .filter_map(|caps| {
                let (whole, list, spec) = (caps.get(0)?, caps.get(1)?, caps.get(2)?);
                if self.source.in_string(whole.start()) {
                    return None;
                }
                let target = match exported_as(list.as_str(), exported)? {
                    "default" => Target::Default,
                    original => Target::Named(original.to_owned()),
                };
                Some((spec.as_str().to_owned(), target))
            })
            .collect()
    }

    fn star_exports(&self) -> Vec<String> {
        let Some(re) = EXPORT_STAR.as_ref() else {
            return Vec::new();
        };
        re.captures_iter(self.text())
            .filter(|caps| {
                caps.get(0)
                    .is_some_and(|m| !self.source.in_string(m.start()))
            })
            .filter_map(|caps| caps.get(1).map(|spec| spec.as_str().to_owned()))
            .take(MAX_STAR_EXPORTS)
            .collect()
    }

    /// The binding `export default name` names, whether or not this module declares it.
    fn default_name(&self) -> Option<String> {
        DEFAULT_EXPORT
            .as_ref()?
            .captures_iter(self.text())
            .find(|caps| {
                caps.get(0)
                    .is_some_and(|m| !self.source.in_string(m.start()))
            })
            .and_then(|caps| caps.get(1))
            .map(|name| name.as_str().to_owned())
    }

    /// Bracket nesting at `to`, counted from `from`, with string literals skipped.
    fn depth_between(&self, from: usize, to: usize) -> usize {
        let bytes = self.text().as_bytes();
        let mut depth = 0usize;
        let mut at = from;
        while at < to {
            let Some(&byte) = bytes.get(at) else {
                break;
            };
            match byte {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth = depth.saturating_sub(1),
                _ => {
                    if let Some(end) = lex::literal_end(bytes, at, self.lang) {
                        at = end;
                        continue;
                    }
                }
            }
            at += 1;
        }
        depth
    }

    /// The declaration region plus the regions of handlers it names that this file
    /// defines (`post(create)`, `app.post("/x", validate(schema), create)`,
    /// `router.post("/x", controller.create)`, `export const POST = withAuth(create)`).
    fn handler_regions(&self, route: &RawRoute, bindings: &[Binding]) -> Vec<Region<'_>> {
        let line = usize::try_from(route.line).unwrap_or(0);
        let mut regions = vec![Region {
            ctx: self,
            range: self.region(line),
        }];
        for reference in self.references(route, line) {
            let Reference::Name(name) = reference else {
                continue;
            };
            if let Some(range) = self.local_region(&name, line, bindings) {
                if !regions.iter().any(|region| region.range == range) {
                    regions.push(Region { ctx: self, range });
                }
            }
        }
        regions
    }

    fn references(&self, route: &RawRoute, line: usize) -> Vec<Reference> {
        let mut references: Vec<Reference> = self
            .named_handlers(route, line)
            .into_iter()
            .map(Reference::Name)
            .collect();
        if route.source == RouteSource::NextAppRouter {
            references.extend(self.next_reference(route.method));
        }
        references
    }

    /// The handler a Next.js App Router method export stands for when it is not written in
    /// place: a re-export (`export { POST } from "m"`), an export-list entry
    /// (`export { create as POST }`), or an assigned binding (`export const POST = handler`).
    fn next_reference(&self, method: RouteMethod) -> Option<Reference> {
        let exported = method_token(method).to_ascii_uppercase();
        let text = self.text();
        let in_code = |found: &regex::Match<'_>| !self.source.in_string(found.start());
        if let Some(re) = EXPORT_FROM.as_ref() {
            for caps in re.captures_iter(text) {
                let (Some(whole), Some(list), Some(spec)) = (caps.get(0), caps.get(1), caps.get(2))
                else {
                    continue;
                };
                if !in_code(&whole) {
                    continue;
                }
                if let Some(imported) = exported_as(list.as_str(), &exported) {
                    let target = match imported {
                        "default" => Target::Default,
                        name => Target::Named(name.to_owned()),
                    };
                    return Some(Reference::Module {
                        spec: spec.as_str().to_owned(),
                        target,
                    });
                }
            }
        }
        let listed = EXPORT_LIST.as_ref().and_then(|re| {
            re.captures_iter(text).find_map(|caps| {
                let (whole, list) = (caps.get(0)?, caps.get(1)?);
                let reexport = text
                    .get(whole.end()..)
                    .is_some_and(|rest| rest.trim_start().starts_with("from"));
                if !in_code(&whole) || reexport {
                    return None;
                }
                exported_as(list.as_str(), &exported).map(str::to_owned)
            })
        });
        let assigned = |name: &str| {
            ASSIGNMENT.as_ref().and_then(|re| {
                re.captures_iter(text)
                    .filter(|caps| caps.get(0).is_some_and(|m| in_code(&m)))
                    .find(|caps| caps.get(1).is_some_and(|m| m.as_str() == name))
                    .and_then(|caps| wrapped_reference(caps.get(2)?.as_str()))
            })
        };
        match listed {
            Some(local) => Some(Reference::Name(assigned(&local).unwrap_or(local))),
            None => assigned(&exported).map(Reference::Name),
        }
    }

    /// Handler references on the declaration line, as written (`create`, `orders.create`).
    fn named_handlers(&self, route: &RawRoute, line: usize) -> Vec<String> {
        let declaration = self.line_text(line);
        let mut names = Vec::new();
        if self.lang == Lang::Rust {
            let wanted = method_token(route.method);
            if let Some(re) = AXUM_HANDLER.as_ref() {
                for caps in re.captures_iter(declaration) {
                    let (Some(method), Some(handler)) = (caps.get(1), caps.get(2)) else {
                        continue;
                    };
                    if method.as_str() == wanted || method.as_str() == "any" {
                        names.push(last_segment(handler.as_str(), "::").to_owned());
                    }
                }
            }
            return names;
        }
        // Call arguments after the path literal that are bare identifiers.
        let Some(re) = IDENTIFIER.as_ref() else {
            return names;
        };
        let bytes = declaration.as_bytes();
        let after_path = declaration
            .find(['"', '\'', '`'])
            .and_then(|open| lex::literal_end(bytes, open, self.lang))
            .unwrap_or(0);
        for found in re.find_iter(declaration.get(after_path..).unwrap_or_default()) {
            let start = after_path + found.start();
            let end = after_path + found.end();
            let before = declaration[..start].trim_end().as_bytes().last().copied();
            let after = declaration[end..].trim_start().as_bytes().first().copied();
            if matches!(before, Some(b',')) && matches!(after, Some(b',' | b')')) {
                let name = last_segment(found.as_str(), ".");
                if !matches!(
                    name,
                    "req" | "res" | "next" | "true" | "false" | "null" | "undefined"
                ) {
                    names.push(found.as_str().to_owned());
                }
            }
            if names.len() >= MAX_NAMED_HANDLERS {
                return names;
            }
        }
        if let Some(wrapped) = WRAPPED_HANDLER.as_ref() {
            for caps in wrapped.captures_iter(declaration) {
                if let Some(name) = caps.get(1).map(|m| m.as_str().to_owned()) {
                    if names.len() < MAX_NAMED_HANDLERS && !names.contains(&name) {
                        names.push(name);
                    }
                }
            }
        }
        names
    }

    fn risk(&self, kind: RouteRiskKind, offset: usize, detail: String) -> RouteRisk {
        let line = self.line_of(offset);
        let text = self.line_text(line).trim();
        let evidence = match text.char_indices().nth(EVIDENCE_CHARS) {
            Some((cut, _)) => format!("{}...", &text[..cut]),
            None => text.to_owned(),
        };
        RouteRisk {
            kind,
            line: u32::try_from(line).unwrap_or(u32::MAX),
            evidence,
            detail,
            file: self.origin.clone(),
        }
    }

    /// End of the statement holding `at`: the next line break in Go, which has no `;`,
    /// otherwise the next `;`, blank line or `CHAIN_WINDOW` bytes.
    fn statement_end(&self, at: usize) -> usize {
        let text = self.text();
        match self.lang {
            Lang::Go => text
                .get(at..)
                .and_then(|tail| tail.find('\n'))
                .map_or(text.len(), |offset| at + offset),
            Lang::Js | Lang::Rust => statement_end(text, at, CHAIN_WINDOW),
        }
    }

    /// `await` immediately before the receiver at `at`.
    fn awaited(&self, at: usize) -> bool {
        let before = self
            .text()
            .get(self.line_start(at)..at)
            .unwrap_or_default()
            .trim_end();
        before.strip_suffix("await").is_some_and(|rest| {
            !rest
                .as_bytes()
                .last()
                .is_some_and(|byte| lex::is_ident_byte(*byte))
        })
    }

    /// Database writes in `range`, one per statement, in source order, labelled for the
    /// risk detail. A SQL string inside a write call's arguments, or in the same statement
    /// (`query("UPDATE ...").execute(db)`), is that call's write, not a second one.
    fn write_sites(&self, range: Range<usize>) -> Vec<WriteSite> {
        let text = self.text();
        let Some(slice) = text.get(range.clone()) else {
            return Vec::new();
        };
        // (start, closing paren, statement end)
        let mut calls: Vec<(usize, usize, usize)> = Vec::new();
        let mut sites: Vec<WriteSite> = Vec::new();
        if let Some(re) = WRITE_CALL.as_ref() {
            for caps in re.captures_iter(slice) {
                let (Some(whole), Some(receiver), Some(method)) =
                    (caps.get(0), caps.get(1), caps.get(2))
                else {
                    continue;
                };
                let at = range.start + whole.start();
                if self.source.in_string(at) {
                    continue;
                }
                let end = self.statement_end(at);
                let receiver = compact(receiver.as_str());
                let method = method.as_str();
                let write = match method {
                    "execute" | "Exec" | "ExecContext" => !self.statement_reads(at, end),
                    _ if method.starts_with(|c: char| c.is_ascii_uppercase()) => {
                        !GO_NON_DB.contains(&root_segment(&receiver))
                    }
                    _ => is_db_receiver(&receiver, self.awaited(at)),
                };
                if !write {
                    continue;
                }
                let open = range.start + whole.end() - 1;
                let close = lex::matching_paren(text, open, self.lang).unwrap_or(open);
                calls.push((at, close, end));
                // A generic executor is named by the statement it runs.
                let label = match method {
                    "execute" | "Exec" | "ExecContext" => self.sql_label(at, end),
                    _ => None,
                }
                .unwrap_or_else(|| format!("{receiver}.{method}"));
                let handle = TX_ROOTS.contains(&root_segment(&receiver))
                    || TX_HANDLE.as_ref().is_some_and(|re| {
                        re.is_match(text.get(open + 1..close).unwrap_or_default())
                    });
                sites.push(WriteSite {
                    at,
                    label,
                    handle,
                    receiver,
                    args: open + 1..close,
                });
            }
        }
        if let Some(sql) = SQL_WRITE.as_ref() {
            for (start, end) in self.source.strings_in(range) {
                let Some(found) = text.get(start..end).and_then(|literal| sql.find(literal)) else {
                    continue;
                };
                let statement = self.statement_end(start);
                let merged = calls
                    .iter()
                    .any(|&(at, close, end)| (at < start && start < close) || end == statement);
                if !merged {
                    let before = text.get(self.line_start(start)..start).unwrap_or_default();
                    let after = text.get(end..statement).unwrap_or_default();
                    let handle = TX_RECEIVER.as_ref().is_some_and(|re| re.is_match(before))
                        || TX_HANDLE.as_ref().is_some_and(|re| re.is_match(after));
                    sites.push(WriteSite {
                        at: start,
                        label: sql_keywords(found.as_str()),
                        handle,
                        receiver: called_receiver(before),
                        args: end..statement.max(end),
                    });
                }
            }
        }
        sites.sort_by_key(|site| site.at);
        sites
    }

    /// The SQL write the statement around `at` runs, as `UPDATE STOCK SET`.
    fn sql_label(&self, at: usize, end: usize) -> Option<String> {
        let statement = self.text().get(self.line_start(at)..end)?;
        let found = SQL_WRITE.as_ref()?.find(statement)?;
        Some(sql_keywords(found.as_str()))
    }

    /// The statement around a call names a SELECT: `conn.execute("SELECT ...")` reads.
    fn statement_reads(&self, at: usize, end: usize) -> bool {
        let statement = self
            .text()
            .get(self.line_start(at)..end)
            .unwrap_or_default();
        SQL_SELECT.as_ref().is_some_and(|re| re.is_match(statement))
    }

    /// Transactions in `range`: transaction calls cover their arguments, a handle-style begin
    /// covers what follows it, and a decorator on the handler (up to three lines above the
    /// region) covers everything.
    fn tx_scope(&self, range: Range<usize>) -> TxScope {
        let text = self.text();
        let mut scope = TxScope::default();
        let above = self
            .starts
            .get(self.line_of(range.start).saturating_sub(4))
            .copied()
            .unwrap_or(0);
        scope.whole = TX_DECORATOR.as_ref().is_some_and(|re| {
            re.find_iter(text.get(above..range.end).unwrap_or_default())
                .any(|found| !self.source.in_string(above + found.start()))
        });
        let Some(slice) = text.get(range.clone()) else {
            return scope;
        };
        let bound = match self.lang {
            Lang::Go => GO_TX_BOUND.as_ref(),
            Lang::Js | Lang::Rust => TX_BOUND.as_ref(),
        };
        // Begin calls that produced a named handle; the generic passes below skip them.
        let mut bound_calls: Vec<usize> = Vec::new();
        for caps in bound.into_iter().flat_map(|re| re.captures_iter(slice)) {
            let (Some(whole), Some(name), Some(conn), Some(call)) =
                (caps.get(0), caps.get(1), caps.get(2), caps.get(3))
            else {
                continue;
            };
            if self.source.in_string(range.start + whole.start()) {
                continue;
            }
            // `transaction(cb)` scopes its callback; only an argument-less call returns one.
            if call.as_str() == "transaction" {
                let open = range.start + whole.end() - 1;
                let empty = lex::matching_paren(text, open, self.lang)
                    .and_then(|close| text.get(open + 1..close))
                    .is_some_and(|args| args.trim().is_empty());
                if !empty {
                    continue;
                }
            }
            let at = range.start + call.start();
            bound_calls.push(at);
            scope.handles.push(TxHandle {
                name: name.as_str().to_owned(),
                conn: compact(conn.as_str()),
                at,
            });
        }
        if let Some(re) = TX_CALL.as_ref() {
            for found in re.find_iter(slice) {
                let at = range.start + found.start();
                if self.source.in_string(at) || bound_calls.contains(&at) {
                    continue;
                }
                let open = range.start + found.end() - 1;
                let Some(close) = lex::matching_paren(text, open, self.lang) else {
                    continue;
                };
                if text
                    .get(open + 1..close)
                    .is_some_and(|args| args.trim().is_empty())
                {
                    // `sequelize.transaction()` returns a handle for the writes after it.
                    scope.begin(at);
                } else {
                    scope.calls.push(open..close);
                }
            }
        }
        if let Some(re) = TX_BEGIN.as_ref() {
            for found in re.find_iter(slice) {
                let at = range.start + found.start();
                if !self.source.in_string(at) && !bound_calls.contains(&at) {
                    scope.begin(at);
                }
            }
        }
        if let Some(re) = SQL_TX.as_ref() {
            for (start, end) in self.source.strings_in(range) {
                if text.get(start..end).is_some_and(|lit| re.is_match(lit)) {
                    scope.begin(start);
                }
            }
        }
        scope
    }

    /// The write runs under a transactional decorator, inside a transaction call, on a
    /// transaction handle, or after an unbound begin. After a bound begin only writes
    /// through its handle count; one still on the connection it was begun on bypasses it.
    fn coverage(&self, scope: &TxScope, site: &WriteSite) -> Coverage {
        if scope.whole || site.handle || scope.calls.iter().any(|call| call.contains(&site.at)) {
            return Coverage::Covered;
        }
        let innermost = scope
            .handles
            .iter()
            .filter(|handle| handle.at < site.at)
            .max_by_key(|handle| handle.at);
        if let Some(handle) = innermost {
            return if self.writes_through(site, &handle.name) {
                Coverage::Covered
            } else if self.writes_through(site, &handle.conn) {
                Coverage::Bypass {
                    conn: handle.conn.clone(),
                    handle: handle.name.clone(),
                }
            } else {
                Coverage::Uncovered
            };
        }
        if scope.begun.is_some_and(|begun| begun < site.at) {
            Coverage::Covered
        } else {
            Coverage::Uncovered
        }
    }

    /// The write's receiver chain is, or starts with, `chain`, or its arguments name it
    /// (`.execute(&db)`, `{ transaction: t }`).
    fn writes_through(&self, site: &WriteSite, chain: &str) -> bool {
        let receiver = site.receiver.as_str();
        receiver == chain
            || receiver
                .strip_prefix(chain)
                .is_some_and(|rest| rest.starts_with('.'))
            || mentions(
                self.text().get(site.args.clone()).unwrap_or_default(),
                chain,
            )
    }

    /// Loop bodies in `range`: `for` / `while` / `do` blocks (or single statements) and the
    /// callbacks of `forEach` / `map` / `flatMap` / `for_each`.
    fn loops(&self, range: Range<usize>) -> Vec<Loop> {
        let re = match self.lang {
            Lang::Js => JS_LOOP.as_ref(),
            Lang::Rust => RUST_LOOP.as_ref(),
            Lang::Go => GO_LOOP.as_ref(),
        };
        let (Some(re), Some(slice)) = (re, self.text().get(range.clone())) else {
            return Vec::new();
        };
        let text = self.text();
        let mut loops = Vec::new();
        for caps in re.captures_iter(slice) {
            let (Some(whole), Some(keyword)) = (caps.get(0), caps.iter().skip(1).flatten().next())
            else {
                continue;
            };
            let at = range.start + whole.start();
            if self.source.in_string(at) {
                continue;
            }
            let last = range.start + whole.end() - 1;
            let body = match text.as_bytes().get(last) {
                Some(b'{') => {
                    lex::matching_bracket(text, last, self.lang).map(|close| last + 1..close)
                }
                // A callback loop runs its argument; a condition loop runs what follows it.
                Some(b'(') => lex::matching_paren(text, last, self.lang).and_then(|close| {
                    if matches!(
                        keyword.as_str(),
                        "forEach" | "map" | "flatMap" | "for_each" | "try_for_each"
                    ) {
                        return Some(last + 1..close);
                    }
                    let next = lex::skip_ws(text, close + 1);
                    match text.as_bytes().get(next) {
                        Some(b'{') => {
                            lex::matching_bracket(text, next, self.lang).map(|end| next + 1..end)
                        }
                        Some(_) => Some(next..statement_end(text, next, CHAIN_WINDOW)),
                        None => None,
                    }
                }),
                _ => None,
            };
            if let Some(body) = body {
                loops.push(Loop {
                    body,
                    kind: loop_kind(keyword.as_str()),
                });
            }
        }
        loops
    }

    /// Argument spans of `spawn_blocking(...)` / `block_in_place(...)` calls in `range`.
    fn offloaded(&self, range: Range<usize>) -> Vec<Range<usize>> {
        let (Some(re), Some(slice)) = (OFFLOADED.as_ref(), self.text().get(range.clone())) else {
            return Vec::new();
        };
        re.find_iter(slice)
            .filter_map(|found| {
                let open = range.start + found.end() - 1;
                let close = lex::matching_paren(self.text(), open, self.lang)?;
                Some(open..close)
            })
            .collect()
    }

    /// First string literal in `range` that holds a SQL statement built from values.
    fn interpolated_sql(&self, range: Range<usize>) -> Option<(usize, &'static str)> {
        let shape = SQL_SHAPE.as_ref()?;
        let text = self.text();
        for (start, end) in self.source.strings_in(range) {
            let Some(literal) = text.get(start..end) else {
                continue;
            };
            if !shape.is_match(literal) {
                continue;
            }
            let quote = literal.as_bytes().first().copied();
            let detail = match (self.lang, quote) {
                (Lang::Js, Some(b'`')) if literal.contains("${") && !self.tagged(start) => {
                    "SQL assembled in a template literal with ${...} interpolation; pass values as bound parameters or use a tagged sql template"
                }
                (Lang::Js, Some(b'\'' | b'"')) | (Lang::Go, Some(b'"' | b'`'))
                    if self.concatenated(end) =>
                {
                    "SQL assembled by string concatenation; pass values as bound parameters"
                }
                (Lang::Rust, _) if self.called_by(start, "format!") && has_placeholder(literal) => {
                    "SQL assembled with format!; bind values with .bind() instead"
                }
                (Lang::Go, Some(b'"' | b'`'))
                    if self.called_by(start, "Sprintf") && literal.contains('%') =>
                {
                    "SQL assembled with fmt.Sprintf; pass values as query arguments"
                }
                _ => continue,
            };
            return Some((start, detail));
        }
        None
    }

    /// A tag (`sql`, `Prisma.sql`, `db.sql(...)`) receives template values as parameters.
    fn tagged(&self, start: usize) -> bool {
        let before = self.text().get(..start).unwrap_or_default().trim_end();
        match before.as_bytes().last() {
            Some(b')' | b']') => true,
            Some(byte) if lex::is_ident_byte(*byte) => {
                let word_start = before
                    .bytes()
                    .rposition(|b| !lex::is_ident_byte(b))
                    .map_or(0, |at| at + 1);
                !TEMPLATE_PRECEDERS.contains(&before.get(word_start..).unwrap_or_default())
            }
            _ => false,
        }
    }

    /// The literal ending at `end` is followed by `+` and an expression.
    fn concatenated(&self, end: usize) -> bool {
        let after = self.text().get(end..).unwrap_or_default().trim_start();
        after.strip_prefix('+').is_some_and(|rest| {
            rest.trim_start()
                .starts_with(|c: char| c.is_ascii_alphabetic() || matches!(c, '_' | '$' | '('))
        })
    }

    /// The literal opening at `start` is the first argument of `callee(`.
    fn called_by(&self, start: usize, callee: &str) -> bool {
        self.text()
            .get(..start)
            .unwrap_or_default()
            .trim_end()
            .strip_suffix('(')
            .is_some_and(|before| before.trim_end().ends_with(callee))
    }
}

/// A slice of one file's source that belongs to a route's handler.
struct Region<'c> {
    ctx: &'c FileContext<'c>,
    range: Range<usize>,
}

impl<'c> Region<'c> {
    fn text(&self) -> &'c str {
        self.ctx.text().get(self.range.clone()).unwrap_or_default()
    }

    /// First code (not string) match of `re`.
    fn first_code_match(&self, re: &Regex) -> Option<usize> {
        re.find_iter(self.text())
            .map(|found| self.range.start + found.start())
            .find(|at| !self.ctx.source.in_string(*at))
    }

    /// First match of `re` in code, counting the `${...}` expressions of JavaScript template
    /// literals as code: `` `order ${req.body.id}` `` reads the body as much as a statement.
    fn first_expression_match(&self, re: &Regex) -> Option<usize> {
        let source = self.ctx.source;
        let templates = self.ctx.lang == Lang::Js;
        re.find_iter(self.text())
            .map(|found| self.range.start + found.start())
            .find(|at| !source.in_string(*at) || (templates && source.in_interpolation(*at)))
    }
}

fn audit(home: &FileContext<'_>, route: &RawRoute, regions: &[Region<'_>]) -> Vec<RouteRisk> {
    let mut risks = Vec::new();
    risks.extend(unvalidated_mutation(route, regions));
    risks.extend(unbounded_query(regions));
    risks.extend(floating_async(home, route, regions));
    risks.extend(non_atomic_writes(regions));
    risks.extend(unsafe_sql(regions));
    risks.extend(blocking_in_async(regions));
    risks
}

fn unvalidated_mutation(route: &RawRoute, regions: &[Region<'_>]) -> Option<RouteRisk> {
    if !matches!(
        route.method,
        RouteMethod::Post | RouteMethod::Put | RouteMethod::Patch | RouteMethod::Delete
    ) {
        return None;
    }
    let (region, read) = regions.iter().find_map(|region| {
        let pattern = match region.ctx.lang {
            Lang::Js => JS_BODY_READ.as_ref(),
            Lang::Rust => RUST_BODY_READ.as_ref(),
            Lang::Go => GO_BODY_READ.as_ref(),
        }?;
        region
            .first_expression_match(pattern)
            .map(|at| (region, at))
    })?;
    if validated(regions) {
        return None;
    }
    Some(region.ctx.risk(
        RouteRiskKind::UnvalidatedMutation,
        read,
        format!(
            "{} handler reads the request body with no schema validation in the handler or its middleware",
            method_token(route.method).to_ascii_uppercase()
        ),
    ))
}

fn validated(regions: &[Region<'_>]) -> bool {
    regions.iter().any(|region| {
        let slice = region.text();
        match region.ctx.lang {
            Lang::Js => {
                JS_VALIDATOR.as_ref().is_some_and(|re| re.is_match(slice))
                    || PARSE_CALL.as_ref().is_some_and(|re| {
                        re.captures_iter(slice).any(|caps| {
                            caps.get(1).is_some_and(|receiver| {
                                !NON_SCHEMA_PARSERS.contains(&receiver.as_str())
                            })
                        })
                    })
            }
            Lang::Rust => {
                RUST_VALIDATOR.as_ref().is_some_and(|re| re.is_match(slice))
                    || RUST_TYPED.as_ref().is_some_and(|re| {
                        re.captures_iter(slice).any(|caps| {
                            caps.get(1).or_else(|| caps.get(2)).is_some_and(|ty| {
                                !UNTYPED_RUST.contains(&last_segment(ty.as_str(), "::"))
                            })
                        })
                    })
            }
            Lang::Go => GO_VALIDATOR.as_ref().is_some_and(|re| re.is_match(slice)),
        }
    })
}

fn unbounded_query(regions: &[Region<'_>]) -> Option<RouteRisk> {
    for region in regions {
        let ctx = region.ctx;
        let text = ctx.text();
        let slice = region.text();
        if let Some(re) = ORM_COLLECTION.as_ref() {
            for caps in re.captures_iter(slice) {
                let (Some(whole), Some(name)) = (caps.get(0), caps.get(1)) else {
                    continue;
                };
                let at = region.range.start + whole.start();
                let open = region.range.start + whole.end() - 1;
                if ctx.source.in_string(at) {
                    continue;
                }
                let Some(close) = lex::matching_paren(text, open, ctx.lang) else {
                    continue;
                };
                let args = &text[open + 1..close];
                // `.find(` is Array.prototype.find unless it takes a query object or
                // nothing; GORM's `Find` takes a destination pointer.
                let trimmed = args.trim_start();
                match name.as_str() {
                    "find" if !(trimmed.is_empty() || trimmed.starts_with('{')) => continue,
                    "Find" if !trimmed.starts_with('&') => continue,
                    _ => {}
                }
                let chain_start = ctx.line_start(at);
                let chain_end = statement_end(text, close, CHAIN_WINDOW);
                let bounded = ORM_BOUND.as_ref().is_some_and(|bound| {
                    bound.is_match(args) || bound.is_match(&text[chain_start..chain_end])
                });
                if !bounded {
                    return Some(ctx.risk(
                        RouteRiskKind::UnboundedQuery,
                        at,
                        format!(
                            "`{}` reads a collection with no limit or pagination",
                            name.as_str()
                        ),
                    ));
                }
            }
        }
        if let (Some(select), Some(from), Some(bound)) =
            (SQL_SELECT.as_ref(), SQL_FROM.as_ref(), SQL_BOUND.as_ref())
        {
            for found in select.find_iter(slice) {
                let at = region.range.start + found.start();
                let Some((_, end)) = ctx.source.string_span(at) else {
                    continue;
                };
                let statement = &text[at..end];
                if from.is_match(statement) && !bound.is_match(statement) {
                    return Some(ctx.risk(
                        RouteRiskKind::UnboundedQuery,
                        at,
                        "SELECT without LIMIT, aggregate or key lookup returns every matching row"
                            .to_owned(),
                    ));
                }
            }
        }
    }
    None
}

fn floating_async(
    home: &FileContext<'_>,
    route: &RawRoute,
    regions: &[Region<'_>],
) -> Option<RouteRisk> {
    match home.lang {
        Lang::Js => floating_promise(regions).or_else(|| unguarded_express(home, route, regions)),
        Lang::Go => {
            let re = GO_DROPPED.as_ref()?;
            regions.iter().find_map(|region| {
                let at = region.first_code_match(re)?;
                Some(region.ctx.risk(
                    RouteRiskKind::FloatingAsync,
                    at,
                    "database call whose error is never checked".to_owned(),
                ))
            })
        }
        // Unused futures and Results are compiler warnings in Rust (`#[must_use]`).
        Lang::Rust => None,
    }
}

fn floating_promise(regions: &[Region<'_>]) -> Option<RouteRisk> {
    let re = JS_FLOATING.as_ref()?;
    for region in regions {
        let ctx = region.ctx;
        let text = ctx.text();
        for caps in re.captures_iter(region.text()) {
            let Some(whole) = caps.get(0) else {
                continue;
            };
            let at = region.range.start + whole.start() + whole.as_str().len()
                - whole.as_str().trim_start().len();
            if ctx.source.in_string(at) {
                continue;
            }
            let receiver = compact(
                caps.get(1)
                    .or_else(|| caps.get(3))
                    .map_or("", |m| m.as_str()),
            );
            let method = caps
                .get(2)
                .or_else(|| caps.get(4))
                .map_or("", |m| m.as_str());
            let io = method == "save" || method == "fetch" || is_db_receiver(&receiver, false);
            if !io {
                continue;
            }
            let call_end = region.range.start + whole.end();
            let end = statement_end(text, call_end, CHAIN_WINDOW);
            let tail = &text[call_end..end];
            if tail.contains(".then(") || tail.contains(".catch(") {
                continue;
            }
            let call = if receiver.is_empty() {
                method.to_owned()
            } else {
                format!("{receiver}.{method}")
            };
            return Some(ctx.risk(
                RouteRiskKind::FloatingAsync,
                at,
                format!("`{call}(...)` is neither awaited nor returned; its failure is lost and the response can precede the write"),
            ));
        }
    }
    None
}

fn unguarded_express(
    home: &FileContext<'_>,
    route: &RawRoute,
    regions: &[Region<'_>],
) -> Option<RouteRisk> {
    if route.source != RouteSource::Express || home.native_async {
        return None;
    }
    let declaration = home.line_text(usize::try_from(route.line).unwrap_or(0));
    if ASYNC_WRAPPERS
        .iter()
        .any(|wrapper| declaration.contains(wrapper))
    {
        return None;
    }
    let (awaits, guarded) = (AWAIT.as_ref()?, ERROR_PATH.as_ref()?);
    regions.iter().find_map(|region| {
        let slice = region.text();
        let head = slice.lines().next().unwrap_or_default();
        let asynchronous = head.contains("async");
        (asynchronous && awaits.is_match(slice) && !guarded.is_match(slice)).then(|| {
            region.ctx.risk(
                RouteRiskKind::FloatingAsync,
                region.range.start,
                "async Express handler awaits with no try/catch or next(err); Express 4 leaves the rejection unhandled and the request hanging".to_owned(),
            )
        })
    })
}

/// A write found in one of a route's regions, with what guards it.
struct Write<'r> {
    region: &'r Region<'r>,
    site: WriteSite,
    coverage: Coverage,
    in_loop: Option<&'static str>,
}

/// Writes that a failure or a concurrent request can leave half-applied: a write that
/// bypasses a transaction handle begun in the same handler, one write repeated by a loop,
/// or two or more writes of which at least one runs outside every transaction. A
/// transaction counts only for the writes it covers, not for the whole handler.
fn non_atomic_writes(regions: &[Region<'_>]) -> Option<RouteRisk> {
    let mut writes: Vec<Write<'_>> = Vec::new();
    for region in regions {
        let ctx = region.ctx;
        let scope = ctx.tx_scope(region.range.clone());
        let loops = ctx.loops(region.range.clone());
        for site in ctx.write_sites(region.range.clone()) {
            let duplicate = writes
                .iter()
                .any(|w| std::ptr::eq(w.region.ctx, ctx) && w.site.at == site.at);
            if duplicate {
                continue;
            }
            writes.push(Write {
                region,
                coverage: ctx.coverage(&scope, &site),
                in_loop: loops
                    .iter()
                    .find(|l| l.body.contains(&site.at))
                    .map(|l| l.kind),
                site,
            });
        }
    }
    let uncovered: Vec<&Write<'_>> = writes
        .iter()
        .filter(|w| !matches!(w.coverage, Coverage::Covered))
        .collect();
    // A bypass is a defect even as the only write: the transaction around it is a no-op.
    for write in &uncovered {
        if let Coverage::Bypass { conn, handle } = &write.coverage {
            return Some(write.region.ctx.risk(
                RouteRiskKind::NonAtomicMultiWrite,
                write.site.at,
                format!(
                    "write on '{conn}' bypasses active transaction handle '{handle}': `{}` commits on its own and survives a rollback",
                    write.site.label
                ),
            ));
        }
    }
    if let Some(write) = uncovered.iter().find(|w| w.in_loop.is_some()) {
        return Some(write.region.ctx.risk(
            RouteRiskKind::NonAtomicMultiWrite,
            write.site.at,
            format!(
                "`{}` runs once per iteration of a `{}` loop with no transaction around it; a failure or a concurrent request mid-loop leaves partial state",
                write.site.label,
                write.in_loop.unwrap_or("for")
            ),
        ));
    }
    let first = uncovered.first()?;
    if writes.len() < 2 {
        return None;
    }
    let listed = |set: &[&Write<'_>]| {
        let mut labels: Vec<String> = set
            .iter()
            .take(LISTED_WRITES)
            .map(|w| format!("`{}`", w.site.label))
            .collect();
        if set.len() > LISTED_WRITES {
            labels.push("...".to_owned());
        }
        labels.join(", ")
    };
    let detail = if uncovered.len() == writes.len() {
        let all: Vec<&Write<'_>> = writes.iter().collect();
        format!(
            "{} writes ({}) with no transaction around them; a failure or a concurrent request between them leaves partial state",
            writes.len(),
            listed(&all)
        )
    } else {
        format!(
            "{} writes, {} of them outside the transaction ({}); a failure after it commits leaves partial state",
            writes.len(),
            uncovered.len(),
            listed(&uncovered)
        )
    };
    Some(
        first
            .region
            .ctx
            .risk(RouteRiskKind::NonAtomicMultiWrite, first.site.at, detail),
    )
}

fn unsafe_sql(regions: &[Region<'_>]) -> Option<RouteRisk> {
    regions.iter().find_map(|region| {
        let (at, detail) = region.ctx.interpolated_sql(region.range.clone())?;
        Some(
            region
                .ctx
                .risk(RouteRiskKind::UnsafeSqlInterpolation, at, detail.to_owned()),
        )
    })
}

/// A blocking call inside a handler body: any JavaScript handler, which runs on the event
/// loop whether or not it is declared `async`, or an `async fn` Rust handler, which runs on
/// a runtime worker. Calls in module scope after a route (startup reads) and calls handed to
/// `spawn_blocking` / `block_in_place` are not findings.
fn blocking_in_async(regions: &[Region<'_>]) -> Option<RouteRisk> {
    regions.iter().find_map(|region| {
        let ctx = region.ctx;
        let re = match ctx.lang {
            Lang::Js => JS_BLOCKING.as_ref()?,
            Lang::Rust if region.text().lines().next()?.contains("async") => {
                RUST_BLOCKING.as_ref()?
            }
            Lang::Rust | Lang::Go => return None,
        };
        let offloaded = ctx.offloaded(region.range.clone());
        re.captures_iter(region.text()).find_map(|caps| {
            let call = caps.get(1)?;
            let at = region.range.start + call.start();
            if ctx.source.in_string(at)
                || ctx.depth_between(region.range.start, at) == 0
                || offloaded.iter().any(|span| span.contains(&at))
            {
                return None;
            }
            let call = call.as_str();
            let detail = match ctx.lang {
                Lang::Js => format!(
                    "`{call}` blocks the event loop inside a request handler, so every concurrent request waits behind it; {}",
                    js_blocking_advice(call)
                ),
                Lang::Rust | Lang::Go => format!(
                    "`{call}` blocks a runtime worker thread inside an async handler, stalling every task scheduled on it; {}",
                    rust_blocking_advice(call)
                ),
            };
            Some(ctx.risk(RouteRiskKind::BlockingInAsync, at, detail))
        })
    })
}

fn js_blocking_advice(call: &str) -> &'static str {
    match call {
        "execSync" | "execFileSync" | "spawnSync" => {
            "run the child process through the callback or promise API"
        }
        "pbkdf2Sync" | "scryptSync" => "use crypto.pbkdf2 / crypto.scrypt with a callback",
        "hashSync" | "compareSync" | "genSaltSync" => "use the async bcrypt hash / compare",
        _ => "use fs/promises",
    }
}

fn rust_blocking_advice(call: &str) -> &'static str {
    if call.ends_with("sleep") {
        "use tokio::time::sleep"
    } else if call.starts_with("bcrypt") {
        "hash inside tokio::task::spawn_blocking"
    } else {
        "use tokio::fs or tokio::task::spawn_blocking"
    }
}

/// `chain` occurs in `text` as a whole identifier path: not inside a longer name, not as a
/// property of another value (`req.body.db`).
fn mentions(text: &str, chain: &str) -> bool {
    !chain.is_empty()
        && text.match_indices(chain).any(|(at, _)| {
            let before = text.get(..at).and_then(|head| head.bytes().next_back());
            let after = text.as_bytes().get(at + chain.len()).copied();
            !before.is_some_and(|b| lex::is_ident_byte(b) || b == b'.')
                && !after.is_some_and(lex::is_ident_byte)
        })
}

/// Receiver chain of the call a literal is the first argument of: `await db.query(` gives
/// `db.query`. Empty when the literal is not a call argument.
fn called_receiver(before: &str) -> String {
    let Some(call) = before.trim_end().strip_suffix('(') else {
        return String::new();
    };
    let call = call.trim_end();
    let start = call
        .bytes()
        .rposition(|b| !(lex::is_ident_byte(b) || matches!(b, b'.' | b'$')))
        .map_or(0, |at| at + 1);
    compact(call.get(start..).unwrap_or_default())
}

/// `receiver` can hold a database handle: a known client name, a model chain
/// (`prisma.order`), a capitalized model (`Order`), or anything awaited. Chains through
/// request, response or in-memory state never qualify.
fn is_db_receiver(receiver: &str, awaited: bool) -> bool {
    let chain = receiver.trim_start_matches("this.");
    let segments: Vec<&str> = chain.split('.').collect();
    let root = segments.first().copied().unwrap_or_default();
    // A client root wins over a state-like model name: `prisma.session` is a table.
    if IO_RECEIVERS.contains(&root) {
        return true;
    }
    if segments
        .iter()
        .any(|segment| NON_DB_SEGMENTS.contains(segment))
    {
        return false;
    }
    let model =
        root.starts_with(|c: char| c.is_ascii_uppercase()) && !GLOBAL_OBJECTS.contains(&root);
    segments.len() >= 2 || model || awaited
}

/// A receiver chain written across lines (`prisma.order` / `  .create`) as one chain.
fn compact(receiver: &str) -> String {
    receiver.split_whitespace().collect()
}

/// `update  stock\n set` as `UPDATE STOCK SET`.
fn sql_keywords(found: &str) -> String {
    found
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase()
}

fn loop_kind(keyword: &str) -> &'static str {
    match keyword {
        "while" => "while",
        "do" => "do",
        "loop" => "loop",
        "forEach" => "forEach",
        "map" => "map",
        "flatMap" => "flatMap",
        "for_each" => "for_each",
        "try_for_each" => "try_for_each",
        keyword if keyword.ends_with("await") => "for await",
        _ => "for",
    }
}

fn root_segment(receiver: &str) -> &str {
    receiver
        .trim_start_matches("this.")
        .split('.')
        .next()
        .unwrap_or_default()
}

/// Where a TypeScript return type annotation starting at `from` ends: at the body's `{` of a
/// method, or at the `=>` of an arrow. Brackets inside the type (`Promise<{ id: string }>`,
/// `(x: number) => void`) are skipped; a `;` first means a signature without a body.
fn annotation_end(text: &str, from: usize, arrow: bool) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut at = from;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'(' | b'<' | b'[' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            b'>' if at > 0 && bytes.get(at - 1) != Some(&b'=') => depth = depth.saturating_sub(1),
            b'=' if arrow && depth == 0 && bytes.get(at + 1) == Some(&b'>') => return Some(at),
            b'{' if depth == 0 && !arrow => return Some(at),
            b'{' => {
                at = lex::matching_bracket(text, at, Lang::Js)? + 1;
                continue;
            }
            b';' if depth == 0 => return None,
            _ => {}
        }
        at += 1;
    }
    None
}

/// A `format!` string with at least one `{}` / `{name}` placeholder.
fn has_placeholder(literal: &str) -> bool {
    literal.replace("{{", "").replace("}}", "").contains('{')
}

/// End of the statement starting before `from`: the next `;`, a blank line, or `window` bytes.
fn statement_end(text: &str, from: usize, window: usize) -> usize {
    let limit = (from + window).min(text.len());
    let tail = text.get(from..limit).unwrap_or_default();
    let end = [tail.find(';'), tail.find("\n\n"), tail.find("\r\n\r\n")]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(tail.len());
    from + end
}

fn last_segment<'s>(path: &'s str, separator: &str) -> &'s str {
    path.rsplit(separator).next().unwrap_or(path)
}

fn method_token(method: RouteMethod) -> &'static str {
    match method {
        RouteMethod::Get => "get",
        RouteMethod::Post => "post",
        RouteMethod::Put => "put",
        RouteMethod::Patch => "patch",
        RouteMethod::Delete => "delete",
        RouteMethod::Head => "head",
        RouteMethod::Options => "options",
        RouteMethod::Any => "any",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::{axum, go, next, node};
    use super::*;

    fn patterns_compile() -> bool {
        [
            &AXUM_HANDLER,
            &IDENTIFIER,
            &WRAPPED_HANDLER,
            &ESM_IMPORT,
            &CJS_REQUIRE,
            &DEFAULT_EXPORT,
            &JS_BODY_READ,
            &JS_VALIDATOR,
            &PARSE_CALL,
            &RUST_BODY_READ,
            &RUST_TYPED,
            &RUST_VALIDATOR,
            &GO_BODY_READ,
            &GO_VALIDATOR,
            &ORM_COLLECTION,
            &ORM_BOUND,
            &SQL_SELECT,
            &SQL_FROM,
            &SQL_BOUND,
            &JS_FLOATING,
            &GO_DROPPED,
            &AWAIT,
            &ERROR_PATH,
            &WRITE_CALL,
            &SQL_WRITE,
            &TX_CALL,
            &TX_BEGIN,
            &TX_HANDLE,
            &TX_RECEIVER,
            &TX_DECORATOR,
            &SQL_TX,
            &JS_LOOP,
            &RUST_LOOP,
            &GO_LOOP,
            &SQL_SHAPE,
            &EXPORT_FROM,
            &EXPORT_LIST,
            &ASSIGNMENT,
            &WRAPPED_REFERENCE,
            &CLASS_DECL,
            &OBJECT_DECL,
            &INSTANCE_DECL,
            &DEFAULT_CONTAINER,
            &MEMBER_HEAD,
            &EXPORT_STAR,
            &TX_BOUND,
            &GO_TX_BOUND,
            &JS_BLOCKING,
            &RUST_BLOCKING,
            &OFFLOADED,
        ]
        .iter()
        .all(|re| re.is_some())
            && JS_DECLARATIONS.len() == 5
            && RUST_DECLARATIONS.len() == 1
            && GO_DECLARATIONS.len() == 1
    }

    #[test]
    fn all_patterns_compile() {
        assert!(patterns_compile());
    }

    fn extracted(lang: Lang, source: &Source, components: &[&str]) -> Vec<RawRoute> {
        match lang {
            Lang::Js => {
                let components: Vec<String> = components.iter().map(|c| (*c).to_owned()).collect();
                let mut routes = next::extract(&components, source);
                routes.extend(node::extract(source));
                routes
            }
            Lang::Rust => axum::extract(source),
            Lang::Go => go::extract(source),
        }
    }

    /// `METHOD path: kind@line` per risk, routes in declaration order.
    fn audited(lang: Lang, src: &str, components: &[&str]) -> Vec<String> {
        let source = Source::new(src, lang);
        let mut routes = extracted(lang, &source, components);
        annotate(&source, lang, &mut routes, None);
        summarize(&routes)
    }

    fn summarize(routes: &[RawRoute]) -> Vec<String> {
        let mut routes = routes.to_vec();
        routes.sort_by_key(|route| route.line);
        routes
            .iter()
            .flat_map(|route| {
                route.risks.iter().map(move |risk| {
                    let at = risk.file.as_deref().map_or_else(
                        || risk.line.to_string(),
                        |file| format!("{file}:{}", risk.line),
                    );
                    format!(
                        "{} {}: {:?}@{at}",
                        method_token(route.method).to_ascii_uppercase(),
                        route.path,
                        risk.kind,
                    )
                })
            })
            .collect()
    }

    #[test]
    fn express_handlers() {
        let src = r#"const express = require("express");
const app = express();

app.post("/orders", async (req, res) => {
  const order = await prisma.order.create({ data: req.body });
  res.status(201).json(order);
});

app.get("/orders", async (req, res, next) => {
  try {
    const orders = await prisma.order.findMany({ where: { open: true } });
    res.json(orders);
  } catch (err) {
    next(err);
  }
});

app.put("/orders/:id", validate(OrderSchema), async (req, res, next) => {
  try {
    prisma.auditLog.create({ data: { id: req.params.id } });
    const order = await prisma.order.update({ where: { id: req.params.id }, data: req.body });
    res.json(order);
  } catch (err) {
    next(err);
  }
});

app.get("/recent", asyncHandler(async (req, res) => {
  // prisma.order.findMany() in a comment is not a query
  const rows = await prisma.order.findMany({ take: 20 });
  res.json(rows.find((row) => row.open));
}));

app.delete("/orders/:id", removeOrder);

async function removeOrder(req, res) {
  const { reason } = req.body;
  await db.query("DELETE FROM orders WHERE id = $1", [req.params.id]);
  mailer.sendMail({ subject: reason }).catch(() => {});
  res.sendStatus(204);
}
"#;
        assert_eq!(
            audited(Lang::Js, src, &["api", "server.js"]),
            [
                "POST /orders: UnvalidatedMutation@5",
                "POST /orders: FloatingAsync@4",
                "GET /orders: UnboundedQuery@11",
                "PUT /orders/:id: FloatingAsync@20",
                "PUT /orders/:id: NonAtomicMultiWrite@20",
                "DELETE /orders/:id: UnvalidatedMutation@37",
                "DELETE /orders/:id: FloatingAsync@36",
            ]
        );
    }

    #[test]
    fn express_async_errors_patch_and_parse_receivers() {
        let src = "require('express-async-errors');\napp.post('/a', async (req, res) => {\n  const body = JSON.parse(req.body.raw);\n  await repo.save(body);\n  res.end();\n});\napp.post('/b', async (req, res) => {\n  const body = Body.parse(req.body);\n  await repo.save(body);\n});\n";
        assert_eq!(
            audited(Lang::Js, src, &["server.js"]),
            ["POST /a: UnvalidatedMutation@3"]
        );
    }

    #[test]
    fn next_app_router_handlers() {
        let src = r#"import { sql } from "@/db";
import { OrderInput } from "@/schemas";

export async function GET() {
  const rows = await sql`SELECT id, total FROM orders ORDER BY created_at DESC`;
  return Response.json(rows);
}

export async function POST(request: Request) {
  const body = OrderInput.parse(await request.json());
  fetch("http://127.0.0.1:9000/hooks/order", { method: "POST", body: JSON.stringify(body) });
  return Response.json(body, { status: 201 });
}
"#;
        let components = ["app", "api", "orders", "route.ts"];
        assert_eq!(
            audited(Lang::Js, src, &components),
            [
                "GET /api/orders: UnboundedQuery@5",
                "POST /api/orders: FloatingAsync@11",
            ]
        );
        let unvalidated = src.replace(
            "OrderInput.parse(await request.json())",
            "await request.json()",
        );
        assert_eq!(
            audited(Lang::Js, &unvalidated, &components),
            [
                "GET /api/orders: UnboundedQuery@5",
                "POST /api/orders: UnvalidatedMutation@10",
                "POST /api/orders: FloatingAsync@11",
            ]
        );
    }

    #[test]
    fn axum_handlers_by_name() {
        let src = r#"pub fn router() -> Router<Db> {
    Router::new()
        .route("/items", post(create_item).get(list_items))
        .route("/items/{id}", put(update_item).get(show_item))
}

async fn create_item(State(db): State<Db>, Json(body): Json<serde_json::Value>) -> StatusCode {
    StatusCode::CREATED
}

async fn list_items(State(db): State<Db>) -> Json<Vec<Item>> {
    let rows = sqlx::query_as::<_, Item>("SELECT id, name FROM items").fetch_all(&db).await;
    Json(rows.unwrap_or_default())
}

async fn update_item(Path(id): Path<i64>, Json(body): Json<UpdateItem>) -> StatusCode {
    StatusCode::OK
}

async fn show_item(Path(id): Path<i64>) -> String {
    sqlx::query("SELECT name FROM items WHERE id = $1").to_string()
}
"#;
        assert_eq!(
            audited(Lang::Rust, src, &[]),
            [
                "POST /items: UnvalidatedMutation@7",
                "GET /items: UnboundedQuery@12",
            ]
        );
    }

    #[test]
    fn go_handlers() {
        let src = "package main\n\nfunc routes(mux *http.ServeMux) {\n\tmux.HandleFunc(\"POST /items\", createItem)\n\tmux.HandleFunc(\"GET /items\", listItems)\n}\n\nfunc createItem(w http.ResponseWriter, r *http.Request) {\n\tvar in Item\n\tif err := json.NewDecoder(r.Body).Decode(&in); err != nil {\n\t\treturn\n\t}\n\tdb.Exec(\"INSERT INTO items (name) VALUES ($1)\", in.Name)\n}\n\nfunc listItems(w http.ResponseWriter, r *http.Request) {\n\trows, err := db.Query(\"SELECT id, name FROM items\")\n\t_ = rows\n\t_ = err\n}\n";
        assert_eq!(
            audited(Lang::Go, src, &[]),
            [
                "POST /items: FloatingAsync@13",
                "GET /items: UnboundedQuery@17",
            ]
        );
    }

    #[test]
    fn writes_outside_a_transaction() {
        let src = r#"app.post("/transfer", validate(Transfer), async (req, res, next) => {
  try {
    const { from, to, amount } = req.body;
    await db.query("UPDATE accounts SET balance = balance - $1 WHERE id = $2", [amount, from]);
    await db.query("UPDATE accounts SET balance = balance + $1 WHERE id = $2", [amount, to]);
    res.sendStatus(204);
  } catch (err) {
    next(err);
  }
});

app.post("/orders", validate(Order), async (req, res, next) => {
  try {
    const order = await prisma.$transaction(async (tx) => {
      const created = await tx.order.create({ data: req.body });
      await tx.coupon.update({ where: { code: req.body.code }, data: { used: { increment: 1 } } });
      return created;
    });
    res.status(201).json(order);
  } catch (err) {
    next(err);
  }
});

app.post("/signup", validate(Signup), async (req, res, next) => {
  try {
    const user = await User.create(req.body);
    await Profile.create({ userId: user.id });
    await mailer.sendMail({ to: user.email });
    res.status(201).json(user);
  } catch (err) {
    next(err);
  }
});

app.delete("/sessions/:id", async (req, res, next) => {
  try {
    url.searchParams.delete("token");
    cache.delete(req.params.id);
    await db.session.delete({ where: { id: req.params.id } });
    res.sendStatus(204);
  } catch (err) {
    next(err);
  }
});
"#;
        assert_eq!(
            audited(Lang::Js, src, &["server.js"]),
            [
                "POST /transfer: NonAtomicMultiWrite@4",
                "POST /signup: NonAtomicMultiWrite@27",
            ]
        );

        let source = Source::new(src, Lang::Js);
        let mut routes = extracted(Lang::Js, &source, &["server.js"]);
        annotate(&source, Lang::Js, &mut routes, None);
        let transfer = routes.iter().find(|r| r.path == "/transfer").unwrap();
        assert_eq!(
            transfer.risks[0].detail,
            "2 writes (`UPDATE ACCOUNTS SET`, `UPDATE ACCOUNTS SET`) with no transaction around them; a failure or a concurrent request between them leaves partial state"
        );
        let signup = routes.iter().find(|r| r.path == "/signup").unwrap();
        assert!(
            signup.risks[0]
                .detail
                .starts_with("2 writes (`User.create`, `Profile.create`)"),
            "{}",
            signup.risks[0].detail
        );

        let rust = r#"pub fn router() -> Router<Db> {
    Router::new()
        .route("/redeem", post(redeem))
        .route("/refund", post(refund))
}

async fn redeem(State(db): State<Db>, Json(body): Json<Redeem>) -> StatusCode {
    sqlx::query("UPDATE coupons SET used = used + 1 WHERE code = $1").bind(&body.code).execute(&db).await.ok();
    sqlx::query("INSERT INTO redemptions (code) VALUES ($1)").bind(&body.code).execute(&db).await.ok();
    StatusCode::OK
}

async fn refund(State(db): State<Db>, Json(body): Json<Refund>) -> StatusCode {
    let mut tx = db.begin().await.unwrap();
    sqlx::query("UPDATE orders SET refunded = true WHERE id = $1").bind(body.id).execute(&mut *tx).await.ok();
    sqlx::query("INSERT INTO ledger (order_id) VALUES ($1)").bind(body.id).execute(&mut *tx).await.ok();
    tx.commit().await.ok();
    StatusCode::OK
}
"#;
        assert_eq!(
            audited(Lang::Rust, rust, &[]),
            ["POST /redeem: NonAtomicMultiWrite@8"]
        );

        let go = "package main\n\nfunc routes(mux *http.ServeMux) {\n\tmux.HandleFunc(\"POST /pay\", pay)\n}\n\nfunc pay(w http.ResponseWriter, r *http.Request) {\n\tif _, err := db.Exec(\"UPDATE wallets SET cents = cents - $1\", 5); err != nil {\n\t\treturn\n\t}\n\tif _, err := db.Exec(\"INSERT INTO payments (cents) VALUES ($1)\", 5); err != nil {\n\t\treturn\n\t}\n\tf, _ := os.Create(\"receipt.txt\")\n\t_ = f\n}\n";
        assert_eq!(
            audited(Lang::Go, go, &[]),
            ["POST /pay: NonAtomicMultiWrite@8"]
        );
    }

    fn details(lang: Lang, src: &str, components: &[&str]) -> Vec<(String, String)> {
        let source = Source::new(src, lang);
        let mut routes = extracted(lang, &source, components);
        annotate(&source, lang, &mut routes, None);
        routes.sort_by_key(|route| route.line);
        routes
            .iter()
            .flat_map(|route| {
                route
                    .risks
                    .iter()
                    .filter(|risk| risk.kind == RouteRiskKind::NonAtomicMultiWrite)
                    .map(move |risk| (route.path.clone(), risk.detail.clone()))
            })
            .collect()
    }

    #[test]
    fn chained_and_repeated_writes_outside_transactions() {
        let src = r#"app.post("/orders", validate(Order), async (req, res, next) => {
  try {
    const order = await prisma.order
      .create({ data: req.body });
    await prisma.coupon
      .update({ where: { code: req.body.code }, data: { used: { increment: 1 } } });
    res.status(201).json(order);
  } catch (err) {
    next(err);
  }
});

app.post("/restock", validate(Restock), async (req, res, next) => {
  try {
    for (const line of req.body.lines) {
      await prisma.stock.update({ where: { sku: line.sku }, data: { qty: line.qty } });
    }
    res.sendStatus(204);
  } catch (err) {
    next(err);
  }
});

app.delete("/carts/:id", validate(Cart), async (req, res, next) => {
  try {
    req.body.items.forEach(async (item) => {
      await db.cartItem.delete({ where: { id: item.id } });
    });
    res.sendStatus(204);
  } catch (err) {
    next(err);
  }
});

app.post("/import", validate(Import), async (req, res, next) => {
  try {
    await prisma.$transaction(async (tx) => {
      for (const row of req.body.rows) {
        await tx.product.upsert({ where: { sku: row.sku }, create: row, update: row });
      }
    });
    res.sendStatus(204);
  } catch (err) {
    next(err);
  }
});

app.post("/checkout", validate(Checkout), async (req, res, next) => {
  try {
    const order = await prisma.$transaction([prisma.order.create({ data: req.body })]);
    await prisma.cart.delete({ where: { id: req.body.cartId } });
    res.status(201).json(order);
  } catch (err) {
    next(err);
  }
});

app.post("/batch", validate(Batch), async (req, res, next) => {
  try {
    let page = 0;
    while (page < req.body.pages) {
      await knex("events").insert({ page: page++ });
    }
    res.sendStatus(202);
  } catch (err) {
    next(err);
  }
});

app.post("/payments", validate(Payment), async (req, res, next) => {
  try {
    await prisma.transaction.create({ data: { cents: req.body.cents } });
    await prisma.account.update({ where: { id: req.body.account }, data: { cents: { decrement: req.body.cents } } });
    res.sendStatus(201);
  } catch (err) {
    next(err);
  }
});

app.post("/ledger", validate(Entry), async (req, res, next) => {
  try {
    const t = await sequelize.transaction();
    await Entry.create(req.body, { transaction: t });
    await Balance.update({ cents: req.body.cents }, { where: { id: req.body.account }, transaction: t });
    await t.commit();
    res.sendStatus(201);
  } catch (err) {
    next(err);
  }
});
"#;
        assert_eq!(
            audited(Lang::Js, src, &["server.js"]),
            [
                "POST /orders: NonAtomicMultiWrite@3",
                "POST /restock: NonAtomicMultiWrite@16",
                "DELETE /carts/:id: NonAtomicMultiWrite@27",
                "POST /checkout: NonAtomicMultiWrite@51",
                "POST /batch: NonAtomicMultiWrite@62",
                "POST /payments: NonAtomicMultiWrite@72",
            ]
        );
        let tail = "a failure or a concurrent request mid-loop leaves partial state";
        assert_eq!(
            details(Lang::Js, src, &["server.js"]),
            [
                ("/orders".to_owned(), "2 writes (`prisma.order.create`, `prisma.coupon.update`) with no transaction around them; a failure or a concurrent request between them leaves partial state".to_owned()),
                ("/restock".to_owned(), format!("`prisma.stock.update` runs once per iteration of a `for` loop with no transaction around it; {tail}")),
                ("/carts/:id".to_owned(), format!("`db.cartItem.delete` runs once per iteration of a `forEach` loop with no transaction around it; {tail}")),
                ("/checkout".to_owned(), "2 writes, 1 of them outside the transaction (`prisma.cart.delete`); a failure after it commits leaves partial state".to_owned()),
                ("/batch".to_owned(), format!("`knex.insert` runs once per iteration of a `while` loop with no transaction around it; {tail}")),
                ("/payments".to_owned(), "2 writes (`prisma.transaction.create`, `prisma.account.update`) with no transaction around them; a failure or a concurrent request between them leaves partial state".to_owned()),
            ]
        );

        let rust = r#"pub fn router() -> Router<Db> {
    Router::new()
        .route("/restock", post(restock))
        .route("/archive", post(archive))
}

async fn restock(State(db): State<Db>, Json(body): Json<Restock>) -> StatusCode {
    for line in &body.lines {
        sqlx::query("UPDATE stock SET qty = $1 WHERE sku = $2").bind(line.qty).bind(&line.sku).execute(&db).await.ok();
    }
    StatusCode::OK
}

async fn archive(State(db): State<Db>, Json(body): Json<Archive>) -> StatusCode {
    let mut tx = db.begin().await.unwrap();
    for id in &body.ids {
        sqlx::query("DELETE FROM orders WHERE id = $1").bind(id).execute(&mut *tx).await.ok();
    }
    tx.commit().await.ok();
    StatusCode::OK
}
"#;
        assert_eq!(
            details(Lang::Rust, rust, &[]),
            [(
                "/restock".to_owned(),
                format!("`UPDATE STOCK SET` runs once per iteration of a `for` loop with no transaction around it; {tail}")
            )]
        );
        assert_eq!(
            audited(Lang::Rust, rust, &[]),
            ["POST /restock: NonAtomicMultiWrite@9"]
        );

        let go = "package main\n\nfunc routes(mux *http.ServeMux) {\n\tmux.HandleFunc(\"POST /sync\", syncItems)\n}\n\nfunc syncItems(w http.ResponseWriter, r *http.Request) {\n\tvar in []Item\n\tif err := json.NewDecoder(r.Body).Decode(&in); err != nil {\n\t\treturn\n\t}\n\tfor _, item := range in {\n\t\tif _, err := db.Exec(\"UPDATE items SET qty = $1 WHERE id = $2\", item.Qty, item.ID); err != nil {\n\t\t\treturn\n\t\t}\n\t}\n}\n";
        assert_eq!(
            audited(Lang::Go, go, &[]),
            ["POST /sync: NonAtomicMultiWrite@13"]
        );
    }

    #[test]
    fn writes_that_bypass_a_bound_transaction_handle() {
        let src = r#"app.post("/transfer", validate(Transfer), async (req, res, next) => {
  try {
    const { from, to, amount } = req.body;
    const tx = await db.begin();
    await tx.query("UPDATE accounts SET balance = balance - $1 WHERE id = $2", [amount, from]);
    await db.query("UPDATE accounts SET balance = balance + $1 WHERE id = $2", [amount, to]);
    await tx.commit();
    res.sendStatus(204);
  } catch (err) {
    next(err);
  }
});

app.post("/archive", validate(Archive), async (req, res, next) => {
  try {
    const trx = await knex.transaction();
    await trx("orders").update({ archived: true }).where({ id: req.body.id });
    await knex("audit").insert({ action: "archive", order: req.body.id });
    await trx.commit();
    res.sendStatus(204);
  } catch (err) {
    next(err);
  }
});

app.post("/ledger", validate(Entry), async (req, res, next) => {
  try {
    const t = await sequelize.transaction();
    await Entry.create(req.body, { transaction: t });
    await Balance.update({ cents: req.body.cents }, { where: { id: req.body.account }, transaction: t });
    await t.commit();
    res.sendStatus(201);
  } catch (err) {
    next(err);
  }
});

app.post("/close", validate(Close), async (req, res, next) => {
  try {
    const tx = await db.begin();
    await db.account.update({ where: { id: req.body.id }, data: { closed: true } });
    await tx.commit();
    res.sendStatus(204);
  } catch (err) {
    next(err);
  }
});
"#;
        assert_eq!(
            audited(Lang::Js, src, &["server.js"]),
            [
                "POST /transfer: NonAtomicMultiWrite@6",
                "POST /archive: NonAtomicMultiWrite@18",
                "POST /close: NonAtomicMultiWrite@41",
            ]
        );
        let bypass = |conn: &str, handle: &str, write: &str| {
            format!("write on '{conn}' bypasses active transaction handle '{handle}': `{write}` commits on its own and survives a rollback")
        };
        assert_eq!(
            details(Lang::Js, src, &["server.js"]),
            [
                (
                    "/transfer".to_owned(),
                    bypass("db", "tx", "UPDATE ACCOUNTS SET")
                ),
                ("/archive".to_owned(), bypass("knex", "trx", "knex.insert")),
                ("/close".to_owned(), bypass("db", "tx", "db.account.update")),
            ]
        );

        let rust = r#"pub fn router() -> Router<Db> {
    Router::new()
        .route("/refund", post(refund))
        .route("/settle", post(settle))
}

async fn refund(State(db): State<Db>, Json(body): Json<Refund>) -> StatusCode {
    let mut tx = db.begin().await.unwrap();
    sqlx::query("UPDATE orders SET refunded = true WHERE id = $1").bind(body.id).execute(&mut *tx).await.ok();
    sqlx::query("INSERT INTO ledger (order_id) VALUES ($1)").bind(body.id).execute(&db).await.ok();
    tx.commit().await.ok();
    StatusCode::OK
}

async fn settle(State(db): State<Db>, Json(body): Json<Settle>) -> StatusCode {
    let mut tx = db.begin().await.unwrap();
    sqlx::query("UPDATE invoices SET paid = true WHERE id = $1").bind(body.id).execute(&mut *tx).await.ok();
    sqlx::query("INSERT INTO payments (invoice_id) VALUES ($1)").bind(body.id).execute(&mut *tx).await.ok();
    tx.commit().await.ok();
    StatusCode::OK
}
"#;
        assert_eq!(
            details(Lang::Rust, rust, &[]),
            [("/refund".to_owned(), bypass("db", "tx", "INSERT INTO"))]
        );
        assert_eq!(
            audited(Lang::Rust, rust, &[]),
            ["POST /refund: NonAtomicMultiWrite@10"]
        );

        let go = "package main\n\nfunc routes(mux *http.ServeMux) {\n\tmux.HandleFunc(\"POST /refund\", refund)\n}\n\nfunc refund(w http.ResponseWriter, r *http.Request) {\n\ttx, err := db.Begin()\n\tif err != nil {\n\t\treturn\n\t}\n\tif _, err := tx.Exec(\"UPDATE orders SET refunded = true WHERE id = $1\", 7); err != nil {\n\t\treturn\n\t}\n\tif _, err := db.Exec(\"INSERT INTO ledger (order_id) VALUES ($1)\", 7); err != nil {\n\t\treturn\n\t}\n\tif err := tx.Commit(); err != nil {\n\t\treturn\n\t}\n}\n";
        assert_eq!(
            audited(Lang::Go, go, &[]),
            ["POST /refund: NonAtomicMultiWrite@15"]
        );
        assert!(mentions("execute(&mut *tx)", "tx"));
        assert!(mentions("{ where: { id }, transaction: t }", "t"));
        assert!(!mentions("{ txn: 1, req.body.tx }", "tx"));
        assert_eq!(
            called_receiver("    await this.pool.query("),
            "this.pool.query"
        );
        assert_eq!(called_receiver("    sqlx::query("), "query");
        assert_eq!(called_receiver("    const sql = "), "");
    }

    #[test]
    fn blocking_calls_inside_handlers() {
        let src = r#"app.get("/avatar/:id", async (req, res, next) => {
  try {
    const template = fs.readFileSync("./templates/avatar.html", "utf8");
    res.send(template.replace("{id}", req.params.id));
  } catch (err) {
    next(err);
  }
});

app.post("/login", validate(Login), async (req, res, next) => {
  try {
    const user = await db.user.findUnique({ where: { email: req.body.email } });
    if (!bcrypt.compareSync(req.body.password, user.passwordHash)) return res.sendStatus(401);
    res.json({ id: user.id });
  } catch (err) {
    next(err);
  }
});
const banner = fs.readFileSync("./banner.txt", "utf8");

app.get("/banner", (req, res) => res.send(banner));
app.get("/docs", (req, res) => res.send("the readFileSync() call is synchronous"));
"#;
        assert_eq!(
            audited(Lang::Js, src, &["server.js"]),
            [
                "GET /avatar/:id: BlockingInAsync@3",
                "POST /login: BlockingInAsync@13",
            ]
        );
        let source = Source::new(src, Lang::Js);
        let mut routes = extracted(Lang::Js, &source, &["server.js"]);
        annotate(&source, Lang::Js, &mut routes, None);
        assert_eq!(
            routes[0].risks[0].detail,
            "`readFileSync` blocks the event loop inside a request handler, so every concurrent request waits behind it; use fs/promises"
        );

        let rust = r#"pub fn router() -> Router<Db> {
    Router::new()
        .route("/report", get(report))
        .route("/export", get(export))
}

async fn report(State(db): State<Db>) -> String {
    std::thread::sleep(std::time::Duration::from_millis(50));
    std::fs::read_to_string("report.txt").unwrap_or_default()
}

async fn export(State(db): State<Db>) -> String {
    tokio::task::spawn_blocking(|| std::fs::read_to_string("export.csv").unwrap_or_default())
        .await
        .unwrap_or_default()
}

fn render(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}
"#;
        assert_eq!(
            audited(Lang::Rust, rust, &[]),
            ["GET /report: BlockingInAsync@8"]
        );
    }

    #[test]
    fn members_with_decorated_and_defaulted_parameters() {
        let src = r#"class OrdersController {
  @Post()
  async create(@Body() dto: CreateOrderDto, @Req() req: Request, @Param('id') id = parseInt("1")) {
    await this.db.order.create({ data: req.body });
    await this.db.audit.create({ data: { action: "create", id } });
  }

  @Get(':id') async show(@Param('id') id: string, @Query() query = defaults()): Promise<{ id: string }> {
    return this.db.order.findMany({ where: { id } });
  }

  list = async (req: Request, res: Response, limit = Number(process.env.LIMIT ?? "20")): Promise<void> => {
    res.json(await this.db.order.findMany());
  };
}

const controller = new OrdersController();
router.post("/orders", controller.create);
router.get("/orders/:id", controller.show);
router.get("/orders", controller.list);
"#;
        assert_eq!(
            audited(Lang::Js, src, &["orders.controller.ts"]),
            [
                "POST /orders: UnvalidatedMutation@4",
                "POST /orders: FloatingAsync@3",
                "POST /orders: NonAtomicMultiWrite@4",
                "GET /orders/:id: UnboundedQuery@9",
                "GET /orders: UnboundedQuery@13",
                "GET /orders: FloatingAsync@12",
            ]
        );
        // A parenthesized value is not a member function; an overload signature has no body.
        let text = "{\n  total: (a + b),\n  create(input: Input): void;\n  create(input: Input) {\n    return input;\n  }\n}\n";
        let source = Source::new(text, Lang::Js);
        let ctx = FileContext::new(&source, Lang::Js, &[], None, false);
        let range = ctx.member_range(1..text.len() - 2, "create").unwrap();
        assert!(text[range.clone()].starts_with("  create(input: Input) {"));
        assert!(text[range].ends_with('}'));
        assert!(ctx.member_range(1..text.len() - 2, "total").is_none());
    }

    #[test]
    fn body_reads_inside_template_expressions() {
        let src = r#"app.post("/notes", async (req, res, next) => {
  try {
    logger.info(`note for ${req.body.orderId} received`);
    res.sendStatus(202);
  } catch (err) {
    next(err);
  }
});

app.post("/docs", async (req, res, next) => {
  try {
    res.send("send the payload as req.body with a JSON content type");
  } catch (err) {
    next(err);
  }
});

app.post("/typed", zValidator("json", Note), async (c) => {
  const note = `${c.req.valid("json").text}`;
  return c.json({ note });
});
"#;
        assert_eq!(
            audited(Lang::Js, src, &["server.js"]),
            ["POST /notes: UnvalidatedMutation@3"]
        );
        // The validated accessor is evidence of validation wherever the validator sits.
        let elsewhere = src.replace("zValidator(\"json\", Note), ", "");
        assert_eq!(
            audited(Lang::Js, &elsewhere, &["server.js"]),
            ["POST /notes: UnvalidatedMutation@3"]
        );
    }

    #[test]
    fn class_and_object_members_in_the_same_file() {
        let src = r#"class OrdersController {
  constructor(service) {
    this.service = service;
  }

  create = async (req, res, next) => {
    try {
      await db.order.create({ data: req.body });
      await db.audit.create({ data: { action: "create" } });
      res.sendStatus(201);
    } catch (err) {
      next(err);
    }
  };

  async list(req, res, next) {
    try {
      res.json(await db.order.findMany());
    } catch (err) {
      next(err);
    }
  }
}

const handlers = {
  remove: async (req, res, next) => {
    try {
      const { reason } = req.body;
      await db.order.delete({ where: { id: req.params.id }, data: { reason } });
      res.sendStatus(204);
    } catch (err) {
      next(err);
    }
  },
};

const controller = new OrdersController(service);
router.post("/orders", controller.create);
router.get("/orders", controller.list);
router.delete("/orders/:id", handlers.remove);
"#;
        assert_eq!(
            audited(Lang::Js, src, &["routes.js"]),
            [
                "POST /orders: UnvalidatedMutation@8",
                "POST /orders: NonAtomicMultiWrite@8",
                "GET /orders: UnboundedQuery@18",
                "DELETE /orders/:id: UnvalidatedMutation@28",
            ]
        );
    }

    #[test]
    fn interpolated_sql() {
        let src = r#"app.get("/users", async (req, res, next) => {
  try {
    const rows = await db.query(`SELECT * FROM users WHERE name = '${req.query.name}' LIMIT 10`);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.get("/users/:id", async (req, res, next) => {
  try {
    const rows = await db.query("SELECT * FROM users WHERE id = " + req.params.id);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.get("/safe/:id", async (req, res, next) => {
  try {
    const rows = await sql`SELECT * FROM users WHERE id = ${req.params.id} LIMIT 1`;
    const more = await db.query("SELECT * FROM users WHERE id = $1 LIMIT 1", [req.params.id]);
    console.log(`selected ${rows.length} users from the cache`);
    res.json([rows, more]);
  } catch (err) {
    next(err);
  }
});
"#;
        assert_eq!(
            audited(Lang::Js, src, &["server.js"]),
            [
                "GET /users: UnsafeSqlInterpolation@3",
                "GET /users/:id: UnsafeSqlInterpolation@12",
            ]
        );

        let rust = "pub fn router() -> Router<Db> {\n    Router::new().route(\"/items\", get(search))\n}\n\nasync fn search(State(db): State<Db>, Query(q): Query<Search>) -> String {\n    let sql = format!(\"SELECT id FROM items WHERE name = '{}' LIMIT 20\", q.name);\n    sqlx::query(&sql).fetch_all(&db).await.map(|_| String::new()).unwrap_or_default()\n}\n";
        assert_eq!(
            audited(Lang::Rust, rust, &[]),
            ["GET /items: UnsafeSqlInterpolation@6"]
        );

        let go = "package main\n\nfunc routes(mux *http.ServeMux) {\n\tmux.HandleFunc(\"GET /items\", search)\n}\n\nfunc search(w http.ResponseWriter, r *http.Request) {\n\tq := fmt.Sprintf(\"SELECT id FROM items WHERE name = '%s' LIMIT 20\", r.URL.Query().Get(\"name\"))\n\trows, err := db.Query(q)\n\t_, _ = rows, err\n}\n";
        assert_eq!(
            audited(Lang::Go, go, &[]),
            ["GET /items: UnsafeSqlInterpolation@8"]
        );
    }

    #[test]
    fn import_bindings_cover_esm_and_commonjs() {
        let src = r#"import Orders, { create as createOrder, type Order } from "./orders";
import * as users from "../controllers/users.js";
import type { Session } from "./session";
import express from "express";
import {
  list,
  remove,
} from "./items";
const { refund, void: cancel } = require("./payments");
const audit = require("./audit");
const notify = require("./notify").send;
"#;
        let source = Source::new(src, Lang::Js);
        let bindings = import_bindings(&source);
        let summary: Vec<(String, String, Export)> = bindings
            .into_iter()
            .map(|b| (b.local, b.module, b.export))
            .collect();
        let named = |n: &str| Export::Named(n.to_owned());
        let s = |text: &str| text.to_owned();
        assert_eq!(
            summary,
            [
                (s("Orders"), s("./orders"), Export::Default),
                (s("createOrder"), s("./orders"), named("create")),
                (s("users"), s("../controllers/users.js"), Export::Module),
                (s("express"), s("express"), Export::Default),
                (s("list"), s("./items"), named("list")),
                (s("remove"), s("./items"), named("remove")),
                (s("refund"), s("./payments"), named("refund")),
                (s("cancel"), s("./payments"), named("void")),
                (s("audit"), s("./audit"), Export::Module),
                (s("notify"), s("./notify"), named("send")),
            ]
        );
        let bindings = import_bindings(&source);
        assert_eq!(
            import_target(&bindings, "users.create"),
            Some(("../controllers/users.js", Target::Named(s("create"))))
        );
        assert_eq!(
            import_target(&bindings, "audit"),
            Some(("./audit", Target::Default))
        );
        // A package is bound like any module; resolution, not binding, rules it out.
        assert_eq!(
            import_target(&bindings, "express"),
            Some(("express", Target::Default))
        );
        assert_eq!(import_target(&bindings, "missing"), None);
        // Members of default and named imports belong to the exported container.
        assert_eq!(
            import_target(&bindings, "Orders.create"),
            Some((
                "./orders",
                Target::Member {
                    container: None,
                    member: s("create")
                }
            ))
        );
        assert_eq!(
            import_target(&bindings, "list.run"),
            Some((
                "./items",
                Target::Member {
                    container: Some(s("list")),
                    member: s("run")
                }
            ))
        );
        assert_eq!(
            class_import(&bindings, "users.OrdersController"),
            Some(("../controllers/users.js", Some(s("OrdersController"))))
        );
        assert_eq!(
            exported_as("GET, create as POST, type T", "POST"),
            Some("create")
        );
        assert_eq!(exported_as("GET", "GET"), Some("GET"));
        assert_eq!(
            wrapped_reference("withAuth(createOrder, { role })").as_deref(),
            Some("createOrder")
        );
        assert_eq!(
            wrapped_reference("orders.create").as_deref(),
            Some("orders.create")
        );
        assert_eq!(wrapped_reference("async (req) => ok(req)"), None);
    }
}
