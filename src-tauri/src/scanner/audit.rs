//! Static reliability audit of route handlers.
//!
//! Lexical, like the extractors. Each route gets the source region of its handler: the
//! declaration up to the next route or top-level declaration, plus the bodies of handlers it
//! names that are defined in the same file. Three checks then run over the comment-masked
//! text. Every check needs positive evidence (a body read, a collection query, a dropped
//! call), so a handler the pass cannot resolve yields no risk rather than a guess.

use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use super::lex::{self, Lang, Source};
use super::routes::{compile, RawRoute};
use crate::engine::types::{RouteMethod, RouteRisk, RouteRiskKind, RouteSource};

/// A handler region never extends past this many lines, so a route at the end of a long
/// file without further declarations is not judged by unrelated code.
const MAX_REGION_LINES: usize = 160;
const MAX_NAMED_HANDLERS: usize = 3;
const EVIDENCE_CHARS: usize = 120;
/// Bytes after a query call searched for a chained `.limit(` / `.then(`.
const CHAIN_WINDOW: usize = 400;

static JS_DECLARATIONS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?m)^(?:export[ \t]+)?(?:default[ \t]+)?(?:async[ \t]+)?function[ \t]*\*?[ \t]*([A-Za-z_$][\w$]*)?",
        r"(?m)^(?:export[ \t]+)?(?:const|let|var)[ \t]+([A-Za-z_$][\w$]*)[ \t]*(?::[^=\n]+)?=[ \t]*(?:async(?-u:\b)|function(?-u:\b)|\(|[A-Za-z_$][\w$]*[ \t]*=>)",
        r"(?m)^[ \t]+(?:(?:public|private|protected|static|override)[ \t]+)*(?:async[ \t]+)?([A-Za-z_$][\w$]*)[ \t]*\([^)\n]*\)[ \t]*(?::[^{\n]+)?\{",
        r"(?m)^(?:export[ \t]+)?(?:default[ \t]+)?class(?-u:\b)",
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

// ---- unvalidated mutation -------------------------------------------------------------

static JS_BODY_READ: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?-u:\b)(?:req|request|ctx\.request)\.body(?-u:\b)|\.(?:json|formData)\(\s*\)|(?-u:\b)c\.req\.parseBody\(",
    )
});
static JS_VALIDATOR: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(concat!(
        r"(?-u:\b)z\.[a-z]+\(|(?-u:\b)(?:zod|valibot|yup|ajv|Ajv|superstruct|class-validator)(?-u:\b)",
        r"|(?-u:\b)(?:Joi|v)\.(?:object|parse)\(|(?-u:\b)Type\.Object\(|(?-u:\b)schema\s*:",
        r"|(?-u:\b)(?:validate|validator|validation|validationResult)|[a-z]Validat(?:e|or|ion)",
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

static JS_FLOATING: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(concat!(
        r"(?m)^[ \t]*((?:this\.)?[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)[ \t]*\.[ \t]*",
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

pub fn annotate(source: &Source, lang: Lang, routes: &mut [RawRoute]) {
    if routes.is_empty() {
        return;
    }
    let file = FileContext::new(source, lang, routes);
    for route in routes.iter_mut() {
        route.risks = file.audit(route);
    }
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
    /// `express-async-errors` patches Express 4 to forward rejected promises.
    patched_express: bool,
}

impl<'a> FileContext<'a> {
    fn new(source: &'a Source, lang: Lang, routes: &[RawRoute]) -> Self {
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
        Self {
            source,
            lang,
            starts,
            boundaries,
            declarations,
            patched_express: text.contains("express-async-errors"),
        }
    }

    fn text(&self) -> &str {
        &self.source.text
    }

    fn line_of(&self, offset: usize) -> usize {
        self.starts.partition_point(|&start| start <= offset)
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

    fn line_text(&self, line: usize) -> &str {
        let start = self
            .starts
            .get(line.saturating_sub(1))
            .copied()
            .unwrap_or(0);
        let end = self.starts.get(line).copied().unwrap_or(self.text().len());
        self.text().get(start..end).unwrap_or_default()
    }

    /// The declaration region plus the regions of handlers it names (`post(create)`,
    /// `app.post("/x", validate(schema), create)`).
    fn handler_regions(&self, route: &RawRoute) -> Vec<Range<usize>> {
        let line = usize::try_from(route.line).unwrap_or(0);
        let mut regions = vec![self.region(line)];
        for name in self.named_handlers(route, line) {
            let defined = self
                .declarations
                .iter()
                .find(|(declared, at)| *declared == name && *at != line)
                .map(|(_, at)| *at);
            if let Some(at) = defined {
                let region = self.region(at);
                if !regions.contains(&region) {
                    regions.push(region);
                }
            }
        }
        regions
    }

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
                    names.push(name.to_owned());
                }
            }
            if names.len() >= MAX_NAMED_HANDLERS {
                break;
            }
        }
        names
    }

    fn audit(&self, route: &RawRoute) -> Vec<RouteRisk> {
        let regions = self.handler_regions(route);
        let mut risks = Vec::new();
        if let Some(risk) = self.unvalidated_mutation(route, &regions) {
            risks.push(risk);
        }
        if let Some(risk) = self.unbounded_query(&regions) {
            risks.push(risk);
        }
        if let Some(risk) = self.floating_async(route, &regions) {
            risks.push(risk);
        }
        risks
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
        }
    }

    /// First code (not string) match of `re` in any region.
    fn first_code_match(&self, re: &Regex, regions: &[Range<usize>]) -> Option<usize> {
        regions.iter().find_map(|region| {
            let slice = self.text().get(region.clone())?;
            re.find_iter(slice)
                .map(|found| region.start + found.start())
                .find(|at| !self.source.in_string(*at))
        })
    }

    fn unvalidated_mutation(
        &self,
        route: &RawRoute,
        regions: &[Range<usize>],
    ) -> Option<RouteRisk> {
        if !matches!(
            route.method,
            RouteMethod::Post | RouteMethod::Put | RouteMethod::Patch | RouteMethod::Delete
        ) {
            return None;
        }
        let read_pattern = match self.lang {
            Lang::Js => JS_BODY_READ.as_ref(),
            Lang::Rust => RUST_BODY_READ.as_ref(),
            Lang::Go => GO_BODY_READ.as_ref(),
        }?;
        let read = self.first_code_match(read_pattern, regions)?;
        if self.validated(regions) {
            return None;
        }
        Some(self.risk(
            RouteRiskKind::UnvalidatedMutation,
            read,
            format!(
                "{} handler reads the request body with no schema validation in the handler or its middleware",
                method_token(route.method).to_ascii_uppercase()
            ),
        ))
    }

    fn validated(&self, regions: &[Range<usize>]) -> bool {
        let text = self.text();
        regions.iter().any(|region| {
            let Some(slice) = text.get(region.clone()) else {
                return false;
            };
            match self.lang {
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

    fn unbounded_query(&self, regions: &[Range<usize>]) -> Option<RouteRisk> {
        let text = self.text();
        for region in regions {
            let slice = text.get(region.clone())?;
            if let Some(re) = ORM_COLLECTION.as_ref() {
                for caps in re.captures_iter(slice) {
                    let (Some(whole), Some(name)) = (caps.get(0), caps.get(1)) else {
                        continue;
                    };
                    let at = region.start + whole.start();
                    let open = region.start + whole.end() - 1;
                    if self.source.in_string(at) {
                        continue;
                    }
                    let Some(close) = lex::matching_paren(text, open, self.lang) else {
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
                    let chain_start = self
                        .starts
                        .get(self.line_of(at).saturating_sub(1))
                        .copied()
                        .unwrap_or(at);
                    let chain_end = statement_end(text, close, CHAIN_WINDOW);
                    let bounded = ORM_BOUND.as_ref().is_some_and(|bound| {
                        bound.is_match(args) || bound.is_match(&text[chain_start..chain_end])
                    });
                    if !bounded {
                        return Some(self.risk(
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
                    let at = region.start + found.start();
                    let Some((_, end)) = self.source.string_span(at) else {
                        continue;
                    };
                    let statement = &text[at..end];
                    if from.is_match(statement) && !bound.is_match(statement) {
                        return Some(self.risk(
                            RouteRiskKind::UnboundedQuery,
                            at,
                            "SELECT without LIMIT, aggregate or key lookup returns every matching row".to_owned(),
                        ));
                    }
                }
            }
        }
        None
    }

    fn floating_async(&self, route: &RawRoute, regions: &[Range<usize>]) -> Option<RouteRisk> {
        match self.lang {
            Lang::Js => self
                .floating_promise(regions)
                .or_else(|| self.unguarded_express(route, regions)),
            Lang::Go => {
                let re = GO_DROPPED.as_ref()?;
                let at = self.first_code_match(re, regions)?;
                Some(self.risk(
                    RouteRiskKind::FloatingAsync,
                    at,
                    "database call whose error is never checked".to_owned(),
                ))
            }
            // Unused futures and Results are compiler warnings in Rust (`#[must_use]`).
            Lang::Rust => None,
        }
    }

    fn floating_promise(&self, regions: &[Range<usize>]) -> Option<RouteRisk> {
        let re = JS_FLOATING.as_ref()?;
        let text = self.text();
        for region in regions {
            let slice = text.get(region.clone())?;
            for caps in re.captures_iter(slice) {
                let Some(whole) = caps.get(0) else {
                    continue;
                };
                let at = region.start + whole.start() + whole.as_str().len()
                    - whole.as_str().trim_start().len();
                if self.source.in_string(at) {
                    continue;
                }
                let receiver = caps
                    .get(1)
                    .or_else(|| caps.get(3))
                    .map_or("", |m| m.as_str());
                let method = caps
                    .get(2)
                    .or_else(|| caps.get(4))
                    .map_or("", |m| m.as_str());
                let io = method == "save"
                    || method == "fetch"
                    || receiver.contains('.')
                    || IO_RECEIVERS.contains(&receiver.trim_start_matches("this."));
                if !io {
                    continue;
                }
                let end = statement_end(text, region.start + whole.end(), CHAIN_WINDOW);
                let tail = &text[region.start + whole.end()..end];
                if tail.contains(".then(") || tail.contains(".catch(") {
                    continue;
                }
                let call = if receiver.is_empty() {
                    method.to_owned()
                } else {
                    format!("{receiver}.{method}")
                };
                return Some(self.risk(
                    RouteRiskKind::FloatingAsync,
                    at,
                    format!("`{call}(...)` is neither awaited nor returned; its failure is lost and the response can precede the write"),
                ));
            }
        }
        None
    }

    fn unguarded_express(&self, route: &RawRoute, regions: &[Range<usize>]) -> Option<RouteRisk> {
        if route.source != RouteSource::Express || self.patched_express {
            return None;
        }
        let text = self.text();
        let declaration = self.line_text(usize::try_from(route.line).unwrap_or(0));
        if ASYNC_WRAPPERS
            .iter()
            .any(|wrapper| declaration.contains(wrapper))
        {
            return None;
        }
        let (awaits, guarded) = (AWAIT.as_ref()?, ERROR_PATH.as_ref()?);
        regions.iter().find_map(|region| {
            let slice = text.get(region.clone())?;
            let head = slice.lines().next().unwrap_or_default();
            let asynchronous = head.contains("async");
            (asynchronous && awaits.is_match(slice) && !guarded.is_match(slice)).then(|| {
                self.risk(
                    RouteRiskKind::FloatingAsync,
                    region.start,
                    "async Express handler awaits with no try/catch or next(err); Express 4 leaves the rejection unhandled and the request hanging".to_owned(),
                )
            })
        })
    }
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
        ]
        .iter()
        .all(|re| re.is_some())
            && JS_DECLARATIONS.len() == 4
            && RUST_DECLARATIONS.len() == 1
            && GO_DECLARATIONS.len() == 1
    }

    #[test]
    fn all_patterns_compile() {
        assert!(patterns_compile());
    }

    /// `METHOD path: kind@line` per risk, routes in declaration order.
    fn audited(lang: Lang, src: &str, components: &[&str]) -> Vec<String> {
        let source = Source::new(src, lang);
        let mut routes = match lang {
            Lang::Js => {
                let components: Vec<String> = components.iter().map(|c| (*c).to_owned()).collect();
                let mut routes = next::extract(&components, &source);
                routes.extend(node::extract(&source));
                routes
            }
            Lang::Rust => axum::extract(&source),
            Lang::Go => go::extract(&source),
        };
        annotate(&source, lang, &mut routes);
        routes.sort_by_key(|route| route.line);
        routes
            .iter()
            .flat_map(|route| {
                route.risks.iter().map(move |risk| {
                    format!(
                        "{} {}: {:?}@{}",
                        method_token(route.method).to_ascii_uppercase(),
                        route.path,
                        risk.kind,
                        risk.line
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
}
