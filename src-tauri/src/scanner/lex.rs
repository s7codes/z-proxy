//! Lexical helpers shared by the source extractors.
//!
//! This is not a parser. It is exactly as precise as route extraction needs: declarations
//! inside comments must be ignored, and call arguments must be delimited correctly when a
//! string literal contains a parenthesis. Everything operates on byte offsets so a match in
//! comment-masked text maps to the same line in the original file.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Js,
    Rust,
    Go,
}

/// Byte offset to 1-based line lookup.
pub struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    pub fn new(src: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(src.match_indices('\n').map(|(at, _)| at + 1));
        Self { starts }
    }

    pub fn line(&self, offset: usize) -> u32 {
        let line = self.starts.partition_point(|&start| start <= offset);
        u32::try_from(line).unwrap_or(u32::MAX)
    }
}

pub fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

pub fn skip_ws(src: &str, mut at: usize) -> usize {
    let bytes = src.as_bytes();
    while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    at
}

/// A source file prepared for extraction: comments masked, string literal spans recorded.
pub struct Source {
    /// Comment bytes replaced by spaces; offsets and lines match the original file.
    pub text: String,
    pub lines: LineIndex,
    strings: Vec<(usize, usize)>,
}

impl Source {
    pub fn new(src: &str, lang: Lang) -> Self {
        let (text, strings) = mask(src, lang);
        let lines = LineIndex::new(&text);
        Self {
            text,
            lines,
            strings,
        }
    }

    /// True when `at` lies inside a string literal: a call-shaped match there is fixture
    /// data or documentation (a test's embedded source, a doc example), not code.
    pub fn in_string(&self, at: usize) -> bool {
        self.string_span(at).is_some()
    }

    /// Byte span (quotes included) of the string literal containing `at`.
    pub fn string_span(&self, at: usize) -> Option<(usize, usize)> {
        let next = self.strings.partition_point(|&(start, _)| start <= at);
        let span = *self.strings.get(next.checked_sub(1)?)?;
        (at < span.1).then_some(span)
    }
}

/// Replaces every comment byte with a space (newlines kept) and records string literal spans.
fn mask(src: &str, lang: Lang) -> (String, Vec<(usize, usize)>) {
    let bytes = src.as_bytes();
    let mut out = bytes.to_vec();
    let mut strings = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let next = bytes.get(at + 1).copied();
        let end = match (bytes[at], next) {
            (b'/', Some(b'/')) => {
                let end = find_byte(bytes, at, b'\n').unwrap_or(bytes.len());
                blank(&mut out, at, end);
                end
            }
            (b'/', Some(b'*')) => {
                let end = find_seq(bytes, at + 2, b"*/").map_or(bytes.len(), |close| close + 2);
                blank(&mut out, at, end);
                end
            }
            _ => match literal_end(bytes, at, lang) {
                Some(end) => {
                    strings.push((at, end));
                    end
                }
                None => at + 1,
            },
        };
        at = end;
    }
    // Comment bytes are replaced as whole runs bounded by ASCII delimiters, so multi-byte
    // characters are never split and the buffer stays valid UTF-8.
    let text = String::from_utf8(out).unwrap_or_else(|_| src.to_owned());
    (text, strings)
}

/// Offset of the `)` matching the `(` at `open`.
pub fn matching_paren(src: &str, open: usize, lang: Lang) -> Option<usize> {
    if src.as_bytes().get(open) != Some(&b'(') {
        return None;
    }
    matching_bracket(src, open, lang)
}

/// Offset of the bracket closing the one at `open`, whichever kind it is. Brackets of every
/// kind count towards depth so a closure body or object literal inside a call does not end
/// it early.
pub fn matching_bracket(src: &str, open: usize, lang: Lang) -> Option<usize> {
    let bytes = src.as_bytes();
    let closer = match bytes.get(open)? {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        _ => return None,
    };
    let mut depth = 0usize;
    let mut at = open;
    while at < bytes.len() {
        match bytes[at] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return (bytes[at] == closer).then_some(at);
                }
            }
            _ => {
                if let Some(end) = literal_end(bytes, at, lang) {
                    at = end;
                    continue;
                }
            }
        }
        at += 1;
    }
    None
}

/// Reads a string literal whose value is fully static, resolving single-character escapes
/// (`\\`, `\/`, `\'`). Template literals with interpolation and strings containing line
/// breaks yield `None`: neither can be a static route path.
pub fn read_string(src: &str, at: usize, lang: Lang) -> Option<(String, usize)> {
    let bytes = src.as_bytes();
    let quote = *bytes.get(at)?;
    let accepted = match lang {
        Lang::Js => matches!(quote, b'\'' | b'"' | b'`'),
        Lang::Rust => quote == b'"',
        Lang::Go => matches!(quote, b'"' | b'`'),
    };
    if !accepted {
        return None;
    }
    let end = literal_end(bytes, at, lang)?;
    if end < at + 2 || bytes.get(end - 1) != Some(&quote) {
        return None;
    }
    let body = src.get(at + 1..end - 1)?;
    if quote == b'`' && lang == Lang::Js && body.contains("${") {
        return None;
    }
    // Go raw strings take backslashes literally.
    if quote == b'`' && lang == Lang::Go {
        return (!body.contains('\n')).then(|| (body.to_owned(), end));
    }
    let mut value = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\n' => return None,
            '\\' => match chars.next()? {
                'n' | 'r' | 't' | '0' | 'u' | 'x' => return None,
                escaped => value.push(escaped),
            },
            _ => value.push(ch),
        }
    }
    Some((value, end))
}

/// If a string, char or raw-string literal opens at `at`, the offset one past its end.
pub fn literal_end(bytes: &[u8], at: usize, lang: Lang) -> Option<usize> {
    let byte = *bytes.get(at)?;
    match (lang, byte) {
        (_, b'"') => Some(quoted_end(bytes, at, b'"', lang != Lang::Js)),
        (Lang::Js, b'\'') => Some(quoted_end(bytes, at, b'\'', false)),
        (Lang::Js, b'`') => Some(quoted_end(bytes, at, b'`', true)),
        (Lang::Go, b'`') => find_byte(bytes, at + 1, b'`').map(|close| close + 1),
        (Lang::Rust | Lang::Go, b'\'') => char_literal_end(bytes, at),
        (Lang::Rust, b'r') if at == 0 || !is_ident_byte(bytes[at - 1]) => raw_string_end(bytes, at),
        _ => None,
    }
}

/// Escape-aware scan to the closing quote. Single-line literals stop at a newline so one
/// unterminated quote cannot swallow the rest of the file.
fn quoted_end(bytes: &[u8], at: usize, quote: u8, multiline: bool) -> usize {
    let mut cursor = at + 1;
    while let Some(&byte) = bytes.get(cursor) {
        match byte {
            b'\\' => cursor += 2,
            b'\n' if !multiline => return cursor,
            _ if byte == quote => return cursor + 1,
            _ => cursor += 1,
        }
    }
    bytes.len()
}

/// `'a'`, `'\n'`, `'é'`; anything else starting with `'` in Rust is a lifetime.
fn char_literal_end(bytes: &[u8], at: usize) -> Option<usize> {
    let first = *bytes.get(at + 1)?;
    if first == b'\\' {
        let limit = (at + 14).min(bytes.len());
        return (at + 2..limit)
            .find(|&cursor| bytes[cursor] == b'\'')
            .map(|close| close + 1);
    }
    let width = match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    };
    (bytes.get(at + 1 + width) == Some(&b'\'')).then_some(at + 2 + width)
}

fn raw_string_end(bytes: &[u8], at: usize) -> Option<usize> {
    let mut cursor = at + 1;
    let mut hashes = 0;
    while bytes.get(cursor) == Some(&b'#') {
        hashes += 1;
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    let mut close = vec![b'"'];
    close.extend(std::iter::repeat_n(b'#', hashes));
    Some(find_seq(bytes, cursor + 1, &close).map_or(bytes.len(), |end| end + close.len()))
}

fn find_byte(bytes: &[u8], from: usize, needle: u8) -> Option<usize> {
    bytes
        .get(from..)?
        .iter()
        .position(|&byte| byte == needle)
        .map(|offset| from + offset)
}

fn find_seq(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from + offset)
}

fn blank(out: &mut [u8], from: usize, to: usize) {
    for byte in &mut out[from..to] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn masks_comments_but_not_strings() {
        let src = "a // app.get('/x', h)\nb /* app.post('/y', h) */ c \"// kept\"";
        let masked = Source::new(src, Lang::Js).text;
        assert_eq!(masked.len(), src.len());
        assert!(!masked.contains("app.get"));
        assert!(!masked.contains("app.post"));
        assert!(masked.contains("\"// kept\""));
        assert_eq!(masked.matches('\n').count(), 1);
    }

    #[test]
    fn masking_keeps_multibyte_comments_valid() {
        let src = "x // über – ünnep\ny";
        let masked = Source::new(src, Lang::Js).text;
        assert_eq!(masked.len(), src.len());
        assert!(masked.ends_with("\ny"));
    }

    #[test]
    fn paren_matching_skips_string_contents() {
        let src = r#"route("/a(b", get(h).post(|| async { ")" }))"#;
        let close = matching_paren(src, 5, Lang::Rust).unwrap();
        assert_eq!(close, src.len() - 1);
    }

    #[test]
    fn rust_lifetimes_are_not_char_literals() {
        let src = "f(x: &'a str, c: '(')";
        assert_eq!(matching_paren(src, 1, Lang::Rust), Some(src.len() - 1));
    }

    #[test]
    fn rust_raw_strings_are_skipped() {
        let src = r##"m(r#"(")"#)"##;
        assert_eq!(matching_paren(src, 1, Lang::Rust), Some(src.len() - 1));
    }

    #[test]
    fn reads_only_static_strings() {
        assert_eq!(
            read_string("'/users/:id'", 0, Lang::Js).map(|(s, _)| s),
            Some("/users/:id".to_owned())
        );
        assert_eq!(read_string("`/a/${b}`", 0, Lang::Js), None);
        assert_eq!(
            read_string("`/static`", 0, Lang::Js).map(|(s, _)| s),
            Some("/static".to_owned())
        );
        assert_eq!(
            read_string(r"'/a/:id(\\d+)'", 0, Lang::Js).map(|(s, _)| s),
            Some(r"/a/:id(\d+)".to_owned())
        );
        assert_eq!(read_string(r"'/a\nb'", 0, Lang::Js), None);
        assert_eq!(read_string("'/x'", 0, Lang::Rust), None);
    }

    #[test]
    fn records_string_spans() {
        let source = Source::new("a(\"x.route(\") // 'y'\nb", Lang::Js);
        assert!(source.in_string(3));
        assert!(!source.in_string(1));
        assert!(!source.in_string(18));
        assert_eq!(matching_bracket("{ f(\"}\") }", 0, Lang::Js), Some(9));
    }

    #[test]
    fn line_index_is_one_based() {
        let index = LineIndex::new("a\nbb\n\nc");
        assert_eq!(index.line(0), 1);
        assert_eq!(index.line(2), 2);
        assert_eq!(index.line(5), 3);
        assert_eq!(index.line(6), 4);
    }
}
