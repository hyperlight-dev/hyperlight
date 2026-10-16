// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! C# identifier and source formatting helpers.

const KEYWORDS: &[&str] = &[
    "abstract",
    "as",
    "base",
    "bool",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "checked",
    "class",
    "const",
    "continue",
    "decimal",
    "default",
    "delegate",
    "do",
    "double",
    "else",
    "enum",
    "event",
    "explicit",
    "extern",
    "false",
    "finally",
    "fixed",
    "float",
    "for",
    "foreach",
    "goto",
    "if",
    "implicit",
    "in",
    "int",
    "interface",
    "internal",
    "is",
    "lock",
    "long",
    "namespace",
    "new",
    "null",
    "object",
    "operator",
    "out",
    "override",
    "params",
    "private",
    "protected",
    "public",
    "readonly",
    "ref",
    "return",
    "sbyte",
    "sealed",
    "short",
    "sizeof",
    "stackalloc",
    "static",
    "string",
    "struct",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "uint",
    "ulong",
    "unchecked",
    "unsafe",
    "ushort",
    "using",
    "virtual",
    "void",
    "volatile",
    "while",
];

/// Members every C# type inherits, plus members synthesized for
/// records. A generated member with one of these names would clash.
const RESERVED_MEMBERS: &[&str] = &[
    "Deconstruct",
    "EqualityContract",
    "Equals",
    "Finalize",
    "GetHashCode",
    "GetType",
    "MemberwiseClone",
    "PrintMembers",
    "ToString",
];

/// `foo-bar` to `FooBar`.
pub(super) fn pascal(kebab: &str) -> String {
    kebab
        .split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect(),
                None => String::new(),
            }
        })
        .collect()
}

/// `foo-bar` to `fooBar`, escaped if it is a keyword.
pub(super) fn camel(kebab: &str) -> String {
    let pascal = pascal(kebab);
    let mut chars = pascal.chars();
    let name: String = match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => String::new(),
    };
    if KEYWORDS.contains(&name.as_str()) {
        format!("@{name}")
    } else {
        name
    }
}

/// A member name of type `enclosing` that does not clash with the
/// type name or an inherited member.
pub(super) fn member(kebab: &str, enclosing: &str) -> String {
    let name = pascal(kebab);
    if name == enclosing || RESERVED_MEMBERS.contains(&name.as_str()) {
        format!("{name}_")
    } else {
        name
    }
}

/// The nested type name of a variant case, which must not clash with
/// the `Match` and `Switch` methods generated on the variant.
pub(super) fn case(kebab: &str, enclosing: &str) -> String {
    let name = member(kebab, enclosing);
    if name == "Match" || name == "Switch" {
        format!("{name}_")
    } else {
        name
    }
}

/// A C# string literal.
pub(super) fn string_literal(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Indented C# source text.
#[derive(Default)]
pub(super) struct Src {
    out: String,
    indent: usize,
}

impl Src {
    pub(super) fn line(&mut self, line: impl AsRef<str>) {
        let line = line.as_ref();
        if !line.is_empty() {
            for _ in 0..self.indent {
                self.out.push_str("    ");
            }
            self.out.push_str(line);
        }
        self.out.push('\n');
    }

    pub(super) fn open(&mut self) {
        self.line("{");
        self.indent += 1;
    }

    pub(super) fn close(&mut self) {
        self.close_with("}");
    }

    pub(super) fn close_with(&mut self, line: &str) {
        self.indent -= 1;
        self.line(line);
    }

    /// Run `f` one indentation level deeper.
    pub(super) fn indent_lines(&mut self, f: impl FnOnce(&mut Self)) {
        self.indent += 1;
        f(self);
        self.indent -= 1;
    }

    /// Emit WIT documentation as an XML doc comment.
    pub(super) fn docs(&mut self, docs: &wit_parser::Docs) {
        let Some(contents) = &docs.contents else {
            return;
        };
        self.line("/// <summary>");
        for line in contents.lines() {
            let line = line
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            self.line(format!("/// {line}").trim_end());
        }
        self.line("/// </summary>");
    }

    /// Append `other`, indented to the current level.
    pub(super) fn append(&mut self, other: Src) {
        for line in other.out.lines() {
            self.line(line);
        }
    }

    pub(super) fn into_string(self) -> String {
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers() {
        assert_eq!(pascal("on-request"), "OnRequest");
        assert_eq!(pascal("flag0a"), "Flag0a");
        assert_eq!(pascal("http-URL"), "HttpURL");
        assert_eq!(camel("query-string"), "queryString");
        assert_eq!(camel("string"), "@string");
        assert_eq!(member("to-string", "Foo"), "ToString_");
        assert_eq!(member("foo", "Foo"), "Foo_");
        assert_eq!(case("match", "Foo"), "Match_");
        assert_eq!(case("switch", "Foo"), "Switch_");
        assert_eq!(case("matches", "Foo"), "Matches");
        assert_eq!(string_literal("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }
}
