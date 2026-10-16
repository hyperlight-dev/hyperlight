// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::collections::BTreeSet;
use std::path::PathBuf;

use hyperlight_component_util::{emit, host, rtypes, util};
use proc_macro2::{TokenStream, TokenTree};

use super::*;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/component_wire")
}

fn generate_str(wit: &str) -> Result<String, Error> {
    generate(WitSource::Inline(wit.to_string()), None, "Test")
}

/// String literals in `tokens` that can be wire names.
fn string_literals(tokens: TokenStream, out: &mut BTreeSet<String>) {
    for token in tokens {
        match token {
            TokenTree::Group(g) => string_literals(g.stream(), out),
            TokenTree::Literal(l) => {
                let l = l.to_string();
                if let Some(s) = l.strip_prefix('"').and_then(|l| l.strip_suffix('"'))
                    && !s.contains(' ')
                {
                    out.insert(s.to_string());
                }
            }
            _ => {}
        }
    }
}

/// The first string literal after each occurrence of `call`.
fn call_names(source: &str, call: &str) -> Vec<String> {
    source
        .match_indices(call)
        .map(|(i, _)| {
            let rest = &source[i + call.len()..];
            rest.split('"').nth(1).unwrap().to_string()
        })
        .collect()
}

#[test]
fn wire_names_match_rust_host_bindings() {
    let rust = util::read_wit_type(
        util::WitSource::Wit("../tests/component_wire/wire.wit".into()),
        None,
        |kebab, ct| {
            emit::run_state(false, false, |s| {
                rtypes::emit_toplevel(s, &kebab, ct);
                host::emit_toplevel(s, &kebab, ct);
            })
        },
    );
    let mut rust_names = BTreeSet::new();
    string_literals(rust, &mut rust_names);

    let cs = generate_from_path(&fixture_dir().join("wire.wit"), None, "Test").unwrap();
    let cs_names = call_names(&cs, "_caller.Call(")
        .into_iter()
        .chain(call_names(&cs, "registry.Register("))
        .collect::<BTreeSet<_>>();

    assert_eq!(rust_names, cs_names);
    assert!(cs_names.contains("test:wire/echo@0.1.0#echo-everything"));
    assert!(cs_names.contains("test:wire/host@0.1.0#log"));
    assert!(cs_names.contains("now"));
    assert!(cs_names.contains("run"));
}

#[test]
fn rejects_resources() {
    let resource = generate_str(
        "package a:b; interface i { resource r; f: func(x: borrow<r>); } world w { export i; }",
    );
    assert!(resource.unwrap_err().to_string().contains("resources"));
}

#[test]
#[should_panic(expected = "async")]
fn rejects_streams() {
    let _ = generate_str("package a:b; world w { export f: func(x: stream<u8>); }");
}

#[test]
#[should_panic(expected = "async")]
fn rejects_async_functions() {
    let _ = generate_str("package a:b; world w { export f: async func(); }");
}

#[test]
fn rejects_invalid_namespace() {
    let generate = |namespace| {
        generate(
            WitSource::Inline("package a:b; world w {}".to_string()),
            None,
            namespace,
        )
    };
    for namespace in ["", "A..B", "A.B-C", "A B", "A.1B", "A.class"] {
        assert!(generate(namespace).is_err(), "{namespace}");
    }
    assert!(generate("A.B_c").is_ok());
}

#[test]
fn rejects_more_than_32_flags() {
    let names = (0..33)
        .map(|i| format!("g{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let wit = format!(
        "package a:b; interface i {{ flags big {{ {names} }} f: func(x: big); }} world w {{ export i; }}"
    );
    let error = generate_str(&wit).unwrap_err().to_string();
    assert!(error.contains("more than 32"), "{error}");
}

#[test]
fn rejects_types_named_like_generated_classes() {
    let error = generate_str(
        "package a:b; world w { record w-component { x: u32 } export f: func(x: w-component); }",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("WComponent"), "{error}");
}
