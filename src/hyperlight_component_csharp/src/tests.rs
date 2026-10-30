// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::collections::BTreeSet;
use std::path::PathBuf;

use hyperlight_component_util::{emit, host, rtypes, util};
use proc_macro2::{TokenStream, TokenTree};

use super::*;

const GUEST_WIT: &str = "../tests/rust_guests/witguest/guest.wit";

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
                    && !s.is_empty()
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
    let rust = util::read_wit_type(util::WitSource::Wit(GUEST_WIT.into()), None, |kebab, ct| {
        emit::run_state(false, false, |s| {
            rtypes::emit_toplevel(s, &kebab, ct);
            host::emit_toplevel(s, &kebab, ct);
        })
    });
    let mut rust_names = BTreeSet::new();
    string_literals(rust, &mut rust_names);

    let cs = generate_from_path(&PathBuf::from(GUEST_WIT), None, "Test").unwrap();
    let cs_names = call_names(&cs, "_caller.Call(")
        .into_iter()
        .chain(call_names(&cs, "registry.Register("))
        .collect::<BTreeSet<_>>();

    assert_eq!(rust_names, cs_names);
    assert!(cs_names.contains("test:wit/roundtrip#roundtrip-composite"));
    assert!(cs_names.contains("test:wit/host-resource#[constructor]testresource"));
    assert!(cs_names.contains("test:wit/host-resource#[method]testresource.append-char"));
    assert!(cs_names.contains("now"));
    assert!(cs_names.contains("run"));
}

#[test]
fn rejects_guest_resources() {
    let resource = generate_str(
        "package a:b; interface i { resource r; f: func(x: borrow<r>); } world w { export i; }",
    );
    let error = resource.unwrap_err().to_string();
    assert!(error.contains("resources the guest defines"), "{error}");
}

#[test]
fn names_host_resource_functions() {
    let cs = generate_str(
        "package a:b; \
         interface i { \
           resource r { constructor(); make: static func() -> r; get: func() -> u32; } \
           new-r: func() -> r; \
         } \
         world w { import i; export f: func(x: borrow<r>); use i.{r}; }",
    )
    .unwrap();
    for expected in [
        "public interface IR",
        "uint Get();",
        "IR NewR();",
        "IR NewR_();",
        "IR RMake();",
        "public sealed class WResources",
        "public static global::Test.WResources RegisterImports(",
        "public WComponent(global::Hyperlight.Component.IGuestCaller caller, global::Test.WResources resources)",
        "__scope.Commit();",
    ] {
        assert!(cs.contains(expected), "{expected}\n{cs}");
    }
}

#[test]
fn rejects_distinct_interfaces_with_one_name() {
    for wit in [
        "package a:b; interface i { record r { x: u32 } f: func() -> r; } \
         world w { import i; export i: interface { record r { x: string } f: func() -> r; } }",
        "package a:b; world w { \
           import io: interface { record p { v: u32 } f: func(x: p); } \
           export io: interface { record p { v: string } g: func() -> p; } }",
    ] {
        let error = generate_str(wit).unwrap_err().to_string();
        assert!(
            error.contains("clashes with another type"),
            "{wit}: {error}"
        );
    }
}

#[test]
fn rejects_classes_named_like_namespaces() {
    let error = generate_str(
        "package a:b; interface foo { f: func(); } \
         interface foo-exports { record r { x: u8 } g: func() -> r; } \
         world w { export foo; export foo-exports; }",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("FooExports"), "{error}");
}

#[test]
fn escapes_record_member_clone() {
    let cs = generate_str(
        "package a:b; interface i { record r { clone: bool } f: func(x: r); } world w { export i; }",
    )
    .unwrap();
    assert!(cs.contains("bool Clone_ {"), "{cs}");
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
fn rejects_empty_types() {
    for (decl, ty) in [
        ("", "tuple<>"),
        ("", "list<u8, 0>"),
        ("record e {}", "e"),
        ("flags e {}", "e"),
    ] {
        let wit = format!(
            "package a:b; interface i {{ {decl} f: func(x: {ty}); }} world w {{ export i; }}"
        );
        let error = generate_str(&wit).unwrap_err().to_string();
        assert!(error.contains("must not be empty"), "{wit}: {error}");
    }
}

#[test]
fn rejects_types_named_like_generated_classes() {
    let error = generate_str(
        "package a:b; world w { record w-component { x: u32 } export f: func(x: w-component); }",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("WComponent"), "{error}");

    let error = generate_str(
        "package test:wire; interface types { f: func(); } \
         world wire { record test { x: u32 } import types; export f: func(x: test); }",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("Test"), "{error}");
}
