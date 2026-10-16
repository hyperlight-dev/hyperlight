// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Checks the encoding produced by `host_bindgen!` against byte vectors
//! that the C# binding tests in `src/tests/component_wire/csharp` also
//! check.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use hyperlight_common::component::Negative;
use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnValue};
use hyperlight_common::func::{ParameterTuple, SupportedReturnType};
use hyperlight_host::func::{HostFunction, Registerable};
use hyperlight_host::sandbox::Callable;

extern crate alloc;
mod bindings {
    hyperlight_component_macro::host_bindgen!(wit: "../tests/component_wire/wire.wit");
}

use bindings::Extra;
use bindings::test::wire::types::{
    Color, Everything, FullFlags, ManyFlags, Permissions, Point, Shape,
};
use bindings::test::wire::{Echo, Host, Types, WireExports, WireImports};

/// A `FullFlags` with only the named flags set.
macro_rules! full_flags {
    ($($set:ident),*) => {{
        #[allow(unused_mut)]
        let mut flags = FullFlags {
            h0: false, h1: false, h2: false, h3: false, h4: false, h5: false, h6: false, h7: false, h8: false, h9: false, h10: false, h11: false, h12: false, h13: false, h14: false, h15: false, h16: false, h17: false, h18: false, h19: false, h20: false, h21: false, h22: false, h23: false, h24: false, h25: false, h26: false, h27: false, h28: false, h29: false, h30: false, h31: false
        };
        $(flags.$set = true;)*
        flags
    }};
}

struct Imports;

impl Types<Negative> for Imports {}

impl Host<Negative, Point> for Imports {
    fn log(&mut self, _message: String, _event: u8) {}

    fn add(&mut self, left: Point, right: Point) -> Point {
        Point {
            x: left.x + right.x,
            y: left.y + right.y,
        }
    }
}

impl WireImports<Negative> for Imports {
    type Types = Self;
    fn types(&mut self) -> impl core::borrow::BorrowMut<Self> {
        self
    }
    type Host = Self;
    fn host(&mut self) -> impl core::borrow::BorrowMut<Self> {
        self
    }
    fn now(&mut self) -> u64 {
        7
    }
}

type ErasedHostFunction = Box<dyn FnMut(Vec<Vec<u8>>) -> Vec<u8>>;

/// Host functions by wire name.
#[derive(Default)]
struct Registry(HashMap<String, ErasedHostFunction>);

impl Registerable for Registry {
    fn register_host_function<Args: ParameterTuple, Output: SupportedReturnType>(
        &mut self,
        name: &str,
        hf: impl Into<HostFunction<Output, Args>>,
    ) -> hyperlight_host::Result<()> {
        let hf = hf.into();
        self.0.insert(
            name.to_string(),
            Box::new(move |args| {
                let args = args.into_iter().map(ParameterValue::VecBytes).collect();
                let result = hf.call(Args::from_value(args).unwrap()).unwrap();
                match result.into_value() {
                    ReturnValue::VecBytes(bytes) => bytes,
                    other => panic!("unexpected result {other:?}"),
                }
            }),
        );
        Ok(())
    }
}

/// A guest whose exports return their arguments.
#[derive(Default)]
struct Guest {
    args: Vec<Vec<u8>>,
}

impl Callable for Guest {
    fn call<Output: SupportedReturnType>(
        &mut self,
        func_name: &str,
        args: impl ParameterTuple,
    ) -> hyperlight_host::Result<Output> {
        self.args = args
            .into_value()
            .into_iter()
            .map(|arg| match arg {
                ParameterValue::VecBytes(bytes) => bytes,
                other => panic!("unexpected argument {other:?}"),
            })
            .collect();
        let result = match func_name {
            "test:wire/echo@0.1.0#no-args" => 42u32.to_le_bytes().to_vec(),
            "test:wire/echo@0.1.0#no-result" => Vec::new(),
            // ok(input)
            "run" => [&[0][..], &self.args[0]].concat(),
            // The arguments concatenated are the encoding of their tuple.
            _ => self.args.concat(),
        };
        Ok(Output::from_value(ReturnValue::VecBytes(result))?)
    }
}

type Sandbox = bindings::WireSandbox<Imports, Guest>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn string(s: &str) -> Vec<u8> {
    [&(s.len() as u32).to_le_bytes()[..], s.as_bytes()].concat()
}

fn point(x: i32, y: i32) -> Vec<u8> {
    [x.to_le_bytes(), y.to_le_bytes()].concat()
}

#[derive(Default)]
struct Vectors(BTreeMap<String, String>);

impl Vectors {
    fn add(&mut self, name: &str, bytes: &[u8]) {
        assert!(
            self.0.insert(name.to_string(), hex(bytes)).is_none(),
            "{name}"
        );
    }

    fn add_args(&mut self, name: &str, args: &[Vec<u8>]) {
        match args {
            [arg] => self.add(name, arg),
            _ => {
                for (i, arg) in args.iter().enumerate() {
                    self.add(&format!("{name}.{i}"), arg);
                }
            }
        }
    }

    /// Call an export that returns its argument, check that decoding
    /// and re-encoding the result reproduces the argument bytes, and
    /// record them.
    fn echo<T>(
        &mut self,
        sb: &mut Sandbox,
        name: &str,
        call: impl Fn(&mut Sandbox, T) -> T,
        value: T,
    ) {
        let result = call(sb, value);
        let args = sb.sb.args.clone();
        call(sb, result);
        assert_eq!(args, sb.sb.args, "{name}");
        self.add_args(name, &args);
    }
}

fn everything_full() -> Everything {
    Everything {
        b: true,
        u8v: 0xab,
        s8v: -2,
        u16v: 0xbeef,
        s16v: -300,
        u32v: 0xdead_beef,
        s32v: -70_000,
        u64v: 0x0123_4567_89ab_cdef,
        s64v: -5_000_000_000,
        f32v: 1.5,
        f64v: -2.25,
        c: '🎈',
        s: "héllo".into(),
        bytes: vec![1, 2, 3],
        points: vec![Point { x: 1, y: 2 }, Point { x: -3, y: 4 }],
        nested: vec![vec!["a".into(), "bc".into()], vec![]],
        fixed_bytes: [7, 8, 9],
        fixed_points: [Point { x: 5, y: 6 }, Point { x: 7, y: 8 }],
        maybe: Some("m".into()),
        maybe_num: Some(9),
        maybe_maybe: Some(Some("mm".into())),
        res: Ok(Point { x: 10, y: 11 }),
        res_unit: Ok(()),
        res_empty: Ok(()),
        tup: ("t".into(), 12, Point { x: 13, y: 14 }),
        tup8: (1, 2, 3, 4, 5, 6, 7, 0x0809),
        maybe_maybe_num: Some(Some(17)),
        shape: Shape::Rect(Point { x: 15, y: 16 }),
        color: Color::Green,
        perms: Permissions {
            read: true,
            write: false,
            exec: true,
        },
        many: ManyFlags {
            f0: true,
            f1: false,
            f2: false,
            f3: false,
            f4: false,
            f5: false,
            f6: false,
            f7: false,
            f8: false,
            f9: true,
        },
        full: full_flags!(h0, h31),
    }
}

fn everything_alt() -> Everything {
    Everything {
        b: false,
        u8v: u8::MAX,
        s8v: i8::MIN,
        u16v: u16::MAX,
        s16v: i16::MIN,
        u32v: u32::MAX,
        s32v: i32::MIN,
        u64v: u64::MAX,
        s64v: i64::MIN,
        f32v: -0.0,
        f64v: f64::MAX,
        c: 'a',
        s: String::new(),
        bytes: vec![],
        points: vec![],
        nested: vec![],
        fixed_bytes: [0, 0, 0],
        fixed_points: [Point { x: 0, y: 0 }, Point { x: 0, y: 0 }],
        maybe: None,
        maybe_num: None,
        maybe_maybe: Some(None),
        res: Err("bad".into()),
        res_unit: Err("e".into()),
        res_empty: Err(()),
        tup: (String::new(), 0, Point { x: 0, y: 0 }),
        tup8: (u8::MAX, 0, 0, 0, 0, 0, 0, u16::MAX),
        maybe_maybe_num: Some(None),
        shape: Shape::Named("n".into()),
        color: Color::Blue,
        perms: Permissions {
            read: false,
            write: false,
            exec: false,
        },
        many: ManyFlags {
            f0: false,
            f1: false,
            f2: false,
            f3: false,
            f4: false,
            f5: false,
            f6: false,
            f7: false,
            f8: true,
            f9: false,
        },
        full: full_flags!(),
    }
}

fn everything_none() -> Everything {
    Everything {
        maybe_maybe: None,
        maybe_maybe_num: None,
        full: full_flags!(
            h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18,
            h19, h20, h21, h22, h23, h24, h25, h26, h27, h28, h29, h30, h31
        ),
        shape: Shape::None,
        color: Color::Red,
        perms: Permissions {
            read: false,
            write: true,
            exec: false,
        },
        ..everything_alt()
    }
}

#[test]
fn rust_bindings_match_wire_vectors() {
    let mut registry = Registry::default();
    let rt = bindings::register_host_functions(&mut registry, Imports).unwrap();
    let mut sb = Sandbox {
        sb: Guest::default(),
        rt,
    };
    let mut v = Vectors::default();

    let echo_everything = |sb: &mut Sandbox, x| sb.echo_everything(x).unwrap();
    v.echo(
        &mut sb,
        "everything-full",
        echo_everything,
        everything_full(),
    );
    v.echo(&mut sb, "everything-alt", echo_everything, everything_alt());
    v.echo(
        &mut sb,
        "everything-none",
        echo_everything,
        everything_none(),
    );

    let echo_shape = |sb: &mut Sandbox, x| sb.echo_shape(x).unwrap();
    v.echo(&mut sb, "shape-none", echo_shape, Shape::None);
    v.echo(&mut sb, "shape-circle", echo_shape, Shape::Circle(3));
    v.echo(
        &mut sb,
        "shape-rect",
        echo_shape,
        Shape::Rect(Point { x: 1, y: -1 }),
    );
    v.echo(&mut sb, "shape-named", echo_shape, Shape::Named("x".into()));
    v.echo(
        &mut sb,
        "shape-path",
        echo_shape,
        Shape::Path(vec![Point { x: 1, y: 2 }, Point { x: 3, y: 4 }]),
    );

    let ping = |sb: &mut Sandbox, x| sb.extra().ping(x).unwrap();
    v.echo(&mut sb, "extra-ping", ping, 0xa5);

    let echo_string = |sb: &mut Sandbox, x| sb.echo_string(x).unwrap();
    v.echo(&mut sb, "string", echo_string, "héllo, 世界 🎈".to_string());

    let two_args = |sb: &mut Sandbox, (a, b)| sb.two_args(a, b).unwrap();
    v.echo(&mut sb, "two-args", two_args, (5, "five".to_string()));

    assert_eq!(sb.no_args().unwrap(), 42);
    assert!(sb.sb.args.is_empty());

    sb.no_result(9).unwrap();
    v.add_args("no-result", &sb.sb.args.clone());

    assert_eq!(sb.run("go".into()).unwrap(), Ok("go".to_string()));
    v.add_args("run", &sb.sb.args.clone());

    let mut host = |name: &str, args: Vec<Vec<u8>>| (registry.0.get_mut(name).unwrap())(args);
    let left = point(3, -4);
    let right = point(10, 20);
    let sum = host(
        "test:wire/host@0.1.0#add",
        vec![left.clone(), right.clone()],
    );
    assert_eq!(sum, point(13, 16));
    v.add_args("host-add", &[left, right]);
    v.add("host-add.result", &sum);

    let log = host("test:wire/host@0.1.0#log", vec![string("hi"), vec![2]]);
    assert!(log.is_empty());
    let now = host("now", vec![]);
    assert_eq!(now, 7u64.to_le_bytes());
    v.add("now.result", &now);

    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/component_wire/vectors.txt");
    let mut generated = String::from(
        "# Encodings checked by src/hyperlight_host/tests/component_wire_test.rs and\n\
         # src/tests/component_wire/csharp. Regenerate with\n\
         # HYPERLIGHT_BLESS=1 cargo test -p hyperlight-host --test component_wire_test\n",
    );
    for (name, bytes) in &v.0 {
        generated.push_str(&format!("{name} {bytes}\n"));
    }
    if std::env::var_os("HYPERLIGHT_BLESS").is_some() {
        std::fs::write(&path, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap()
        .replace("\r\n", "\n");
    assert!(
        committed == generated,
        "{} is out of date. Rerun with HYPERLIGHT_BLESS=1 to update it.",
        path.display()
    );
}
