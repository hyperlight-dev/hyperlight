/*
Copyright 2025 The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

//! Just enough component parsing support to get at the actual types

use wasmparser::Payload::{
    ComponentAliasSection, ComponentExportSection, ComponentTypeSection, Version,
};
use wasmparser::{
    ComponentAlias, ComponentExternalKind, ComponentOuterAliasKind, ComponentType,
    ComponentTypeRef, Payload,
};

use crate::etypes::{Component, Ctx, Defined};

/// From [`wasmparser::ComponentExport`], elaborate a deftype_e as per
/// the specification.
fn raw_type_export_type<'p, 'a, 'c>(
    ctx: &'c Ctx<'p, 'a>,
    ce: &'c wasmparser::ComponentExport<'a>,
) -> &'c Defined<'a> {
    match ce.ty {
        Some(ComponentTypeRef::Component(n)) => match ctx.types.get(n as usize) {
            Some(t) => t,
            None => {
                panic!("malformed component type export: ascription does not refer to a type");
            }
        },
        Some(_) => {
            panic!(
                "malformed component type export: ascription does not refer to a component type"
            );
        }
        None => match ctx.types.get(ce.index as usize) {
            Some(t) => t,
            None => {
                panic!("malformed component type export: does not refer to a type");
            }
        },
    }
}

/// Find the last exported type in a component, since in wasm-encoded
/// WIT this is typically the main world to use.  This is a very
/// special case that just lets us pull a type out of a value-level
///
/// Precondition: The given iterator is
/// - a component, whose
/// - encoding version is 0xd exactly, and who
/// - does not contain any value-level aliases, and whose
/// - final export is a component type
///
/// Anything that is a "binary-encoded WIT" produced by a recent
/// toolchain should satisfy this. On violation, this function will
/// panic with an error message.
///
/// The reason we look for the last export is that the WIT binary
/// encoding encodes any instance type imported/exported from the main
/// component (a/k/a WIT world) as a type export, followed by a final
/// type export for the type of the main component/world.
///
/// TODO: Allow the user to specify a specific export to use (or a WIT
/// world name), since current WIT tooling can generate encoded
/// packages with multiple component types in them.
///
/// TODO: Encode even more assumptions about WIT package structure
/// (which are already there in rtypes/host/guest) and allow looking
/// for a specific named world, instead of simply grabbing the last
/// export.
pub fn read_component_single_exported_type<'a>(
    items: impl Iterator<Item = wasmparser::Result<Payload<'a>>>,
    world_name: Option<String>,
) -> Component<'a> {
    let mut ctx = Ctx::new(None, false);
    let mut selected_type_idx = None;
    for x in items {
        match x {
            Ok(Version { num, encoding, .. }) => {
                if encoding != wasmparser::Encoding::Component {
                    panic!("wasm file is not a component")
                }
                if num != 0xd {
                    panic!("unknown component encoding version 0x{:x}\n", num);
                }
            }
            Ok(ComponentTypeSection(ts)) => {
                for t in ts {
                    match t {
                        Ok(ComponentType::Component(ct)) => {
                            let ct_ = ctx.elab_component(&ct);
                            ctx.types.push(Defined::Component(ct_.unwrap()));
                        }
                        _ => panic!("non-component type"),
                    }
                }
            }
            Ok(ComponentExportSection(es)) => {
                for e in es {
                    match e {
                        Err(_) => panic!("invalid export section"),
                        Ok(ce) => {
                            if ce.kind == ComponentExternalKind::Type {
                                ctx.types.push(raw_type_export_type(&ctx, &ce).clone());

                                // picks the world index if world_name is passed in the proc_macro
                                // else picks the index of last type, exported by core module
                                if let Some(world) = world_name.as_ref() {
                                    let name = ce.name.0;
                                    if name.eq_ignore_ascii_case(world) {
                                        selected_type_idx = Some(ctx.types.len() - 1);
                                    }
                                } else {
                                    selected_type_idx = Some(ctx.types.len() - 1);
                                }
                            }
                        }
                    }
                }
            }
            Ok(ComponentAliasSection(r#as)) => {
                for a in r#as {
                    match a {
                        Ok(ComponentAlias::InstanceExport {
                            kind: ComponentExternalKind::Type,
                            ..
                        })
                        | Ok(ComponentAlias::Outer {
                            kind: ComponentOuterAliasKind::Type,
                            ..
                        }) => {
                            panic!("Component outer type aliases are not supported")
                        }
                        // Anything else doesn't affect the index
                        // space that we are interested in, so we can
                        // safely ignore
                        _ => {}
                    }
                }
            }

            // No other component section should be terribly relevant
            // for us.  We would not generally expect to find them in
            // a file that just represents a type like this, but it
            // seems like there are/may be a whole bunch of debugging
            // custom sections, etc that might show up, so for now
            // let's just ignore anything.
            _ => {}
        }
    }

    match selected_type_idx {
        Some(n) => match ctx.types.into_iter().nth(n) {
            Some(Defined::Component(c)) => c,
            _ => panic!("final export is not component"),
        },
        None => match &world_name {
            Some(name) => panic!("world '{}' not found in component", name),
            None => panic!("no exported type"),
        },
    }
}
