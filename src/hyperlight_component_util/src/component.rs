//! Just enough component parsing support to get at the actual types

use wasmparser::Payload::{ComponentExportSection, ComponentTypeSection, Version};
use wasmparser::{ComponentExternalKind, ComponentType, ComponentTypeRef, Payload};

use crate::etypes::{Component, Ctx, Defined};

fn raw_type_export_type<'p, 'a, 'c>(
    ctx: &'c Ctx<'p, 'a>,
    ce: &'c wasmparser::ComponentExport<'a>,
) -> &'c Defined<'a> {
    match ce.ty {
        Some(ComponentTypeRef::Component(n)) => match ctx.types.iter().nth(n as usize) {
            Some(t) => return t,
            t => panic!("bad component type 1 {:?}", t),
        },
        None => match ctx.types.iter().nth(ce.index as usize) {
            Some(t) => return &t,
            t => panic!("bad component type 2 {:?}", t),
        },
        _ => panic!("non-component ascribed type"),
    }
}

pub fn read_component_single_exported_type<'a>(
    items: impl Iterator<Item = wasmparser::Result<Payload<'a>>>,
) -> Component<'a> {
    let mut ctx = Ctx::new(None, false);
    let mut last_idx = None;
    for x in items {
        match x {
            Ok(Version { .. }) => (),
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
                                last_idx = Some(ctx.types.len());
                                ctx.types.push(raw_type_export_type(&ctx, &ce).clone());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    match last_idx {
        None => panic!("no exported type"),
        Some(n) => match ctx.types.into_iter().nth(n) {
            Some(Defined::Component(c)) => c,
            _ => panic!("final export is not component"),
        },
    }
}
