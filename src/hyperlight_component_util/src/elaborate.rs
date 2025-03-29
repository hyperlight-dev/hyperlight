use wasmparser::{
    ComponentAlias, ComponentDefinedType, ComponentExternalKind, ComponentFuncResult,
    ComponentFuncType, ComponentOuterAliasKind, ComponentType, ComponentTypeDeclaration,
    ComponentTypeRef, ComponentValType, CompositeInnerType, CoreType, ExternalKind,
    InstanceTypeDeclaration, ModuleTypeDeclaration, OuterAliasKind, PrimitiveValType, TypeBounds,
    TypeRef,
};

use crate::etypes::{
    self, BoundedTyvar, Component, CoreDefined, CoreExportDecl, CoreExternDesc, CoreModule,
    CoreOrComponentExternDesc, Ctx, Defined, ExternDecl, ExternDesc, FloatWidth, Func, Handleable,
    Instance, IntWidth, Name, Param, QualifiedInstance, RecordField, Resource, ResourceId,
    TypeBound, Tyvar, Value, VariantCase,
};
use crate::structure::{CoreSort, Sort};
use crate::substitute::{self, Substitution, Unvoidable};
use crate::tv::ResolvedTyvar;
use crate::wf;

// Basic utility conversion functions
fn sort_matches_core_ed<'a>(sort: Sort, ed: &CoreExternDesc) {
    match (sort, ed) {
        (Sort::Core(CoreSort::Func), CoreExternDesc::Func(_)) => (),
        (Sort::Core(CoreSort::Table), CoreExternDesc::Table(_)) => (),
        (Sort::Core(CoreSort::Memory), CoreExternDesc::Memory(_)) => (),
        (Sort::Core(CoreSort::Global), CoreExternDesc::Global(_)) => (),
        _ => panic!("sort does not match core extern descriptor"),
    }
}

fn external_kind(k: ExternalKind) -> Sort {
    match k {
        ExternalKind::Func => Sort::Core(CoreSort::Func),
        ExternalKind::Table => Sort::Core(CoreSort::Table),
        ExternalKind::Memory => Sort::Core(CoreSort::Memory),
        ExternalKind::Global => Sort::Core(CoreSort::Global),
        ExternalKind::Tag => panic!("core type tags are not supported"),
    }
}

fn sort_matches_ed<'a>(sort: Sort, ed: &ExternDesc<'a>) {
    match (sort, ed) {
        (Sort::Core(CoreSort::Module), ExternDesc::CoreModule(_)) => (),
        (Sort::Func, ExternDesc::Func(_)) => (),
        (Sort::Type, ExternDesc::Type(_)) => (),
        (Sort::Instance, ExternDesc::Instance(_)) => (),
        (Sort::Component, ExternDesc::Component(_)) => (),
        _ => panic!("sort does not match extern descriptor"),
    }
}

fn component_external_kind(k: ComponentExternalKind) -> Sort {
    match k {
        ComponentExternalKind::Module => Sort::Core(CoreSort::Module),
        ComponentExternalKind::Func => Sort::Func,
        ComponentExternalKind::Value => Sort::Value,
        ComponentExternalKind::Type => Sort::Type,
        ComponentExternalKind::Instance => Sort::Instance,
        ComponentExternalKind::Component => Sort::Component,
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum Error<'a> {
    InvalidOuterAlias(substitute::InnerizeError),
    IllFormedOuterAlias(wf::Error<'a>),
    ResourceInDeclarator,
    HandleToNonResource,
    ValTypeRefToNonVal(Defined<'a>),
    ClosingError(substitute::ClosingError),
}
impl<'a> From<substitute::ClosingError> for Error<'a> {
    fn from(e: substitute::ClosingError) -> Error<'a> {
        Error::ClosingError(e)
    }
}

// Elaboration

impl<'p, 'a> Ctx<'p, 'a> {
    pub fn elab_component<'c>(
        &'c mut self,
        decls: &[ComponentTypeDeclaration<'a>],
    ) -> Result<Component<'a>, Error<'a>> {
        let mut ctx = Ctx::new(Some(self), false);
        let mut imports = Vec::new();
        let mut exports = Vec::new();
        for decl in decls {
            let (import, export) = ctx.elab_component_decl(decl)?;
            if let Some(import) = import {
                imports.push(import);
            }
            if let Some(export) = export {
                exports.push(export);
            }
        }
        ctx.finish_component(&imports, &exports)
    }

    fn elab_core_module_decl<'c>(
        &'c mut self,
        decl: &ModuleTypeDeclaration<'a>,
    ) -> (Option<wasmparser::Import<'a>>, Option<CoreExportDecl<'a>>) {
        match decl {
            ModuleTypeDeclaration::Import(i) => (Some(i.clone()), None),
            ModuleTypeDeclaration::Type(rg) => {
                let ct = self.elab_core_type_rec(rg);
                self.core.types.push(ct);
                (None, None)
            },
            ModuleTypeDeclaration::OuterAlias {
                kind: OuterAliasKind::Type,
                count, index
            } => {
                let ct = self.parents().nth(*count as usize).unwrap()
                    .core.types[*index as usize].clone();
                self.core.types.push(ct);
                (None, None)
            }
            ModuleTypeDeclaration::Export { name, ty } => (None, Some(CoreExportDecl {
                name: Name { name: *name },
                desc: match ty {
                    TypeRef::Func(n) => match &self.core.types[*n as usize] {
                        CoreDefined::Func(ft) => CoreExternDesc::Func(ft.clone()),
                        _ => panic!("internal invariant violation: WasmParser function TypeRef refers to non-function"),
                    },
                    TypeRef::Table(tt) => CoreExternDesc::Table(*tt),
                    TypeRef::Memory(mt) => CoreExternDesc::Memory(*mt),
                    TypeRef::Global(gt) => CoreExternDesc::Global(*gt),
                    TypeRef::Tag(_) => panic!("core type tags are not supported"),
                },
            })),
        }
    }

    fn elab_core_module<'c>(&'c mut self, decls: &[ModuleTypeDeclaration<'a>]) -> CoreModule<'a> {
        let mut ctx = Ctx::new(Some(self), false);
        let mut imports = Vec::new();
        let mut exports = Vec::new();
        for decl in decls {
            let (import, export) = ctx.elab_core_module_decl(decl);
            if let Some(import) = import {
                imports.push(import)
            }
            if let Some(export) = export {
                exports.push(export)
            }
        }
        CoreModule {
            _imports: imports,
            _exports: exports,
        }
    }

    fn elab_core_type_rec<'c>(&'c mut self, rg: &wasmparser::RecGroup) -> CoreDefined<'a> {
        match &rg.types().nth(0).unwrap().composite_type.inner {
            CompositeInnerType::Func(ft) => CoreDefined::Func(ft.clone()),
            _ => panic!("GC core types are not presently supported"),
        }
    }

    fn elab_core_type<'c>(&'c mut self, ct: &wasmparser::CoreType<'a>) -> CoreDefined<'a> {
        match ct {
            CoreType::Rec(rg) => self.elab_core_type_rec(rg),
            CoreType::Module(ds) => CoreDefined::Module(self.elab_core_module(&ds)),
        }
    }

    fn resolve_alias<'c>(
        &'c mut self,
        alias: &ComponentAlias<'a>,
    ) -> Result<CoreOrComponentExternDesc<'a>, Error<'a>> {
        match alias {
            ComponentAlias::InstanceExport {
                kind,
                instance_index,
                name,
            } => {
                let it = &self.instances[*instance_index as usize];
                let ed = &it
                    .exports
                    .iter()
                    .find(|e| e.kebab_name == *name)
                    .unwrap()
                    .desc;
                let sort = component_external_kind(*kind);
                sort_matches_ed(sort, ed);
                Ok(CoreOrComponentExternDesc::Component(ed.clone()))
            }
            ComponentAlias::CoreInstanceExport {
                kind,
                instance_index,
                name,
            } => {
                let it = &self.core.instances[*instance_index as usize];
                let ed = &it
                    .exports
                    .iter()
                    .find(|e| e.name.name == *name)
                    .unwrap()
                    .desc;
                let sort = external_kind(*kind);
                sort_matches_core_ed(sort, ed);
                Ok(CoreOrComponentExternDesc::Core(ed.clone()))
            }
            ComponentAlias::Outer { kind, count, index } => {
                if *kind != ComponentOuterAliasKind::Type {
                    panic!("In types, only outer type aliases are allowed");
                }
                // Walk through each of the contexts between us and
                // the targeted type, so that we can innerize each one
                let mut ctxs = self.parents().take(*count as usize + 1).collect::<Vec<_>>();
                ctxs.reverse();
                let mut target_type = ctxs[0].types[*index as usize].clone();
                let mut ob_crossed = false;
                for ctxs_ in ctxs.windows(2) {
                    ob_crossed |= ctxs_[1].outer_boundary;
                    let sub = substitute::Innerize::new(ctxs_[0], ctxs_[1].outer_boundary);
                    target_type = sub
                        .defined(&target_type)
                        .map_err(Error::InvalidOuterAlias)?;
                }
                if ob_crossed {
                    self.wf_defined(wf::DefinedTypePosition::export(), &target_type)
                        .map_err(Error::IllFormedOuterAlias)?;
                }
                Ok(CoreOrComponentExternDesc::Component(ExternDesc::Type(
                    target_type,
                )))
            }
        }
    }

    fn add_core_ed<'c>(&'c mut self, ed: CoreExternDesc) {
        match ed {
            CoreExternDesc::Func(ft) => self.core.funcs.push(ft),
            CoreExternDesc::Table(tt) => self.core.tables.push(tt),
            CoreExternDesc::Memory(mt) => self.core.mems.push(mt),
            CoreExternDesc::Global(gt) => self.core.globals.push(gt),
        }
    }

    fn add_ed<'c>(&'c mut self, ed: &ExternDesc<'a>) {
        match ed {
            ExternDesc::CoreModule(cmd) => self.core.modules.push(cmd.clone()),
            ExternDesc::Func(ft) => self.funcs.push(ft.clone()),
            ExternDesc::Type(dt) => self.types.push(dt.clone()),
            ExternDesc::Instance(it) => self.instances.push(it.clone()),
            ExternDesc::Component(ct) => self.components.push(ct.clone()),
        }
    }

    fn add_core_or_component_ed<'c>(&'c mut self, ed: CoreOrComponentExternDesc<'a>) {
        match ed {
            CoreOrComponentExternDesc::Core(ced) => self.add_core_ed(ced),
            CoreOrComponentExternDesc::Component(ed) => self.add_ed(&ed),
        }
    }

    fn elab_value<'c>(&'c mut self, ctr: &ComponentValType) -> Result<Value<'a>, Error<'a>> {
        match ctr {
            ComponentValType::Type(n) => match &self.types[*n as usize] {
                Defined::Value(vt) => Ok(vt.clone()),
                dt @ Defined::Handleable(Handleable::Var(tv)) => match self.resolve_tyvar(tv) {
                    ResolvedTyvar::Definite(Defined::Value(vt)) => {
                        Ok(Value::Var(Some(tv.clone()), Box::new(vt)))
                    }
                    _ => Err(Error::ValTypeRefToNonVal(dt.clone())),
                },
                dt => Err(Error::ValTypeRefToNonVal(dt.clone())),
            },
            ComponentValType::Primitive(pt) => Ok(match pt {
                PrimitiveValType::Bool => Value::Bool,
                PrimitiveValType::S8 => Value::S(IntWidth::I8),
                PrimitiveValType::U8 => Value::U(IntWidth::I8),
                PrimitiveValType::S16 => Value::S(IntWidth::I16),
                PrimitiveValType::U16 => Value::U(IntWidth::I16),
                PrimitiveValType::S32 => Value::S(IntWidth::I32),
                PrimitiveValType::U32 => Value::U(IntWidth::I32),
                PrimitiveValType::S64 => Value::S(IntWidth::I64),
                PrimitiveValType::U64 => Value::U(IntWidth::I64),
                PrimitiveValType::F32 => Value::F(FloatWidth::F32),
                PrimitiveValType::F64 => Value::F(FloatWidth::F64),
                PrimitiveValType::Char => Value::Char,
                PrimitiveValType::String => Value::String,
            }),
        }
    }

    fn elab_defined_value<'c>(
        &'c mut self,
        vt: &ComponentDefinedType<'a>,
    ) -> Result<Value<'a>, Error<'a>> {
        match vt {
            ComponentDefinedType::Primitive(pvt) => {
                self.elab_value(&ComponentValType::Primitive(*pvt))
            }
            ComponentDefinedType::Record(rfs) => {
                let rfs = rfs
                    .iter()
                    .map(|(name, ty)| {
                        Ok::<_, Error<'a>>(RecordField {
                            name: Name { name: *name },
                            ty: self.elab_value(ty)?,
                        })
                    })
                    .collect::<Result<Vec<_>, Error<'a>>>()?;
                Ok(Value::Record(rfs))
            }
            ComponentDefinedType::Variant(vcs) => {
                let vcs = vcs
                    .iter()
                    .map(|vc| {
                        Ok(VariantCase {
                            name: Name { name: vc.name },
                            ty: vc.ty.as_ref().map(|ty| self.elab_value(ty)).transpose()?,
                            refines: vc.refines,
                        })
                    })
                    .collect::<Result<Vec<_>, Error<'a>>>()?;
                Ok(Value::Variant(vcs))
            }
            ComponentDefinedType::List(vt) => Ok(Value::List(Box::new(self.elab_value(vt)?))),
            ComponentDefinedType::Tuple(vts) => Ok(Value::Tuple(
                vts.iter()
                    .map(|vt| self.elab_value(vt))
                    .collect::<Result<Vec<_>, Error<'a>>>()?,
            )),
            ComponentDefinedType::Flags(ns) => {
                Ok(Value::Flags(ns.iter().map(|n| Name { name: *n }).collect()))
            }
            ComponentDefinedType::Enum(ns) => {
                Ok(Value::Enum(ns.iter().map(|n| Name { name: *n }).collect()))
            }
            ComponentDefinedType::Option(vt) => Ok(Value::Option(Box::new(self.elab_value(vt)?))),
            ComponentDefinedType::Result { ok, err } => Ok(Value::Result(
                Box::new(ok.map(|ok| self.elab_value(&ok)).transpose()?),
                Box::new(err.map(|err| self.elab_value(&err)).transpose()?),
            )),
            ComponentDefinedType::Own(n) => match &self.types[*n as usize] {
                Defined::Handleable(h) => Ok(Value::Own(h.clone())),
                _ => Err(Error::HandleToNonResource),
            },
            ComponentDefinedType::Borrow(n) => match &self.types[*n as usize] {
                Defined::Handleable(h) => Ok(Value::Borrow(h.clone())),
                _ => Err(Error::HandleToNonResource),
            },
            ComponentDefinedType::Future(_)
            | ComponentDefinedType::Stream(_)
            | ComponentDefinedType::ErrorContext => panic!("async not yet supported"),
        }
    }

    fn elab_func<'c>(&'c mut self, ft: &ComponentFuncType<'a>) -> Result<Func<'a>, Error<'a>> {
        Ok(Func {
            params: ft
                .params
                .iter()
                .map(|(n, vt)| {
                    Ok(Param {
                        name: Name { name: *n },
                        ty: self.elab_value(vt)?,
                    })
                })
                .collect::<Result<Vec<_>, Error<'a>>>()?,
            result: match &ft.results {
                ComponentFuncResult::Unnamed(vt) => etypes::Result::Unnamed(self.elab_value(vt)?),
                ComponentFuncResult::Named(rs) => etypes::Result::Named(
                    rs.iter()
                        .map(|(n, vt)| {
                            Ok(Param {
                                name: Name { name: *n },
                                ty: self.elab_value(vt)?,
                            })
                        })
                        .collect::<Result<Vec<_>, Error<'a>>>()?,
                ),
            },
        })
    }

    fn elab_extern_desc<'c>(
        &'c mut self,
        ed: &ComponentTypeRef,
    ) -> Result<(Vec<BoundedTyvar<'a>>, ExternDesc<'a>), Error<'a>> {
        match ed {
            ComponentTypeRef::Module(i) => match &self.core.types[*i as usize] {
                CoreDefined::Module(mt) => Ok((vec![], ExternDesc::CoreModule(mt.clone()))),
                _ => {
                    panic!("internal invariant violation: bad sort for ComponentTypeRef to Module")
                }
            },
            ComponentTypeRef::Func(i) => match &self.types[*i as usize] {
                Defined::Func(ft) => Ok((vec![], ExternDesc::Func(ft.clone()))),
                _ => panic!("internal invariant violation: bad sort for ComponentTypeRef to Func"),
            },
            ComponentTypeRef::Value(_) => panic!("First-class values are not yet supported"),
            ComponentTypeRef::Type(tb) => {
                let bound = match tb {
                    TypeBounds::Eq(i) => TypeBound::Eq(self.types[*i as usize].clone()),
                    TypeBounds::SubResource => TypeBound::SubResource,
                };
                let dt = Defined::Handleable(Handleable::Var(Tyvar::Bound(0)));
                Ok((vec![BoundedTyvar::new(bound)], ExternDesc::Type(dt)))
            }
            ComponentTypeRef::Instance(i) => match &self.types[*i as usize] {
                Defined::Instance(qit) => Ok((
                    qit.evars.clone(),
                    ExternDesc::Instance(qit.unqualified.clone()),
                )),
                _ => panic!(
                    "internal invariant violation: bad sort for ComponentTypeRef to Instance"
                ),
            },
            ComponentTypeRef::Component(i) => match &self.types[*i as usize] {
                Defined::Component(ct) => Ok((vec![], ExternDesc::Component(ct.clone()))),
                _ => panic!(
                    "internal invariant violation: bad sort for ComponentTypeRef to Component"
                ),
            },
        }
    }

    fn elab_instance_decl<'c>(
        &'c mut self,
        decl: &InstanceTypeDeclaration<'a>,
    ) -> Result<Option<ExternDecl<'a>>, Error<'a>> {
        match decl {
            InstanceTypeDeclaration::CoreType(ct) => {
                let ct = self.elab_core_type(ct);
                self.core.types.push(ct);
                Ok(None)
            }
            InstanceTypeDeclaration::Type(t) => {
                let t = self.elab_defined(t)?;
                if let Defined::Handleable(_) = t {
                    return Err(Error::ResourceInDeclarator);
                }
                self.types.push(t);
                Ok(None)
            }
            InstanceTypeDeclaration::Alias(a) => {
                let ed = self.resolve_alias(a)?;
                self.add_core_or_component_ed(ed);
                Ok(None)
            }
            InstanceTypeDeclaration::Export { name, ty } => {
                let (vs, ed) = self.elab_extern_desc(ty)?;
                let sub = self.bound_to_evars(Some(name.0), &vs);
                let ed = sub.extern_desc(&ed).not_void();
                self.add_ed(&ed);
                Ok(Some(ExternDecl {
                    kebab_name: name.0,
                    desc: ed,
                }))
            }
        }
    }

    fn elab_instance<'c>(
        &'c mut self,
        decls: &[InstanceTypeDeclaration<'a>],
    ) -> Result<QualifiedInstance<'a>, Error<'a>> {
        let mut ctx = Ctx::new(Some(self), false);
        let mut exports = Vec::new();
        for decl in decls {
            let export = ctx.elab_instance_decl(decl)?;
            if let Some(export) = export {
                exports.push(export);
            }
        }
        ctx.finish_instance(&exports)
    }

    fn finish_instance_evars(
        self,
        exports: &[ExternDecl<'a>],
    ) -> Result<QualifiedInstance<'a>, Error<'a>> {
        let mut evars = Vec::new();
        let mut sub = substitute::Closing::new(false);
        for (bound, _) in self.evars {
            let bound = sub.bounded_tyvar(&bound)?;
            evars.push(bound);
            sub.next_e();
        }
        let unqualified = sub.instance(&Instance {
            exports: exports.to_vec(),
        })?;
        Ok(QualifiedInstance { evars, unqualified })
    }

    fn finish_instance(
        self,
        exports: &[ExternDecl<'a>],
    ) -> Result<QualifiedInstance<'a>, Error<'a>> {
        let qi = self.finish_instance_evars(exports)?;
        let raise_u_sub = substitute::Closing::new(true);
        Ok(raise_u_sub.qualified_instance(&qi)?)
    }

    fn elab_component_decl<'c>(
        &'c mut self,
        decl: &ComponentTypeDeclaration<'a>,
    ) -> Result<(Option<ExternDecl<'a>>, Option<ExternDecl<'a>>), Error<'a>> {
        match decl {
            ComponentTypeDeclaration::CoreType(ct) => {
                let ct = self.elab_core_type(ct);
                self.core.types.push(ct);
                Ok((None, None))
            }
            ComponentTypeDeclaration::Type(t) => {
                let t = self.elab_defined(t)?;
                if let Defined::Handleable(_) = t {
                    return Err(Error::ResourceInDeclarator);
                }
                self.types.push(t);
                Ok((None, None))
            }
            ComponentTypeDeclaration::Alias(a) => {
                let ed = self.resolve_alias(a)?;
                self.add_core_or_component_ed(ed);
                Ok((None, None))
            }
            ComponentTypeDeclaration::Export { name, ty, .. } => {
                let (vs, ed) = self.elab_extern_desc(ty)?;
                let sub = self.bound_to_evars(Some(name.0), &vs);
                let ed = sub.extern_desc(&ed).not_void();
                self.add_ed(&ed);
                Ok((
                    None,
                    Some(ExternDecl {
                        kebab_name: name.0,
                        desc: ed,
                    }),
                ))
            }
            ComponentTypeDeclaration::Import(i) => {
                let (vs, ed) = self.elab_extern_desc(&i.ty)?;
                let sub = self.bound_to_uvars(Some(i.name.0), &vs, true);
                let ed = sub.extern_desc(&ed).not_void();
                self.add_ed(&ed);
                Ok((
                    Some(ExternDecl {
                        kebab_name: i.name.0,
                        desc: ed,
                    }),
                    None,
                ))
            }
        }
    }

    fn finish_component(
        self,
        imports: &[ExternDecl<'a>],
        exports: &[ExternDecl<'a>],
    ) -> Result<Component<'a>, Error<'a>> {
        let mut uvars = Vec::new();
        let mut sub = substitute::Closing::new(true);
        for (bound, imported) in &self.uvars {
            let bound = sub.bounded_tyvar(&bound)?;
            uvars.push(bound);
            sub.next_u(*imported);
        }
        let imports = imports
            .iter()
            .map(|ed| sub.extern_decl(ed).map_err(Into::into))
            .collect::<Result<Vec<ExternDecl<'a>>, Error<'a>>>()?;
        let instance = sub.qualified_instance(&self.finish_instance_evars(exports)?)?;
        Ok(Component {
            uvars,
            imports,
            instance,
        })
    }

    fn elab_defined<'c>(&'c mut self, dt: &ComponentType<'a>) -> Result<Defined<'a>, Error<'a>> {
        match dt {
            ComponentType::Defined(vt) => Ok(Defined::Value(self.elab_defined_value(vt)?)),
            ComponentType::Func(ft) => Ok(Defined::Func(self.elab_func(ft)?)),
            ComponentType::Component(cds) => Ok(Defined::Component(self.elab_component(cds)?)),
            ComponentType::Instance(ids) => Ok(Defined::Instance(self.elab_instance(ids)?)),
            ComponentType::Resource { dtor, .. } => {
                let rid = ResourceId {
                    id: self.rtypes.len() as u32,
                };
                self.rtypes.push(Resource { _dtor: *dtor });
                Ok(Defined::Handleable(Handleable::Resource(rid)))
            }
        }
    }
}
