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

//! Component type well-formedness
//!
//! This is a pretty direct port of the relevant sections of the OCaml
//! reference interpreter.
use itertools::Itertools;

use crate::etypes::{
    BoundedTyvar, Component, Ctx, Defined, ExternDecl, ExternDesc, Func, Handleable, Instance,
    Name, Param, QualifiedInstance, RecordField, TypeBound, Value, VariantCase,
};
use crate::substitute::{Substitution, Unvoidable};
use crate::subtype;

/// The various position metadata that affect what value types are
/// well-formed
#[derive(Clone, Copy)]
struct ValueTypePosition {
    /// Is this well-formedness check for a type that is part of the
    /// parameter type of a function? (Borrows should be allowed)
    is_param: bool,
    dtp: DefinedTypePosition,
}

impl From<DefinedTypePosition> for ValueTypePosition {
    fn from(p: DefinedTypePosition) -> ValueTypePosition {
        ValueTypePosition {
            is_param: false,
            dtp: p,
        }
    }
}
impl ValueTypePosition {
    fn not_anon_export(self) -> Self {
        ValueTypePosition {
            dtp: self.dtp.not_anon_export(),
            ..self
        }
    }
    fn anon_export(self) -> Self {
        ValueTypePosition {
            dtp: self.dtp.anon_export(),
            ..self
        }
    }
}

/// The various position metadata that affect what defined types are
/// well-formed
#[derive(Clone, Copy)]
pub struct DefinedTypePosition {
    /// Is this well-formedness check for a type one that should be
    /// exportable (e.g. one that is being
    /// exported/imported/outer-aliased-through-an-outer-boundary)?
    /// (Bare resource types should be disallowed)
    is_export: bool,
    /// Is this well-formedness check for a type that should be
    /// allowed in an "unnamed" export (i.e. nested under some other
    /// type constructor in an export)? (Record, variant, enum, and
    /// flags types, which must always be named in exports due to WIT
    /// constraints, should not be allowed).
    is_anon_export: bool,
}
impl DefinedTypePosition {
    pub fn internal() -> Self {
        DefinedTypePosition {
            is_export: false,
            is_anon_export: false,
        }
    }
    pub fn export() -> Self {
        DefinedTypePosition {
            is_export: true,
            is_anon_export: false,
        }
    }
    fn not_anon_export(self) -> Self {
        DefinedTypePosition {
            is_anon_export: false,
            ..self
        }
    }
    fn anon_export(self) -> Self {
        DefinedTypePosition {
            is_anon_export: true,
            ..self
        }
    }
}

/// There are several ways in which a type may be ill-formed:
#[derive(Debug)]
#[allow(dead_code)]
pub enum Error<'a> {
    /// A component/instance exported a bare resource type not behind
    /// a tyvar (and therefore not named)
    BareResourceExport,
    /// A component/instance exported certain complex value types not
    /// behind a tyvar (and therefore not named)
    BareComplexValTypeExport(Value<'a>),
    /// A record has multiple fields with the same name
    DuplicateRecordField(Name<'a>),
    /// A variant has multiple cases with the same name
    DuplicateVariantField(Name<'a>),
    /// A flags has multiple flags with the same name
    DuplicateFlagsName(Name<'a>),
    /// An enum has multiple cases with the same name
    DuplicateEnumName(Name<'a>),
    /// An import/export has the same name as another; the boolean is
    /// true if it is an import
    DuplicateExternName(&'a str, bool),
    /// A value type owns or borrows a type that is not a resource type
    NotAResource(subtype::Error<'a>),
    /// A borrow type exists somewhere other than a function parameter
    BorrowOutsideParam,
}

fn error_if_duplicates_by<T, U: Eq + std::hash::Hash, E>(
    i: impl Iterator<Item = T>,
    f: impl FnMut(&T) -> U,
    e: impl Fn(T) -> E,
) -> Result<(), E> {
    let mut duplicates = i.duplicates_by(f);
    if let Some(x) = duplicates.next() {
        Err(e(x))
    } else {
        Ok(())
    }
}

/// # Well-formedness
///
/// Most of this is a very direct translation of the specification
/// (Well-formedness subsections of section 3.4 Type Elaboration).
impl<'p, 'a> Ctx<'p, 'a> {
    fn wf_record_fields<'r>(
        &'r self,
        p: ValueTypePosition,
        rfs: &'r [RecordField<'a>],
    ) -> Result<(), Error<'a>> {
        rfs.iter()
            .try_for_each(|rf: &'r RecordField<'a>| self.wf_value(p, &rf.ty))?;
        error_if_duplicates_by(
            rfs.iter(),
            |&rf| rf.name.name,
            |rf| Error::DuplicateRecordField(rf.name),
        )?;
        Ok(())
    }
    fn wf_variant_cases<'r>(
        &'r self,
        p: ValueTypePosition,
        vcs: &'r [VariantCase<'a>],
    ) -> Result<(), Error<'a>> {
        vcs.iter()
            .try_for_each(|vc: &'r VariantCase<'a>| self.wf_value_option(p, &vc.ty))?;
        error_if_duplicates_by(
            vcs.iter(),
            |&vc| vc.name.name,
            |vc| Error::DuplicateVariantField(vc.name),
        )?;
        Ok(())
    }
    fn wf_value<'r>(&'r self, p: ValueTypePosition, vt: &'r Value<'a>) -> Result<(), Error<'a>> {
        let anon_err: Result<(), Error<'a>> = if p.dtp.is_export && p.dtp.is_anon_export {
            Err(Error::BareComplexValTypeExport(vt.clone()))
        } else {
            Ok(())
        };
        let p_ = p.anon_export();
        let resource_err = |h| {
            self.wf_handleable(p.dtp, h).and(
                self.subtype_handleable_is_resource(h)
                    .map_err(Error::NotAResource),
            )
        };
        match vt {
            Value::Bool => Ok(()),
            Value::S(_) => Ok(()),
            Value::U(_) => Ok(()),
            Value::F(_) => Ok(()),
            Value::Char => Ok(()),
            Value::String => Ok(()),
            Value::List(vt) => self.wf_value(p_, vt),
            Value::FixList(vt, _) => self.wf_value(p_, vt),
            Value::Record(rfs) => anon_err.and(self.wf_record_fields(p_, rfs)),
            Value::Variant(vcs) => anon_err.and(self.wf_variant_cases(p_, vcs)),
            Value::Flags(ns) => anon_err.and(error_if_duplicates_by(
                ns.iter(),
                |&n| n.name,
                |n| Error::DuplicateFlagsName(*n),
            )),
            Value::Enum(ns) => anon_err.and(error_if_duplicates_by(
                ns.iter(),
                |&n| n.name,
                |n| Error::DuplicateEnumName(*n),
            )),
            Value::Option(vt) => self.wf_value(p_, vt),
            Value::Tuple(vs) => vs
                .iter()
                .try_for_each(|vt: &'r Value<'a>| self.wf_value(p_, vt)),
            Value::Result(vt1, vt2) => self
                .wf_value_option(p_, vt1)
                .and(self.wf_value_option(p_, vt2)),
            Value::Own(h) => resource_err(h),
            Value::Borrow(h) => {
                if p.is_param {
                    resource_err(h)
                } else {
                    Err(Error::BorrowOutsideParam)
                }
            }
            Value::Var(tv, vt) => tv
                .as_ref()
                .map(|tv| self.wf_type_bound(p.dtp, self.var_bound(tv)))
                .unwrap_or(Ok(()))
                .and(self.wf_value(p.not_anon_export(), vt)),
        }
    }
    fn wf_value_option<'r>(
        &'r self,
        p: ValueTypePosition,
        vt: &'r Option<Value<'a>>,
    ) -> Result<(), Error<'a>> {
        vt.as_ref().map_or(Ok(()), |ty| self.wf_value(p, ty))
    }
    fn wf_func<'r>(&'r self, p: DefinedTypePosition, ft: &'r Func<'a>) -> Result<(), Error<'a>> {
        let p_ = p.anon_export();
        let param_pos = ValueTypePosition {
            is_param: true,
            dtp: p_,
        };
        let result_pos = ValueTypePosition {
            is_param: false,
            dtp: p_,
        };
        ft.params
            .iter()
            .try_for_each(|fp: &'r Param<'a>| self.wf_value(param_pos, &fp.ty))?;
        match &ft.result {
            Some(vt) => self.wf_value(result_pos, vt),
            None => Ok(()),
        }
    }
    fn wf_type_bound<'r>(
        &'r self,
        p: DefinedTypePosition,
        tb: &'r TypeBound<'a>,
    ) -> Result<(), Error<'a>> {
        match tb {
            TypeBound::SubResource => Ok(()),
            TypeBound::Eq(dt) => self.wf_defined(p.not_anon_export(), dt),
        }
    }
    fn wf_bounded_tyvar<'r>(
        &'r self,
        p: DefinedTypePosition,
        btv: &'r BoundedTyvar<'a>,
    ) -> Result<(), Error<'a>> {
        match &btv.bound {
            TypeBound::SubResource => Ok(()),
            TypeBound::Eq(dt) => self.wf_defined(p, dt),
        }
    }

    fn wf_handleable<'r>(
        &'r self,
        p: DefinedTypePosition,
        ht: &'r Handleable,
    ) -> Result<(), Error<'a>> {
        match ht {
            Handleable::Var(tv) => self.wf_type_bound(p, self.var_bound(tv)),
            Handleable::Resource(rid) => {
                if p.is_export {
                    Err(Error::BareResourceExport)
                } else {
                    // Internal invariant: rtidx should always exist
                    assert!((rid.id as usize) < self.rtypes.len());
                    Ok(())
                }
            }
        }
    }
    pub fn wf_defined<'r>(
        &'r self,
        p: DefinedTypePosition,
        dt: &'r Defined<'a>,
    ) -> Result<(), Error<'a>> {
        match dt {
            Defined::Handleable(ht) => self.wf_handleable(p, ht),
            Defined::Value(vt) => self.wf_value(p.into(), vt),
            Defined::Func(ft) => self.wf_func(p, ft),
            Defined::Instance(it) => self.wf_qualified_instance(p, it),
            Defined::Component(ct) => self.wf_component(p, ct),
        }
    }
    fn wf_extern_desc<'r>(
        &self,
        p: DefinedTypePosition,
        ed: &'r ExternDesc<'a>,
    ) -> Result<(), Error<'a>> {
        match ed {
            ExternDesc::CoreModule(_) => Ok(()),
            ExternDesc::Func(ft) => self.wf_func(p, ft),
            ExternDesc::Type(dt) => self.wf_defined(p, dt),
            ExternDesc::Instance(it) => self.wf_instance(p, it),
            ExternDesc::Component(ct) => self.wf_component(p, ct),
        }
    }
    fn wf_extern_decl<'r>(
        &self,
        p: DefinedTypePosition,
        ed: &'r ExternDecl<'a>,
    ) -> Result<(), Error<'a>> {
        self.wf_extern_desc(p, &ed.desc)
    }
    fn wf_instance<'r>(
        &self,
        p: DefinedTypePosition,
        it: &'r Instance<'a>,
    ) -> Result<(), Error<'a>> {
        error_if_duplicates_by(
            it.exports.iter(),
            |&ex| ex.kebab_name,
            |ex| Error::DuplicateExternName(ex.kebab_name, false),
        )?;
        it.exports
            .iter()
            .try_for_each(|ed| self.wf_extern_decl(p, ed))
    }
    pub fn wf_qualified_instance<'r>(
        &self,
        p: DefinedTypePosition,
        qit: &'r QualifiedInstance<'a>,
    ) -> Result<(), Error<'a>> {
        let mut ctx_ = self.clone();
        let subst = ctx_.bound_to_evars(None, &qit.evars);
        ctx_.evars
            .iter()
            .try_for_each(|(btv, _)| ctx_.wf_bounded_tyvar(p, btv))?;
        let it = subst.instance(&qit.unqualified).not_void();
        ctx_.wf_instance(p, &it)
    }
    pub fn wf_component<'r>(
        &self,
        p: DefinedTypePosition,
        ct: &'r Component<'a>,
    ) -> Result<(), Error<'a>> {
        let mut ctx_ = self.clone();
        let subst = ctx_.bound_to_uvars(None, &ct.uvars, false);
        ctx_.uvars
            .iter()
            .try_for_each(|(btv, _)| ctx_.wf_bounded_tyvar(p, btv))?;
        error_if_duplicates_by(
            ct.imports.iter(),
            |&im| im.kebab_name,
            |im| Error::DuplicateExternName(im.kebab_name, true),
        )?;
        ct.imports
            .iter()
            .map(|ed| subst.extern_decl(ed).not_void())
            .try_for_each(|ed| ctx_.wf_extern_decl(p, &ed))?;
        let it = subst.qualified_instance(&ct.instance).not_void();
        ctx_.wf_qualified_instance(p, &it)
    }
}
