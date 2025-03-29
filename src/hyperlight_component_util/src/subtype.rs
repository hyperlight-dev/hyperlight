use itertools::Itertools;

use crate::etypes::{
    Component, Ctx, Defined, Func, Handleable, Name, QualifiedInstance, ResourceId, TypeBound,
    Tyvar, Value,
};
use crate::tv::ResolvedTyvar;

#[derive(Debug)]
#[allow(dead_code)]
pub enum Error<'r> {
    MissingValue(Value<'r>),
    MissingRecordField(Name<'r>),
    MissingVariantCase(Name<'r>),
    MismatchedValue(Value<'r>, Value<'r>),
    MismatchedDefined(Defined<'r>, Defined<'r>),
    MismatchedResources(ResourceId, ResourceId),
    MismatchedVars(Tyvar, Tyvar),
    MismatchedResourceVar(Tyvar, ResourceId),
    NotResource(Handleable),
}

impl<'p, 'a> Ctx<'p, 'a> {
    pub fn subtype_value<'r>(
        &self,
        vt1: &'r Value<'a>,
        vt2: &'r Value<'a>,
    ) -> Result<(), Error<'a>> {
        use itertools::EitherOrBoth::*;
        use Value::*;
        match (vt1, vt2) {
            (Bool, Bool) => Ok(()),
            (S(w1), S(w2)) if w1 == w2 => Ok(()),
            (U(w1), U(w2)) if w1 == w2 => Ok(()),
            (F(w1), F(w2)) if w1 == w2 => Ok(()),
            (Char, Char) => Ok(()),
            (String, String) => Ok(()),
            (List(vt1), List(vt2)) => self.subtype_value(vt1, vt2),
            (Record(rfs1), Record(rfs2)) => {
                for rf2 in rfs2.iter() {
                    match rfs1.iter().find(|rf| rf2.name.name == rf.name.name) {
                        None => return Err(Error::MissingRecordField(rf2.name)),
                        Some(rf1) => self.subtype_value(&rf1.ty, &rf2.ty)?,
                    }
                }
                Ok(())
            }
            (Tuple(vts1), Tuple(vts2)) => vts1
                .iter()
                .zip_longest(vts2.iter())
                .map(|vs| match vs {
                    Both(vt1, vt2) => self.subtype_value(vt1, vt2),
                    Left(_) => Ok(()),
                    Right(vt2) => Err(Error::MissingValue(vt2.clone())),
                })
                .collect::<std::result::Result<(), Error>>(),
            (Flags(ns1), Flags(ns2)) => ns2
                .iter()
                .find(|n2| ns1.iter().find(|n| n.name == n2.name).is_none())
                .map_or(Ok(()), |n| Err(Error::MissingRecordField(*n))),
            (Variant(vcs1), Variant(vcs2)) => {
                for vc1 in vcs1.iter() {
                    match vcs2.iter().find(|vc| vc1.name.name == vc.name.name) {
                        None => return Err(Error::MissingVariantCase(vc1.name)),
                        Some(vc2) => self.subtype_value_option(&vc1.ty, &vc2.ty)?,
                    }
                }
                Ok(())
            }
            (Enum(ns1), Enum(ns2)) => ns1
                .iter()
                .find(|n1| ns2.iter().find(|n| n.name == n1.name).is_none())
                .map_or(Ok(()), |n| Err(Error::MissingVariantCase(*n))),
            (Option(vt1), Option(vt2)) => self.subtype_value(vt1, vt2),
            (Result(vt11, vt12), Result(vt21, vt22)) => self
                .subtype_value_option(vt11, vt21)
                .and(self.subtype_value_option(vt12, vt22)),
            (Own(ht1), Own(ht2)) | (Borrow(ht1), Borrow(ht2)) => {
                self.subtype_handleable_is_resource(ht1)?;
                self.subtype_handleable_is_resource(ht2)?;
                self.subtype_handleable(ht1, ht2)
            }
            (Var(_, vt1), vt2) => self.subtype_value(vt1, vt2),
            (vt1, Var(_, vt2)) => self.subtype_value(vt1, vt2),
            _ => Err(Error::MismatchedValue(vt1.clone(), vt2.clone())),
        }
    }
    pub fn subtype_value_option<'r>(
        &self,
        vt1: &'r Option<Value<'a>>,
        vt2: &'r Option<Value<'a>>,
    ) -> Result<(), Error<'a>> {
        match (vt1, vt2) {
            (None, None) => Ok(()),
            (None, Some(vt2)) => Err(Error::MissingValue(vt2.clone())),
            (Some(_), None) => Ok(()),
            (Some(vt1), Some(vt2)) => self.subtype_value(vt1, vt2),
        }
    }
    pub fn subtype_var_var<'r>(&self, v1: &'r Tyvar, v2: &'r Tyvar) -> Result<(), Error<'a>> {
        match (self.resolve_tyvar(v1), self.resolve_tyvar(v2)) {
            (ResolvedTyvar::Definite(dt1), ResolvedTyvar::Definite(dt2)) => {
                self.subtype_defined(&dt1, &dt2)
            }
            (ResolvedTyvar::E(o1, i1, _), ResolvedTyvar::E(o2, i2, _)) if o1 == o2 && i1 == i2 => {
                Ok(())
            }
            (ResolvedTyvar::U(o1, i1, _), ResolvedTyvar::U(o2, i2, _)) if o1 == o2 && i1 == i2 => {
                Ok(())
            }
            (ResolvedTyvar::Bound(_), _) | (_, ResolvedTyvar::Bound(_)) => {
                panic!("internal invariant violation: stray bvar in subtype_var_var")
            }
            _ => Err(Error::MismatchedVars(v1.clone(), v2.clone())),
        }
    }
    pub fn subtype_var_resource<'r>(
        &self,
        v1: &'r Tyvar,
        rid2: &'r ResourceId,
    ) -> Result<(), Error<'a>> {
        match self.resolve_tyvar(v1) {
            ResolvedTyvar::Definite(Defined::Handleable(Handleable::Resource(rid1)))
                if rid1 == *rid2 =>
            {
                Ok(())
            }
            _ => Err(Error::MismatchedResourceVar(v1.clone(), *rid2)),
        }
    }
    pub fn subtype_resource_var<'r>(
        &self,
        rid1: &'r ResourceId,
        v2: &'r Tyvar,
    ) -> Result<(), Error<'a>> {
        match self.resolve_tyvar(v2) {
            ResolvedTyvar::Definite(Defined::Handleable(Handleable::Resource(rid2)))
                if *rid1 == rid2 =>
            {
                Ok(())
            }
            _ => Err(Error::MismatchedResourceVar(v2.clone(), *rid1)),
        }
    }
    pub fn subtype_handleable<'r>(
        &self,
        ht1: &'r Handleable,
        ht2: &'r Handleable,
    ) -> Result<(), Error<'a>> {
        match (ht1, ht2) {
            (Handleable::Var(v1), Handleable::Var(v2)) => self.subtype_var_var(v1, v2),
            (Handleable::Var(v1), Handleable::Resource(rid2)) => {
                self.subtype_var_resource(v1, rid2)
            }
            (Handleable::Resource(rid1), Handleable::Var(v2)) => {
                self.subtype_resource_var(rid1, v2)
            }
            (Handleable::Resource(rid1), Handleable::Resource(rid2)) => {
                if rid1 == rid2 {
                    Ok(())
                } else {
                    Err(Error::MismatchedResources(*rid1, *rid2))
                }
            }
        }
    }
    pub fn subtype_func<'r>(
        &self,
        _ft1: &'r Func<'a>,
        _ft2: &'r Func<'a>,
    ) -> Result<(), Error<'a>> {
        panic!("func <: func should be impossible to encounter during type elaboration")
    }
    pub fn subtype_qualified_instance<'r>(
        &self,
        _qi1: &'r QualifiedInstance<'a>,
        _qi2: &'r QualifiedInstance<'a>,
    ) -> Result<(), Error<'a>> {
        panic!("qinstance <: qinstance should be impossible to encounter during type elaboration")
    }
    pub fn subtype_component<'r>(
        &self,
        _ct1: &'r Component<'a>,
        _ct2: &'r Component<'a>,
    ) -> Result<(), Error<'a>> {
        panic!("component <: component should be impossible to encounter during type elaboration")
    }
    pub fn subtype_defined<'r>(
        &self,
        dt1: &'r Defined<'a>,
        dt2: &'r Defined<'a>,
    ) -> Result<(), Error<'a>> {
        match (dt1, dt2) {
            (Defined::Handleable(ht1), Defined::Handleable(ht2)) => {
                self.subtype_handleable(ht1, ht2)
            }
            (Defined::Value(vt1), Defined::Value(vt2)) => self.subtype_value(vt1, vt2),
            (Defined::Func(ft1), Defined::Func(ft2)) => self.subtype_func(ft1, ft2),
            (Defined::Instance(it1), Defined::Instance(it2)) => {
                self.subtype_qualified_instance(it1, it2)
            }
            (Defined::Component(ct1), Defined::Component(ct2)) => self.subtype_component(ct1, ct2),
            _ => Err(Error::MismatchedDefined(dt1.clone(), dt2.clone())),
        }
    }
    pub fn subtype_handleable_is_resource<'r>(&self, ht: &'r Handleable) -> Result<(), Error<'a>> {
        match ht {
            Handleable::Resource(_) => Ok(()),
            Handleable::Var(tv) => match self.resolve_tyvar(tv) {
                ResolvedTyvar::Definite(Defined::Handleable(Handleable::Resource(_))) => Ok(()),
                ResolvedTyvar::E(_, _, TypeBound::SubResource) => Ok(()),
                ResolvedTyvar::U(_, _, TypeBound::SubResource) => Ok(()),
                _ => Err(Error::NotResource(ht.clone())),
            },
        }
    }
}
