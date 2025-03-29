use std::primitive::u32;

use crate::etypes::{
    BoundedTyvar, Component, Ctx, Defined, ExternDecl, ExternDesc, FreeTyvar, Func, Handleable,
    Instance, Param, QualifiedInstance, RecordField, TypeBound, Tyvar, Value, VariantCase,
};
use crate::tv::ResolvedTyvar;

/// A substitution
///
/// The [`Shiftable`] bound is required because the implementation of
/// substitution for components and instances needs to be able to
/// shift.
pub trait Substitution<'a>
where
    Self: Shiftable<'a>,
{
    type Error: From<<<Self as Shiftable<'a>>::Inner as Substitution<'a>>::Error>;
    fn subst_bvar(&self, i: u32) -> Result<Option<Defined<'a>>, Self::Error>;
    fn subst_evar(&self, o: u32, i: u32) -> Result<Option<Defined<'a>>, Self::Error>;
    fn subst_uvar(&self, o: u32, i: u32) -> Result<Option<Defined<'a>>, Self::Error>;

    fn record_fields(&self, rfs: &[RecordField<'a>]) -> Result<Vec<RecordField<'a>>, Self::Error> {
        rfs.iter()
            .map(|rf| {
                Ok(RecordField {
                    name: rf.name.clone(),
                    ty: self.value(&rf.ty)?,
                })
            })
            .collect()
    }

    fn variant_cases(&self, vcs: &[VariantCase<'a>]) -> Result<Vec<VariantCase<'a>>, Self::Error> {
        vcs.iter()
            .map(|vc| {
                Ok(VariantCase {
                    name: vc.name.clone(),
                    ty: self.value_option(&vc.ty)?,
                    refines: vc.refines.clone(),
                })
            })
            .collect()
    }

    fn value_option(&self, vt: &Option<Value<'a>>) -> Result<Option<Value<'a>>, Self::Error> {
        vt.as_ref().map(|ty| self.value(ty)).transpose()
    }

    fn value(&self, vt: &Value<'a>) -> Result<Value<'a>, Self::Error> {
        Ok(match vt {
            Value::Bool => Value::Bool,
            Value::S(w) => Value::S(*w),
            Value::U(w) => Value::U(*w),
            Value::F(w) => Value::F(*w),
            Value::Char => Value::Char,
            Value::String => Value::String,
            Value::List(vt) => Value::List(Box::new(self.value(vt)?)),
            Value::Record(rfs) => Value::Record(self.record_fields(rfs)?),
            Value::Variant(vcs) => Value::Variant(self.variant_cases(vcs)?),
            Value::Flags(ns) => Value::Flags(ns.clone()),
            Value::Enum(ns) => Value::Enum(ns.clone()),
            Value::Option(vt) => Value::Option(Box::new(self.value(vt)?)),
            Value::Tuple(vts) => Value::Tuple(
                vts.iter()
                    .map(|vt| self.value(vt))
                    .collect::<Result<Vec<Value<'a>>, Self::Error>>()?,
            ),
            Value::Result(vt1, vt2) => Value::Result(
                Box::new(self.value_option(vt1)?),
                Box::new(self.value_option(vt2)?),
            ),
            Value::Own(h) => Value::Own(self.handleable_(h)?),
            Value::Borrow(h) => Value::Borrow(self.handleable_(h)?),
            Value::Var(tv, vt) => Value::Var(
                tv.as_ref().and_then(|tv| match self.var(tv) {
                    Ok(Some(Defined::Handleable(Handleable::Var(tv)))) => Some(tv),
                    Ok(None) => Some(tv.clone()),
                    _ => None,
                }),
                Box::new(self.value(vt)?),
            ),
        })
    }

    fn param(&self, pt: &Param<'a>) -> Result<Param<'a>, Self::Error> {
        Ok(Param {
            name: pt.name,
            ty: self.value(&pt.ty)?,
        })
    }

    fn params(&self, pts: &Vec<Param<'a>>) -> Result<Vec<Param<'a>>, Self::Error> {
        pts.iter().map(|pt| self.param(pt)).collect()
    }

    fn result(
        &self,
        rt: &crate::etypes::Result<'a>,
    ) -> Result<crate::etypes::Result<'a>, Self::Error> {
        Ok(match rt {
            crate::etypes::Result::Unnamed(vt) => crate::etypes::Result::Unnamed(self.value(vt)?),
            crate::etypes::Result::Named(pts) => crate::etypes::Result::Named(self.params(pts)?),
        })
    }

    fn func(&self, ft: &Func<'a>) -> Result<Func<'a>, Self::Error> {
        Ok(Func {
            params: self.params(&ft.params)?,
            result: self.result(&ft.result)?,
        })
    }

    fn var(&self, tv: &Tyvar) -> Result<Option<Defined<'a>>, Self::Error> {
        match tv {
            Tyvar::Bound(i) => self.subst_bvar(*i),
            Tyvar::Free(FreeTyvar::U(o, i)) => self.subst_uvar(*o, *i),
            Tyvar::Free(FreeTyvar::E(o, i)) => self.subst_evar(*o, *i),
        }
    }

    fn handleable(&self, h: &Handleable) -> Result<Defined<'a>, Self::Error> {
        let hh = Defined::Handleable(h.clone());
        match h {
            Handleable::Resource(_) => Ok(hh),
            Handleable::Var(tv) => Ok(self.var(tv)?.unwrap_or(hh)),
        }
    }

    fn handleable_(&self, h: &Handleable) -> Result<Handleable, Self::Error> {
        match self.handleable(h)? {
            Defined::Handleable(h_) => Ok(h_),
            _ => panic!("internal invariant a violation: owned/borrowed var is not resource"),
        }
    }

    fn defined(&self, dt: &Defined<'a>) -> Result<Defined<'a>, Self::Error> {
        Ok(match dt {
            Defined::Handleable(h) => self.handleable(h)?,
            Defined::Value(vt) => Defined::Value(self.value(vt)?),
            Defined::Func(ft) => Defined::Func(self.func(ft)?),
            Defined::Instance(it) => Defined::Instance(self.qualified_instance(it)?),
            Defined::Component(ct) => Defined::Component(self.component(ct)?),
        })
    }

    fn type_bound(&self, tb: &TypeBound<'a>) -> Result<TypeBound<'a>, Self::Error> {
        Ok(match tb {
            TypeBound::Eq(dt) => TypeBound::Eq(self.defined(dt)?),
            TypeBound::SubResource => TypeBound::SubResource,
        })
    }

    fn bounded_tyvar(&self, btv: &BoundedTyvar<'a>) -> Result<BoundedTyvar<'a>, Self::Error> {
        Ok(BoundedTyvar {
            origin: btv.origin.clone(),
            bound: self.type_bound(&btv.bound)?,
        })
    }

    fn extern_desc(&self, ed: &ExternDesc<'a>) -> Result<ExternDesc<'a>, Self::Error> {
        Ok(match ed {
            ExternDesc::CoreModule(cmt) => ExternDesc::CoreModule(cmt.clone()),
            ExternDesc::Func(ft) => ExternDesc::Func(self.func(ft)?),
            ExternDesc::Type(dt) => ExternDesc::Type(self.defined(dt)?),
            ExternDesc::Instance(it) => ExternDesc::Instance(self.instance(it)?),
            ExternDesc::Component(ct) => ExternDesc::Component(self.component(ct)?),
        })
    }

    fn extern_decl(&self, ed: &ExternDecl<'a>) -> Result<ExternDecl<'a>, Self::Error> {
        Ok(ExternDecl {
            kebab_name: ed.kebab_name,
            desc: self.extern_desc(&ed.desc)?,
        })
    }

    fn instance(&self, it: &Instance<'a>) -> Result<Instance<'a>, Self::Error> {
        let exports = it
            .exports
            .iter()
            .map(|ed| self.extern_decl(ed).map_err(Into::into))
            .collect::<Result<Vec<_>, Self::Error>>()?;
        Ok(Instance { exports })
    }

    fn qualified_instance(
        &self,
        qit: &QualifiedInstance<'a>,
    ) -> Result<QualifiedInstance<'a>, Self::Error> {
        let mut evars = Vec::new();
        let mut sub = self.shifted();
        for evar in &qit.evars {
            evars.push(sub.bounded_tyvar(&evar)?);
            sub.bshift(1);
            sub.rbshift(1);
        }
        let it = sub.instance(&qit.unqualified)?;
        Ok(QualifiedInstance {
            evars,
            unqualified: it,
        })
    }

    fn component(&self, ct: &Component<'a>) -> Result<Component<'a>, Self::Error> {
        let mut uvars = Vec::new();
        let mut sub = self.shifted();
        for uvar in &ct.uvars {
            uvars.push(sub.bounded_tyvar(&uvar)?);
            sub.bshift(1);
            sub.rbshift(1);
        }
        let imports = ct
            .imports
            .iter()
            .map(|ed| sub.extern_decl(ed).map_err(Into::into))
            .collect::<Result<Vec<ExternDecl<'a>>, Self::Error>>()?;
        let instance = sub.qualified_instance(&ct.instance)?;
        Ok(Component {
            uvars,
            imports,
            instance,
        })
    }
}

/// A substitution that shifts bound variables up by a defined offset.
/// This will generally be accessed through [`Shifted`] below.  It is
/// important to ensure that a bound variable produced by a
/// substitution is not captured.
struct RBShift {
    rbshift: i32,
}
impl<'a> Shiftable<'a> for RBShift {
    type Inner = Self;
    fn shifted<'b>(&'b self) -> Shifted<'b, Self::Inner> {
        Shifted::new(self)
    }
}
impl<'a> Substitution<'a> for RBShift {
    type Error = Void;
    fn subst_bvar(&self, i: u32) -> Result<Option<Defined<'a>>, Self::Error> {
        Ok(Some(Defined::Handleable(Handleable::Var(Tyvar::Bound(
            i.checked_add_signed(self.rbshift).unwrap(),
        )))))
    }
    fn subst_evar(&self, _o: u32, _i: u32) -> Result<Option<Defined<'a>>, Self::Error> {
        Ok(None)
    }
    fn subst_uvar(&self, _o: u32, _i: u32) -> Result<Option<Defined<'a>>, Self::Error> {
        Ok(None)
    }
}

/// A substitution that can be converted into a [`Shifted`]
/// substitution. All types other than [`Shifted`] itself should
/// implement this with the obvious option of
/// ```
/// impl<'a> Shiftable<'a> for A {
///     type Inner = Self;
///     fn shifted<'b>(&'b self) -> Shifted<'b, Self::Inner> { Shifted::new(self) }
/// }
/// ```
/// Unfortunately, it is not reasonably possible to provide this
/// automatically without specialization.
pub trait Shiftable<'a> {
    type Inner: ?Sized + Substitution<'a>;
    fn shifted<'c>(&'c self) -> Shifted<'c, Self::Inner>;
}

/// A "shifted" version of a substitution, used internally to assure
/// that substitution is capture-avoiding.
pub struct Shifted<'b, A: ?Sized> {
    /// The substitution which is being shifted
    underlying: &'b A,
    /// The offset to apply to bound variables before querying the
    /// original substitution
    bshift: i32,
    /// The offset to apply to outer instance indices before
    /// querying the original substitution
    oshift: i32,
    /// The offset to apply to free evar indices before
    /// querying the original substitution
    eshift: i32,
    /// The offset to apply to free uvar indices before
    /// querying the original substitution
    ushift: i32,
    /// The offset to apply to bound variables in the result of the
    /// original substitution
    rbshift: i32,
}
impl<'b, A: ?Sized> Clone for Shifted<'b, A> {
    fn clone(&self) -> Self {
        Self {
            underlying: self.underlying,
            bshift: self.bshift,
            oshift: self.oshift,
            eshift: self.eshift,
            ushift: self.ushift,
            rbshift: self.rbshift,
        }
    }
}
impl<'a, 'b, A: ?Sized + Substitution<'a>> Shiftable<'a> for Shifted<'b, A> {
    type Inner = A;
    fn shifted<'c>(&'c self) -> Shifted<'c, Self::Inner> {
        self.clone()
    }
}

impl<'a, 'b, A: ?Sized + Substitution<'a>> Shifted<'b, A> {
    fn new(s: &'b A) -> Self {
        Self {
            underlying: s,
            bshift: 0,
            oshift: 0,
            eshift: 0,
            ushift: 0,
            rbshift: 0,
        }
    }
    fn bshift(&mut self, bshift: i32) {
        self.bshift += bshift;
    }
    #[allow(unused)]
    fn oshift(&mut self, oshift: i32) {
        self.oshift += oshift;
    }
    #[allow(unused)]
    fn ushift(&mut self, ushift: i32) {
        self.ushift += ushift;
    }
    #[allow(unused)]
    fn eshift(&mut self, eshift: i32) {
        self.eshift += eshift;
    }
    fn rbshift(&mut self, rbshift: i32) {
        self.rbshift += rbshift;
    }

    fn sub_rbshift(
        &self,
        dt: Result<Option<Defined<'a>>, <Self as Substitution<'a>>::Error>,
    ) -> Result<Option<Defined<'a>>, <Self as Substitution<'a>>::Error> {
        match dt {
            Ok(Some(dt)) => {
                let rbsub = RBShift {
                    rbshift: self.rbshift,
                };
                Ok(Some(rbsub.defined(&dt).not_void()))
            }
            _ => dt,
        }
    }
}

impl<'a, 'b, A: ?Sized + Substitution<'a>> Substitution<'a> for Shifted<'b, A> {
    type Error = A::Error;
    fn subst_bvar(&self, i: u32) -> Result<Option<Defined<'a>>, Self::Error> {
        match i.checked_add_signed(-self.bshift) {
            Some(i) => self.sub_rbshift(self.underlying.subst_bvar(i)),
            _ => Ok(None),
        }
    }
    fn subst_evar(&self, o: u32, i: u32) -> Result<Option<Defined<'a>>, Self::Error> {
        match (
            o.checked_add_signed(-self.oshift),
            i.checked_add_signed(-self.eshift),
        ) {
            (Some(o), Some(i)) => self.sub_rbshift(self.underlying.subst_evar(o, i)),
            _ => Ok(None),
        }
    }
    fn subst_uvar(&self, o: u32, i: u32) -> Result<Option<Defined<'a>>, Self::Error> {
        match (
            o.checked_add_signed(-self.oshift),
            i.checked_add_signed(-self.ushift),
        ) {
            (Some(o), Some(i)) => self.sub_rbshift(self.underlying.subst_uvar(o, i)),
            _ => Ok(None),
        }
    }
}

#[derive(Debug)]
pub enum InnerizeError {
    IndefiniteTyvar,
}
/// An innerize substitution is used to bring an outer type alias
/// inwards through one context.
pub struct Innerize<'c, 'p, 'a> {
    /// What ctx was this type originally in?
    ctx: &'c Ctx<'p, 'a>,
    /// Are we crossing an outer_boundary?
    outer_boundary: bool,
}
impl<'c, 'p, 'a> Shiftable<'a> for Innerize<'c, 'p, 'a> {
    type Inner = Self;
    fn shifted<'d>(&'d self) -> Shifted<'d, Self::Inner> {
        Shifted::new(self)
    }
}
impl<'c, 'p, 'a> Substitution<'a> for Innerize<'c, 'p, 'a> {
    type Error = InnerizeError;
    fn subst_bvar(&self, _i: u32) -> Result<Option<Defined<'a>>, Self::Error> {
        Ok(None)
    }
    // Note that even if the variables resolve, what they resolve to
    // needs to itself be innerized, since it was also designed for
    // this context.
    fn subst_evar(&self, o: u32, i: u32) -> Result<Option<Defined<'a>>, Self::Error> {
        if !self.outer_boundary {
            Ok(Some(Defined::Handleable(Handleable::Var(Tyvar::Free(
                FreeTyvar::E(o + 1, i),
            )))))
        } else {
            match self.ctx.resolve_tyvar(&Tyvar::Free(FreeTyvar::E(o, i))) {
                ResolvedTyvar::Definite(dt) => Ok(Some(self.defined(&dt)?)),
                _ => Err(InnerizeError::IndefiniteTyvar),
            }
        }
    }
    fn subst_uvar(&self, o: u32, i: u32) -> Result<Option<Defined<'a>>, Self::Error> {
        if !self.outer_boundary {
            Ok(Some(Defined::Handleable(Handleable::Var(Tyvar::Free(
                FreeTyvar::U(o + 1, i),
            )))))
        } else {
            match self.ctx.resolve_tyvar(&Tyvar::Free(FreeTyvar::U(o, i))) {
                ResolvedTyvar::Definite(dt) => Ok(Some(self.defined(&dt)?)),
                _ => Err(InnerizeError::IndefiniteTyvar),
            }
        }
    }
}
impl<'c, 'p, 'a> Innerize<'c, 'p, 'a> {
    pub fn new(ctx: &'c Ctx<'p, 'a>, outer_boundary: bool) -> Innerize<'c, 'p, 'a> {
        Innerize {
            ctx,
            outer_boundary,
        }
    }
}

/// The empty (void) type
pub enum Void {}

/// Things that you can call [`not_void`](Unvoidable::not_void) on
pub trait Unvoidable {
    type Result;
    fn not_void(self) -> Self::Result;
}

/// Eliminate a Result<_, Void>
impl<A> Unvoidable for Result<A, Void> {
    type Result = A;
    fn not_void(self) -> A {
        match self {
            Ok(x) => x,
            Err(v) => match v {},
        }
    }
}

/// An opening substitution is used to map bound variables into
/// free variables. Note that because of the differences in ordering
/// for bound variable indices (inside out) and context variables
/// (left to right, but variables are inserted in outside-in order),
/// `Bound(0)` gets mapped to `Free(0, base + n)`.
pub struct Opening {
    /// Whether to produce E or U free variables
    is_universal: bool,
    /// At what index in the context are the free variables being
    /// inserted?
    free_base: u32,
    /// How many bound variables are being shifted to the context
    how_many: u32,
}
impl<'a> Shiftable<'a> for Opening {
    type Inner = Self;
    fn shifted<'d>(&'d self) -> Shifted<'d, Self::Inner> {
        Shifted::new(self)
    }
}
impl<'a> Substitution<'a> for Opening {
    type Error = Void;
    fn subst_bvar(&self, i: u32) -> Result<Option<Defined<'a>>, Void> {
        let mk = |i| {
            let fi = self.free_base + self.how_many - i - 1;
            if self.is_universal {
                FreeTyvar::U(0, fi)
            } else {
                FreeTyvar::E(0, fi)
            }
        };
        Ok(if i < self.how_many {
            Some(Defined::Handleable(Handleable::Var(Tyvar::Free(mk(i)))))
        } else {
            None
        })
    }
    fn subst_evar(&self, _o: u32, _i: u32) -> Result<Option<Defined<'a>>, Void> {
        Ok(None)
    }
    fn subst_uvar(&self, _o: u32, _i: u32) -> Result<Option<Defined<'a>>, Void> {
        Ok(None)
    }
}
impl Opening {
    pub fn new(is_universal: bool, free_base: u32) -> Self {
        Opening {
            is_universal,
            free_base,
            how_many: 0,
        }
    }
    pub fn next(&mut self) {
        self.how_many += 1;
    }
}

/// A closing substitution is used to map free variables into bound
/// variables when converting a type being built in a context to a
/// closed(ish) type that is above that context.
///
/// Like [`Opening`], a given [`Closing`] substitution either affects
/// only existential variables or affects only universal variables, as
/// these are closed at different times.
pub struct Closing {
    /// If this substitution applies to universal variables, this
    /// keeps track of which ones are imported and which are
    /// not. Non-imported universal variables may not be referred to
    /// in types.
    ///
    /// Invariant: If this is provided, its length must be equal to
    /// self.how_many
    universal_imported: Option<Vec<bool>>,
    /// How many of the relevant (u/e) free vars are valid at this point.
    how_many: u32,
}
impl Closing {
    pub fn new(is_universal: bool) -> Self {
        let universal_imported = if is_universal { Some(Vec::new()) } else { None };
        Closing {
            universal_imported,
            how_many: 0,
        }
    }
    fn is_universal(&self) -> bool {
        self.universal_imported.is_some()
    }
    pub fn next_u(&mut self, imported: bool) {
        let Some(ref mut importeds) = self.universal_imported else {
            panic!("next_u called on existential Closing");
        };
        importeds.push(imported);
        self.how_many += 1;
    }
    pub fn next_e(&mut self) {
        if self.is_universal() {
            panic!("next_e called on universal Closing");
        };
        self.how_many += 1;
    }
    fn subst_uevar<'a>(
        &self,
        ue_is_u: bool,
        o: u32,
        i: u32,
    ) -> Result<Option<Defined<'a>>, ClosingError> {
        if self.is_universal() ^ ue_is_u {
            return Ok(None);
        }
        let mk_ue = |o, i| {
            if self.is_universal() {
                Tyvar::Free(FreeTyvar::U(o, i))
            } else {
                Tyvar::Free(FreeTyvar::E(o, i))
            }
        };
        let mk = |v| Ok(Some(Defined::Handleable(Handleable::Var(v))));
        if o > 0 {
            return mk(mk_ue(o - 1, i));
        }
        if i >= self.how_many {
            return Err(ClosingError::UnknownVar(false, i));
        }
        let bidx = if let Some(imported) = &self.universal_imported {
            if !imported[i as usize] {
                return Err(ClosingError::UnimportedVar(i));
            }
            imported[i as usize..].iter().filter(|x| **x).count() as u32 - 1
        } else {
            self.how_many - i - 1
        };
        mk(Tyvar::Bound(bidx))
    }
}
impl<'a> Shiftable<'a> for Closing {
    type Inner = Self;
    fn shifted<'d>(&'d self) -> Shifted<'d, Self::Inner> {
        Shifted::new(self)
    }
}
#[derive(Debug)]
#[allow(unused)]
pub enum ClosingError {
    UnknownVar(bool, u32),
    UnimportedVar(u32),
}
impl<'a> Substitution<'a> for Closing {
    type Error = ClosingError;
    fn subst_bvar(&self, _: u32) -> Result<Option<Defined<'a>>, ClosingError> {
        Ok(None)
    }
    fn subst_evar(&self, o: u32, i: u32) -> Result<Option<Defined<'a>>, ClosingError> {
        self.subst_uevar(false, o, i)
    }
    fn subst_uvar(&self, o: u32, i: u32) -> Result<Option<Defined<'a>>, ClosingError> {
        self.subst_uevar(true, o, i)
    }
}
