/// Elaborated component model types
///
/// This has the basic type definitions for the elaborated types. They
/// correspond roughly to the "Elaborated Types" section in the
/// specification.
use crate::structure::*;

#[derive(Debug, Clone, PartialEq, Copy)]
pub struct Name<'a> {
    pub name: &'a str,
}

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum IntWidth {
    I8,
    I16,
    I32,
    I64,
}
impl IntWidth {
    pub fn width(self) -> u8 {
        match self {
            IntWidth::I8 => 8,
            IntWidth::I16 => 16,
            IntWidth::I32 => 32,
            IntWidth::I64 => 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum FloatWidth {
    F32,
    F64,
}
impl FloatWidth {
    pub fn width(self) -> u8 {
        match self {
            FloatWidth::F32 => 32,
            FloatWidth::F64 => 64,
        }
    }
}

/// recordfield_e in the specification
#[derive(Debug, Clone)]
pub struct RecordField<'a> {
    pub name: Name<'a>,
    pub ty: Value<'a>,
}

/// variantcase_e in the specification
#[derive(Debug, Clone)]
pub struct VariantCase<'a> {
    pub name: Name<'a>,
    pub ty: Option<Value<'a>>,
    pub refines: Option<u32>,
}

/// valtype_e in the specification
#[derive(Debug, Clone)]
pub enum Value<'a> {
    Bool,
    S(IntWidth),
    U(IntWidth),
    F(FloatWidth),
    Char,
    String,
    List(Box<Value<'a>>),
    Record(Vec<RecordField<'a>>),
    Tuple(Vec<Value<'a>>),
    Flags(Vec<Name<'a>>),
    Variant(Vec<VariantCase<'a>>),
    Enum(Vec<Name<'a>>),
    Option(Box<Value<'a>>),
    Result(Box<Option<Value<'a>>>, Box<Option<Value<'a>>>),
    Own(Handleable),
    Borrow(Handleable),
    /// This records that a type variable was once here, and is used
    /// to enforce export namedness checks.
    Var(Option<Tyvar>, Box<Value<'a>>),
}

/// global resource identifier
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResourceId {
    pub(super) id: u32,
}

#[derive(Debug, Clone)]
pub enum FreeTyvar {
    U(u32, u32),
    E(u32, u32),
}

#[derive(Debug, Clone)]
pub enum Tyvar {
    Bound(u32),
    Free(FreeTyvar),
}

#[derive(Debug, Clone)]
pub struct Param<'a> {
    pub name: Name<'a>,
    pub ty: Value<'a>,
}

#[derive(Debug, Clone)]
pub enum Result<'a> {
    Unnamed(Value<'a>),
    Named(Vec<Param<'a>>),
}

/// functype_e in the specification
#[derive(Debug, Clone)]
pub struct Func<'a> {
    pub params: Vec<Param<'a>>,
    pub result: Result<'a>,
}

/// In the spec, this does not exist, but a validation rule ensures an
/// invariant that certain deftype_e s are of this form.
#[derive(Debug, Clone)]
pub enum Handleable {
    Var(Tyvar),
    Resource(ResourceId),
}

/// deftype_e in the specification
#[derive(Debug, Clone)]
pub enum Defined<'a> {
    Handleable(Handleable),
    Value(Value<'a>),
    Func(Func<'a>),
    Instance(QualifiedInstance<'a>),
    Component(Component<'a>),
}

/// typebound_e in the specification
#[derive(Debug, Clone)]
pub enum TypeBound<'a> {
    Eq(Defined<'a>),
    SubResource,
}

/// The name of an import or export of the current
/// component/context. Not in the spec; only used for
/// [`BoundedTyvar::origin`] below.
///
/// Any string present in one of these should also be present in an
/// [`ExternDecl::kebab_name`] in a relevant place.
#[derive(Debug, Clone, PartialEq)]
pub enum ImportExport<'a> {
    Import(&'a str),
    Export(&'a str),
}
impl<'a> ImportExport<'a> {
    pub fn name(&self) -> &'a str {
        match self {
            ImportExport::Import(s) => s,
            ImportExport::Export(s) => s,
        }
    }
    pub fn imported(&self) -> bool {
        match self {
            ImportExport::Import(_) => true,
            ImportExport::Export(_) => false,
        }
    }
}

/// An (optional) path through the imports/exports of a current
/// component/context. Not in the spec; only used for
/// [`BoundedTyvar::origin`] below.
#[derive(Debug, Clone, PartialEq)]
pub struct TyvarOrigin<'a> {
    /// Note that the most recent (closest) element is last
    pub path: Option<Vec<ImportExport<'a>>>,
}

impl<'a> TyvarOrigin<'a> {
    pub fn new() -> Self {
        TyvarOrigin { path: Some(vec![]) }
    }
    pub fn push(&self, x: Option<ImportExport<'a>>) -> Self {
        match (&self.path, x) {
            (None, _) => TyvarOrigin { path: None },
            (_, None) => self.clone(),
            (Some(xs), Some(x)) => {
                let mut xs = xs.clone();
                xs.push(x);
                TyvarOrigin { path: Some(xs) }
            }
        }
    }
    pub fn matches<I: Iterator<Item = &'a ImportExport<'a>>>(&self, path: I) -> bool {
        self.path
            .as_ref()
            .map(|p| p.iter().rev().eq(path))
            .unwrap_or(false)
    }
    pub fn is_local<
        I: DoubleEndedIterator<Item = &'a ImportExport<'a>>
            + ExactSizeIterator<Item = &'a ImportExport<'a>>,
    >(
        &self,
        path: I,
    ) -> Option<Vec<ImportExport<'a>>> {
        let mut other = path.rev().skip(1).rev();
        let Some(path) = self.path.as_ref() else {
            return None;
        };
        let path = path.iter();
        let mut path = path.rev();
        while let Some(elem) = other.next() {
            match path.next() {
                None => break,
                Some(oe) if oe != elem => return None,
                _ => (),
            }
        }
        Some(path.map(|p| p.clone()).collect())
    }
    pub fn last_name(&self) -> Option<&'a str> {
        self.path
            .as_ref()
            .and_then(|x| x.get(0))
            .map(|ie| ie.name())
    }
    pub fn is_imported(&self) -> bool {
        let Some(p) = &self.path else {
            return false;
        };
        p[p.len() - 1].imported()
    }
}

/// boundedtyvar_e in the spec
///
/// Because we use a de bruijn representation of type indices, this is
/// only the type_bound - which variable it is binding is implicit in
/// its position in the list.
#[derive(Debug, Clone)]
pub struct BoundedTyvar<'a> {
    /// This is not important for typechecking, but is used to keep
    /// track of where a type variable originated from in order to
    /// decide on a canonical name to be used in bindings
    /// generation.
    pub origin: TyvarOrigin<'a>,
    pub bound: TypeBound<'a>,
}

impl<'a> BoundedTyvar<'a> {
    pub fn new(bound: TypeBound<'a>) -> Self {
        BoundedTyvar {
            origin: TyvarOrigin::new(),
            bound,
        }
    }
    pub fn push_origin(&self, x: Option<ImportExport<'a>>) -> Self {
        BoundedTyvar {
            origin: self.origin.push(x),
            ..self.clone()
        }
    }
}

/// externdesc_e in the specification
#[derive(Debug, Clone)]
pub enum ExternDesc<'a> {
    CoreModule(CoreModule<'a>),
    Func(Func<'a>),
    /* TODO: First-class values */
    Type(Defined<'a>),
    /// This uses an [`Instance`] rather than a [`QualifiedInstance`]
    /// because the instance's evars need to be propagated up to the
    /// surrounding component/instance (so that e.g. `alias`ing them
    /// and using them in another import/export is possible).
    Instance(Instance<'a>),
    Component(Component<'a>),
}

/// Merely a convenience for certain helper code
#[derive(Debug, Clone)]
pub enum CoreOrComponentExternDesc<'a> {
    Core(CoreExternDesc),
    Component(ExternDesc<'a>),
}

/// externdecl_e in the specification
#[derive(Debug, Clone)]
pub struct ExternDecl<'a> {
    pub kebab_name: &'a str,
    pub desc: ExternDesc<'a>,
}

/// `instancetype_e` in the specification.
///
/// An "opened" instance, whose existential variables are recorded in
/// some surrounding context.
#[derive(Debug, Clone)]
pub struct Instance<'a> {
    pub exports: Vec<ExternDecl<'a>>,
}

/// This is an instance together with its existential variables. This
/// concept doesn't exist as a named syntax class in the specification, but
/// is the payload of the instance case of `deftype_e` and the output
/// of the instance declaration inference judgement.
#[derive(Debug, Clone)]
pub struct QualifiedInstance<'a> {
    /// Existential variables produced by this instance (which may be
    /// referred to by [`exports`](Instance::exports)). These are stored in
    /// "outside-in" order that matches how they would be written on
    /// paper: de Bruijn index Bound(0) in the imports is the last
    /// element in the list, and later elements can depend on earlier
    /// ones.
    pub evars: Vec<BoundedTyvar<'a>>,
    pub unqualified: Instance<'a>,
}

/// componenttype_e in the specification
#[derive(Debug, Clone)]
pub struct Component<'a> {
    /// Universal variables over which this component is parameterized
    /// (which may be referred to by `imports`). These are stored in
    /// "outside-in" order that matches how they would be written on
    /// paper: de Bruijn index Bound(0) in the imports is the last
    /// element in the list, and later elements can depend on earlier
    /// ones.
    pub uvars: Vec<BoundedTyvar<'a>>,
    pub imports: Vec<ExternDecl<'a>>,
    /// Since we already have [`QualifiedInstance`], we use that to
    /// keep track of both the evars and the actual instance, unlike
    /// in the spec; this is quite natural, since during inference the
    /// evars are generated by the exports. However, they conceptually
    /// belong here as much as there: instantiating a component should
    /// add them to the context as non-imported uvars and produce an
    /// [`Instance`], rather than a [`QualifiedInstance`] directly.
    pub instance: QualifiedInstance<'a>,
}

// core:importdecl in the specification is wasmparser::Import

// core:importdesc in the specification
#[derive(Debug, Clone)]
pub enum CoreExternDesc {
    Func(wasmparser::FuncType),
    Table(wasmparser::TableType),
    Memory(wasmparser::MemoryType),
    Global(wasmparser::GlobalType),
}

/// core:exportdecl in the specification
#[derive(Debug, Clone)]
pub struct CoreExportDecl<'a> {
    pub name: Name<'a>,
    pub desc: CoreExternDesc,
}

// core:functype is wasmparser::FuncType

/// core:instancetype_e in the specification
#[derive(Debug, Clone)]
pub struct CoreInstance<'a> {
    pub exports: Vec<CoreExportDecl<'a>>,
}

/// core:moduletype_e in the specification
#[derive(Debug, Clone)]
pub struct CoreModule<'a> {
    pub _imports: Vec<wasmparser::Import<'a>>,
    pub _exports: Vec<CoreExportDecl<'a>>,
}

/// core:deftype_e in the specification
#[derive(Debug, Clone)]
pub enum CoreDefined<'a> {
    Func(wasmparser::FuncType),
    Module(CoreModule<'a>),
}

/// gamma_c in the specification
#[derive(Debug, Clone)]
pub struct CoreCtx<'a> {
    pub types: Vec<CoreDefined<'a>>,
    pub funcs: Vec<wasmparser::FuncType>,
    pub modules: Vec<CoreModule<'a>>,
    pub instances: Vec<CoreInstance<'a>>,
    pub tables: Vec<wasmparser::TableType>,
    pub mems: Vec<wasmparser::MemoryType>,
    pub globals: Vec<wasmparser::GlobalType>,
}

impl<'a> CoreCtx<'a> {
    pub fn new() -> Self {
        CoreCtx {
            types: Vec::new(),
            funcs: Vec::new(),
            modules: Vec::new(),
            instances: Vec::new(),
            tables: Vec::new(),
            mems: Vec::new(),
            globals: Vec::new(),
        }
    }
}

/// resourcetype_e in the specification
#[derive(Debug, Clone)]
pub struct Resource {
    // One day, there will be a `rep` field here...
    pub _dtor: Option<FuncIdx>,
}

/// gamma in the specification
#[derive(Debug, Clone)]
pub struct Ctx<'p, 'a> {
    pub parent: Option<&'p Ctx<'p, 'a>>,
    pub outer_boundary: bool,
    pub core: CoreCtx<'a>,
    /// Universally-quantified variables, specifying for each the
    /// known bound and whether or not it was imported. Uvars can come
    /// from imports or component instantiations; only the imported
    /// ones can be allowed to escape in the type of a components
    /// exports/imports, since only those can be named outside of the
    /// component itself.
    pub uvars: Vec<(BoundedTyvar<'a>, bool)>,
    /// Existentially-quantified variables, specifying for each the
    /// known bound and, if it was locally defined, the type which
    /// instantiates it.
    pub evars: Vec<(BoundedTyvar<'a>, Option<Defined<'a>>)>,
    pub rtypes: Vec<Resource>,
    pub types: Vec<Defined<'a>>,
    pub components: Vec<Component<'a>>,
    pub instances: Vec<Instance<'a>>,
    pub funcs: Vec<Func<'a>>,
}

impl<'p, 'a> Ctx<'p, 'a> {
    pub fn new<'c>(parent: Option<&'p Ctx<'c, 'a>>, outer_boundary: bool) -> Self {
        Ctx {
            parent,
            outer_boundary,
            core: CoreCtx::new(),
            uvars: Vec::new(),
            evars: Vec::new(),
            rtypes: Vec::new(),
            types: Vec::new(),
            components: Vec::new(),
            instances: Vec::new(),
            funcs: Vec::new(),
        }
    }
}

pub struct CtxParentIterator<'i, 'p: 'i, 'a: 'i> {
    ctx: Option<&'i Ctx<'p, 'a>>,
}
impl<'i, 'p, 'a> Iterator for CtxParentIterator<'i, 'p, 'a> {
    type Item = &'i Ctx<'p, 'a>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.ctx {
            Some(ctx) => {
                self.ctx = ctx.parent;
                Some(ctx)
            }
            None => None,
        }
    }
}

impl<'p, 'a> Ctx<'p, 'a> {
    pub fn parents<'i>(self: &'i Self) -> CtxParentIterator<'i, 'p, 'a> {
        CtxParentIterator { ctx: Some(self) }
    }
}
