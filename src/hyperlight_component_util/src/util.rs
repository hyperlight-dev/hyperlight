use crate::{dbg_println, etypes};

pub fn read_wit_type_from_file<R, F: FnMut(String, &etypes::Component) -> R>(
    filename: impl AsRef<std::ffi::OsStr>,
    mut cb: F,
) -> R {
    let path = std::path::Path::new(&filename);
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_dir = std::path::Path::new(&manifest_dir);
    let path = manifest_dir.join(path);

    let bytes = std::fs::read(path).unwrap();
    let i = wasmparser::Parser::new(0).parse_all(&bytes);
    let ct = crate::component::read_component_single_exported_type(i);

    // because of the two-level encapsulation scheme, we need to look
    // for the single export of the component type that we just read
    #[allow(unused_parens)]
    if ct.uvars.len() != 0
        || ct.imports.len() != 0
        || ct.instance.evars.len() != 0
        || ct.instance.unqualified.exports.len() != 1
    {
        panic!("malformed component type container for wit type");
    };
    let export = &ct.instance.unqualified.exports[0];
    use etypes::ExternDesc;
    let ExternDesc::Component(ct) = &export.desc else {
        panic!("component type container does not contain component type");
    };
    dbg_println!("hcm: considering component type {:?}", ct);
    cb(export.kebab_name.to_string(), ct)
}

pub fn emit_decls(decls: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    if let Ok(dbg_out) = std::env::var("HYPERLIGHT_COMPONENT_MACRO_DEBUG") {
        if let Ok(file) = syn::parse2(decls.clone()) {
            std::fs::write(&dbg_out, prettyplease::unparse(&file)).unwrap();
        } else {
            let decls = format!("{}", &decls);
            std::fs::write(&dbg_out, &decls).unwrap();
        }
        (quote::quote! { include!(#dbg_out); }).into()
    } else {
        decls
    }
}
