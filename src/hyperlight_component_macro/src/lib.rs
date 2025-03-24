extern crate proc_macro;

use hyperlight_component_util::*;

#[proc_macro]
pub fn host_bindgen(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let path: String = syn::parse_macro_input!(input as syn::LitStr).value();
    util::read_wit_type_from_file(path, |kebab_name, ct| {
        let decls = emit::run_state(false, |s| {
            rtypes::emit_toplevel(s, &kebab_name, ct);
            host::emit_toplevel(s, &kebab_name, ct);
        });
        util::emit_decls(decls).into()
    })
}
