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

use itertools::Itertools;
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use crate::emit::{State, kebab_to_cons, kebab_to_var};
use crate::etypes::{self, Defined, Handleable, TypeBound, Tyvar, Value};
use crate::rtypes;

/// Construct a string that can be used "on the wire" to identify a
/// given function between the guest/host.  This should be replaced
/// with an integer index so that we can dispatch less dynamically in
/// the future.
pub fn emit_fn_hl_name(s: &State, kebab: &str) -> String {
    s.mod_cursor
        .iter()
        .map(|x| x.to_string())
        .chain(std::iter::once(kebab.to_string()))
        .join("::")
}

/// Emit code to unmarshal a value into a toplevel type (i.e. types
/// that cannot be represented inline in a valtype).
/// - `id`: an ident of a slice that the code will unmarshal from; also
///   used as the beginning of any other identifiers that this code
///   declares (if only we had hygiene in stable rust...)
/// - `tv`: the tyvar that we followed to get to this type
/// - `vt`: the value type that we are unmarshalling
///
/// The token stream produced will be an expression which typechecks
/// as a tuple whose first component is the Rust type (as defined by
/// the [`crate::rtypes`] module) of the given value type and whose
/// second component is an integer. The second component represents
/// the number of bytes consumed from the `id` slice while
/// unmarshalling.
pub fn emit_hl_unmarshal_toplevel_value(
    s: &mut State,
    id: Ident,
    tv: Tyvar,
    vt: &Value,
) -> TokenStream {
    let tname = rtypes::emit_var_ref_value(s, &tv);
    let mut s = s.clone();
    let Tyvar::Bound(n) = tv else {
        panic!("impossible tyvar")
    };
    s.var_offset += n as usize + 1;
    let s = &mut s;
    match vt {
        Value::Record(rfs) => {
            let cursor = format_ident!("{}_cursor", id);
            let inid = format_ident!("{}_field", id);
            let (decls, uses) = rfs
                .iter()
                .map(|rf| {
                    let field_name = kebab_to_var(rf.name.name);
                    let field_name_var = format_ident!("{}_field_{}", id, field_name);
                    let vtun = emit_hl_unmarshal_value(s, inid.clone(), &rf.ty);
                    (
                        quote! {
                            let #inid = &#id[#cursor..];
                            let (#field_name_var, b) = { #vtun };
                            #cursor += b;
                        },
                        quote! {
                            #field_name: #field_name_var,
                        },
                    )
                })
                .unzip::<_, _, Vec<_>, Vec<_>>();
            quote! {
                let mut #cursor = 0;
                #(#decls)*
                (#tname { #(#uses)* }, #cursor)
            }
        }
        Value::Flags(ns) => {
            let bytes = usize::div_ceil(ns.len(), 8);
            let fields = ns.iter().enumerate().map(|(i, n)| {
                let byte_offset = i / 8;
                let bit_offset = i % 8;
                let fieldid = kebab_to_var(n.name);
                quote! {
                    #fieldid: (#id[#byte_offset] >> #bit_offset) & 0x1 == 1,
                }
            });
            quote! {
                (#tname { #(#fields)* }, #bytes)
            }
        }
        Value::Variant(vcs) => {
            let inid = format_ident!("{}_body", id);
            let vcs = vcs.iter().enumerate().map(|(i, vc)| {
                let case_name = kebab_to_cons(vc.name.name);
                let i = i as u32;
                let case_name_var = format_ident!("{}_case_{}", id, case_name);
                match &vc.ty {
                    Some(ty) => {
                        let vtun = emit_hl_unmarshal_value(s, inid.clone(), ty);
                        quote! {
                            #i => {
                                let (#case_name_var, b) = { #vtun };
                                (#tname::#case_name(#case_name_var), b + 4)
                            }
                        }
                    }
                    None => quote! {
                        #i => (#tname::#case_name, 4)
                    },
                }
            });
            quote! {
                let n = u32::from_ne_bytes(#id[0..4].try_into().unwrap());
                let #inid = &#id[4..];
                match n {
                    #(#vcs,)*
                    _ => panic!("invalid value for variant"),
                }
            }
        }
        Value::Enum(ns) => {
            let vcs = ns.iter().enumerate().map(|(i, n)| {
                let case_name = kebab_to_cons(n.name);
                let i = i as u32;
                quote! { #i => ( #tname::#case_name, 4) }
            });
            quote! {
                let n = u32::from_ne_bytes(#id[0..4].try_into().unwrap());
                match n {
                    #(#vcs,)*
                    _ => panic!("invalid value for enum"),
                }
            }
        }
        _ => emit_hl_unmarshal_value(s, id, vt),
    }
}

/// Find the resource index that the given type variable refers to.
///
/// Precondition: this type variable does refer to a resource type
fn resolve_tyvar_to_resource(s: &mut State, v: u32) -> u32 {
    match s.bound_vars[v as usize].bound {
        TypeBound::SubResource => v,
        TypeBound::Eq(Defined::Handleable(Handleable::Var(Tyvar::Bound(vv)))) => {
            resolve_tyvar_to_resource(s, v + vv + 1)
        }
        _ => panic!("impossible: resource var is not resource"),
    }
}
/// Find the resource index that the given Handleable refers to.
///
/// Precondition: this type variable does refer to a resource type
pub fn resolve_handleable_to_resource(s: &mut State, ht: &Handleable) -> u32 {
    match ht {
        Handleable::Var(Tyvar::Bound(vi)) => {
            resolve_tyvar_to_resource(s, s.var_offset as u32 + *vi)
        }
        _ => panic!("impossible handleable in type"),
    }
}

/// Emit code to unmarshal a value into an inline-able value type
/// - `id`: an ident of a slice that the code will unmarshal from; also
///   used as the beginning of any other identifiers that this code
///   declares (if only we had hygiene in stable rust...)
/// - `vt`: the value type that we are unmarshalling
///
/// The token stream produced will be an expression which typechecks
/// as a tuple whose first component is the Rust type (as defined by
/// the [`crate::rtypes`] module) of the given value type and whose
/// second component is an integer. The second component represents
/// the number of bytes consumed from the `id` slice while
/// unmarshalling.
pub fn emit_hl_unmarshal_value(s: &mut State, id: Ident, vt: &Value) -> TokenStream {
    match vt {
        Value::Bool => quote! { (#id[0] != 0, 1) },
        Value::S(_) | Value::U(_) | Value::F(_) => {
            let (tid, width) = rtypes::numeric_rtype(vt);
            let blen = width as usize / 8;
            quote! {
                (#tid::from_ne_bytes(#id[0..#blen].try_into().unwrap()), #blen)
            }
        }
        Value::Char => quote! {
            (unsafe { char::from_u32_unchecked(u32::from_ne_bytes(
                #id[0..4].try_into().unwrap())) }, 4)
        },
        Value::String => quote! {
            let n = u32::from_ne_bytes(#id[0..4].try_into().unwrap()) as usize;
            let s = ::alloc::string::ToString::to_string(::core::str::from_utf8(&#id[4..4 + n]).unwrap()); // todo: better error handling
            (s, n + 4)
        },
        Value::List(vt) => {
            let retid = format_ident!("{}_list", id);
            let inid = format_ident!("{}_elem", id);
            let vtun = emit_hl_unmarshal_value(s, inid.clone(), vt);
            quote! {
                let n = u32::from_ne_bytes(#id[0..4].try_into().unwrap()) as usize;
                let mut #retid = alloc::vec::Vec::new();
                let mut cursor = 4;
                for i in 0..n {
                    let #inid = &#id[cursor..];
                    let (x, b) = { #vtun };
                    cursor += b;
                    #retid.push(x);
                }
                (#retid, cursor)
            }
        }
        Value::Record(_) => panic!("record not at top level of valtype"),
        Value::Tuple(vts) => {
            let inid = format_ident!("{}_elem", id);
            let len = format_ident!("{}_len", id);
            let (ns, vtuns) = vts
                .iter()
                .enumerate()
                .map(|(i, vt)| {
                    let vtun = emit_hl_unmarshal_value(s, inid.clone(), vt);
                    let retid = format_ident!("{}_elem{}", id, i);
                    (
                        retid.clone(),
                        quote! {
                            let (#retid, b) = { #vtun };
                            #len += b;
                            let #inid = &#inid[b..];
                        },
                    )
                })
                .unzip::<_, _, Vec<_>, Vec<_>>();
            quote! {
                let #inid = &#id[0..];
                let mut #len = 0;
                #(#vtuns)*
                ((#(#ns),*), #len)
            }
        }
        Value::Flags(_) => panic!("flags not at top level of valtype"),
        Value::Variant(_) => panic!("variant not at top level of valtype"),
        Value::Enum(_) => panic!("enum not at top level of valtype"),
        Value::Option(vt) => {
            let inid = format_ident!("{}_body", id);
            let vtun = emit_hl_unmarshal_value(s, inid.clone(), vt);
            quote! {
                let n = u8::from_ne_bytes(#id[0..1].try_into().unwrap());
                if n != 0 {
                    let #inid = &#id[1..];
                    let (x, b) = { #vtun };
                    (::core::option::Option::Some(x), b + 1)
                } else {
                    (::core::option::Option::None, 1)
                }
            }
        }
        Value::Result(vt1, vt2) => {
            let inid = format_ident!("{}_body", id);
            let vtun1 = if let Some(ref vt1) = **vt1 {
                emit_hl_unmarshal_value(s, inid.clone(), vt1)
            } else {
                quote! { ((), 0) }
            };
            let vtun2 = if let Some(ref vt2) = **vt2 {
                emit_hl_unmarshal_value(s, inid.clone(), vt2)
            } else {
                quote! { ((), 0) }
            };
            quote! {
                let i = u8::from_ne_bytes(#id[0..1].try_into().unwrap());
                let #inid = &#id[1..];
                if i == 0 {
                    let (x, b) = { #vtun1 };
                    (::core::result::Result::Ok(x), b + 1)
                } else {
                    let (x, b)= { #vtun2 };
                    (::core::result::Result::Err(x), b +1)
                }
            }
        }
        Value::Own(ht) => {
            let vi = resolve_handleable_to_resource(s, ht);
            log::debug!("resolved ht to r (1) {:?} {:?}", ht, vi);
            if s.is_guest {
                let rid = format_ident!("HostResource{}", vi);
                if s.is_wasmtime_guest {
                    quote! {
                        let i = u32::from_ne_bytes(#id[0..4].try_into().unwrap());
                        (::wasmtime::component::Resource::<#rid>::new_own(i), 4)
                    }
                } else {
                    quote! {
                        let i = u32::from_ne_bytes(#id[0..4].try_into().unwrap());
                        (#rid { rep: i }, 4)
                    }
                }
            } else {
                let rid = format_ident!("resource{}", vi);
                quote! {
                    let i = u32::from_ne_bytes(#id[0..4].try_into().unwrap());
                    let Some(v) = rts.#rid[i as usize].take() else {
                        // todo: better error handling
                        panic!("");
                    };
                    (v, 4)
                }
            }
        }
        Value::Borrow(ht) => {
            let vi = resolve_handleable_to_resource(s, ht);
            log::debug!("resolved ht to r (2) {:?} {:?}", ht, vi);
            if s.is_guest {
                let rid = format_ident!("HostResource{}", vi);
                quote! {
                    let i = u32::from_ne_bytes(#id[0..4].try_into().unwrap());
                    (::wasmtime::component::Resource::<#rid>::new_borrow(i), 4)
                }
            } else {
                let rid = format_ident!("resource{}", vi);
                quote! {
                    let i = u32::from_ne_bytes(#id[0..4].try_into().unwrap());
                    let Some(v) = rts.#rid[i as usize].borrow() else {
                        // todo: better error handling
                        panic!("");
                    };
                    (v, 4)
                }
            }
        }
        Value::Var(tv, _) => {
            let Some(Tyvar::Bound(n)) = tv else {
                panic!("impossible tyvar")
            };
            let (n, Some(Defined::Value(vt))) = s.resolve_tv(*n) else {
                panic!("unresolvable tyvar (2)");
            };
            let vt = vt.clone();
            emit_hl_unmarshal_toplevel_value(s, id, Tyvar::Bound(n), &vt)
        }
    }
}

/// Emit code to marshal a value from a toplevel type (i.e. types that
/// cannot be represented inline in a valtype).
/// - `id`: an ident of a Rust value of the Rust type (as defined by
///   the [`crate::rtypes`] module) of the given value type that is
///   being marshaled from
/// - `tv`: the tyvar that we followed to get to this type
/// - `vt`: the value type that we are marshaling
///
/// The token stream produced will be an expression which typechecks
/// as `Vec<u8`>`.
pub fn emit_hl_marshal_toplevel_value(
    s: &mut State,
    id: Ident,
    tv: Tyvar,
    vt: &Value,
) -> TokenStream {
    let tname = rtypes::emit_var_ref_value(s, &tv);
    let mut s = s.clone();
    let Tyvar::Bound(n) = tv else {
        panic!("impossible tyvar")
    };
    s.var_offset += n as usize + 1;
    let s = &mut s;
    match vt {
        Value::Record(rfs) => {
            let retid = format_ident!("{}_record", id);
            let fields = rfs
                .iter()
                .map(|rf| {
                    let field_name = kebab_to_var(rf.name.name);
                    let fieldid = format_ident!("{}_field_{}", id, field_name);
                    let vtun = emit_hl_marshal_value(s, fieldid.clone(), &rf.ty);
                    quote! {
                        let #fieldid = #id.#field_name;
                        #retid.extend({ #vtun });
                    }
                })
                .collect::<Vec<_>>();
            quote! {
                let mut #retid = alloc::vec::Vec::new();
                #(#fields)*
                #retid
            }
        }
        Value::Flags(ns) => {
            let bytes = usize::div_ceil(ns.len(), 8);
            let fields = ns
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    let byte_offset = i / 8;
                    let bit_offset = i % 8;
                    let fieldid = kebab_to_var(n.name);
                    quote! {
                        bytes[#byte_offset] |= (if #id.#fieldid { 1 } else { 0 }) << #bit_offset;
                    }
                })
                .collect::<Vec<_>>();
            quote! {
                let mut bytes = [0; #bytes];
                #(#fields)*
                alloc::vec::Vec::from(bytes)
            }
        }
        Value::Variant(vcs) => {
            let retid = format_ident!("{}_ret", id);
            let bodyid = format_ident!("{}_body", id);
            let vcs = vcs
                .iter()
                .enumerate()
                .map(|(i, vc)| {
                    let i = i as u32;
                    let case_name = kebab_to_cons(vc.name.name);
                    match &vc.ty {
                        Some(ty) => {
                            let vtun = emit_hl_marshal_value(s, bodyid.clone(), ty);
                            quote! {
                               #tname::#case_name(#bodyid) => {
                                    #retid.extend(u32::to_ne_bytes(#i));
                                    #retid.extend({ #vtun })
                                }
                            }
                        }
                        None => {
                            quote! {
                                #tname::#case_name => {
                                    #retid.extend(u32::to_ne_bytes(#i));
                                }
                            }
                        }
                    }
                })
                .collect::<Vec<_>>();
            quote! {
                let mut #retid = alloc::vec::Vec::new();
                match #id {
                    #(#vcs)*
                }
                #retid
            }
        }
        Value::Enum(ns) => {
            let vcs = ns.iter().enumerate().map(|(i, n)| {
                let case_name = kebab_to_cons(n.name);
                let i = i as u32;
                quote! { #tname::#case_name => #i }
            });
            quote! {
                alloc::vec::Vec::from(u32::to_ne_bytes(match #id {
                    #(#vcs,)*
                }))
            }
        }
        _ => emit_hl_marshal_value(s, id, vt),
    }
}

/// Emit code to marshal a value from an inline-able value type
/// - `id`: an ident of a Rust value of the Rust type (as defined by
///   the [`crate::rtypes`] module) of the given value type that is
///   being marshaled from
/// - `vt`: the value type that we are marshaling
///
/// The token stream produced will be an expression which typechecks
/// as `Vec<u8>`.
pub fn emit_hl_marshal_value(s: &mut State, id: Ident, vt: &Value) -> TokenStream {
    match vt {
        Value::Bool => quote! {
            alloc::vec![if #id { 1u8 } else { 0u8 }]
        },
        Value::S(_) | Value::U(_) | Value::F(_) => {
            let (tid, _) = rtypes::numeric_rtype(vt);
            quote! { alloc::vec::Vec::from(#tid::to_ne_bytes(#id)) }
        }
        Value::Char => quote! {
            alloc::vec::Vec::from((#id as u32).to_ne_bytes())
        },
        Value::String => {
            let retid = format_ident!("{}_string", id);
            let bytesid = format_ident!("{}_bytes", id);
            quote! {
                let mut #retid = alloc::vec::Vec::new();
                let #bytesid = #id.into_bytes();
                #retid.extend(alloc::vec::Vec::from(u32::to_ne_bytes(#bytesid.len() as u32)));
                #retid.extend(#bytesid);
                #retid
            }
        }
        Value::List(vt) => {
            let retid = format_ident!("{}_list", id);
            let inid = format_ident!("{}_elem", id);
            let vtun = emit_hl_marshal_value(s, inid.clone(), vt);
            quote! {
                let mut #retid = alloc::vec::Vec::new();
                let n = #id.len();
                #retid.extend(alloc::vec::Vec::from(u32::to_ne_bytes(n as u32)));
                for #inid in #id {
                    #retid.extend({ #vtun })
                }
                #retid
            }
        }
        Value::Record(_) => panic!("record not at top level of valtype"),
        Value::Tuple(vts) => {
            let retid = format_ident!("{}_tuple", id);
            let inid = format_ident!("{}_elem", id);
            let vtuns = vts.iter().enumerate().map(|(i, vt)| {
                let i = syn::Index::from(i);
                let vtun = emit_hl_marshal_value(s, inid.clone(), vt);
                quote! {
                    let #inid = #id.#i;
                    #retid.extend({ #vtun });
                }
            });
            quote! {
                let mut #retid = alloc::vec::Vec::new();
                #(#vtuns)*
                #retid
            }
        }
        Value::Flags(_) => panic!("flags not at top level of valtype"),
        Value::Variant(_) => panic!("flags not at top level of valtype"),
        Value::Enum(_) => panic!("flags not at top level of valtype"),
        Value::Option(vt) => {
            let bodyid = format_ident!("{}_body", id);
            let retid = format_ident!("{}_ret", id);
            let vtun = emit_hl_marshal_value(s, bodyid.clone(), vt);
            quote! {
                match #id {
                    ::core::option::Option::Some(#bodyid) => {
                        let mut #retid = alloc::vec::Vec::from(u8::to_ne_bytes(1));
                        #retid.extend({ #vtun });
                        #retid
                    },
                    ::core::option::Option::None => alloc::vec::Vec::from(u8::to_ne_bytes(0))
                }
            }
        }
        Value::Result(vt1, vt2) => {
            let bodyid = format_ident!("{}_body", id);
            let retid = format_ident!("{}_ret", id);
            let vtun1 = if let Some(ref vt1) = **vt1 {
                let vtun = emit_hl_marshal_value(s, bodyid.clone(), vt1);
                quote! { #retid.extend({ #vtun }); }
            } else {
                quote! {}
            };
            let vtun2 = if let Some(ref vt2) = **vt2 {
                let vtun = emit_hl_marshal_value(s, bodyid.clone(), vt2);
                quote! { #retid.extend({ #vtun }); }
            } else {
                quote! {}
            };
            quote! {
                match #id {
                    ::core::result::Result::Ok(#bodyid) => {
                        let mut #retid = alloc::vec::Vec::from(u8::to_ne_bytes(0));
                        #vtun1
                        #retid
                    },
                    ::core::result::Result::Err(#bodyid) => {
                        let mut #retid = alloc::vec::Vec::from(u8::to_ne_bytes(1));
                        #vtun2
                        #retid
                    },
                }
            }
        }
        Value::Own(ht) => {
            let vi = resolve_handleable_to_resource(s, ht);
            log::debug!("resolved ht to r (3) {:?} {:?}", ht, vi);
            if s.is_guest {
                let call = if s.is_wasmtime_guest {
                    quote! { () }
                } else {
                    quote! {}
                };
                quote! {
                    alloc::vec::Vec::from(u32::to_ne_bytes(#id.rep #call))
                }
            } else {
                let rid = format_ident!("resource{}", vi);
                quote! {
                    let i = rts.#rid.len();
                    rts.#rid.push_back(::hyperlight_common::resource::ResourceEntry::give(#id));
                    alloc::vec::Vec::from(u32::to_ne_bytes(i as u32))
                }
            }
        }
        Value::Borrow(ht) => {
            let vi = resolve_handleable_to_resource(s, ht);
            log::debug!("resolved ht to r (6) {:?} {:?}", ht, vi);
            if s.is_guest {
                let call = if s.is_wasmtime_guest {
                    quote! { () }
                } else {
                    quote! {}
                };
                quote! {
                    alloc::vec::Vec::from(u32::to_ne_bytes(#id.rep #call))
                }
            } else {
                let rid = format_ident!("resource{}", vi);
                quote! {
                    let i = rts.#rid.len();
                    rts.#rid.push_back(::hyperlight_common::resource::ResourceEntry::lend(#id));
                    alloc::vec::Vec::from(u32::to_ne_bytes(i as u32))
                }
            }
        }
        Value::Var(tv, _) => {
            let Some(Tyvar::Bound(n)) = tv else {
                panic!("impossible tyvar")
            };
            let (n, Some(Defined::Value(vt))) = s.resolve_tv(*n) else {
                panic!("unresolvable tyvar (2)");
            };
            let vt = vt.clone();
            emit_hl_marshal_toplevel_value(s, id, Tyvar::Bound(n), &vt)
        }
    }
}

/// Emit code to unmarshal a parameter with value type `pt` from a
/// slice named by `id`. The resultant token stream will be an
/// expression which typechecks at the Rust type (as defined by the
/// [`crate::rtypes`] module) of the given value type.
pub fn emit_hl_unmarshal_param(s: &mut State, id: Ident, pt: &Value) -> TokenStream {
    let toks = emit_hl_unmarshal_value(s, id, pt);
    quote! { { #toks }.0 }
}

/// Emit code to unmarshal the result of a function with result type
/// `rt` from a slice named by `id`. The resultant token stream
/// will be an expression which typechecks at the Rust type (as
/// defined by the [`crate::rtypes`] module) of the unnamed type of
/// the result, or unit if named results are used.
///
/// Precondition: the result type must only be a named result if there
/// are no names in it (i.e. a unit type)
pub fn emit_hl_unmarshal_result(s: &mut State, id: Ident, rt: &etypes::Result) -> TokenStream {
    match rt {
        etypes::Result::Named(rs) if rs.is_empty() => TokenStream::new(),
        etypes::Result::Unnamed(vt) => {
            let toks = emit_hl_unmarshal_value(s, id, vt);
            quote! { { #toks }.0 }
        }
        _ => panic!("named results not supported"),
    }
}

/// Emit code to marshal a parameter with value type `pt` from a
/// Rust value named by `id`. The resultant token stream will be an
/// expression which typechecks as `Vec<u8>`.
pub fn emit_hl_marshal_param(s: &mut State, id: Ident, pt: &Value) -> TokenStream {
    let toks = emit_hl_marshal_value(s, id, pt);
    quote! { { #toks } }
}

/// Emit code to marshal the result of a function with result type
/// `rt` from a Rust value named by `id`. The resultant token stream
/// will be an expression that which typechecks as `Vec<u8>`.
///
/// Precondition: the result type must only be a named result if there
/// are no names in it (a unit type)
pub fn emit_hl_marshal_result(s: &mut State, id: Ident, rt: &etypes::Result) -> TokenStream {
    match rt {
        etypes::Result::Named(rs) if rs.is_empty() => quote! { ::alloc::vec::Vec::new() },
        etypes::Result::Unnamed(vt) => {
            let toks = emit_hl_marshal_value(s, id, vt);
            quote! { { #toks } }
        }
        _ => panic!("named results not supported"),
    }
}
