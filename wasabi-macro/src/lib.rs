use darling::FromDeriveInput;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[derive(Debug, FromDeriveInput)]
#[darling(attributes(event))]
struct EventArgs {
    name: Option<String>,
}

#[proc_macro_derive(Event, attributes(event))]
pub fn derive_event(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ident = &input.ident;

    let args = match EventArgs::from_derive_input(&input) {
        Ok(val) => val,
        Err(err) => return err.write_errors().into(),
    };

    let event_name = args.name.unwrap_or(ident.to_string());

    let expanded = quote! {
        impl wasabi::events::Event for #ident {
            fn event_type(&self) -> &'static str {
                #event_name
            }
        }
    };

    TokenStream::from(expanded)
}
