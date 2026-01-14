//! Procedural macros for the Wasabi framework.
//!
//! This crate provides derive macros that complement `wasabi-core`:
//!
//! - [`Event`] - Derive the `Event` trait for Firehose event recording
//!
//! # Usage
//!
//! This crate is re-exported through the main `wasabi` crate, so you typically
//! don't need to depend on it directly:
//!
//! ```rust,ignore
//! use wasabi::Event;
//!
//! #[derive(Event, serde::Serialize)]
//! struct UserCreated {
//!     user_id: String,
//!     email: String,
//! }
//!
//! // Event type defaults to struct name: "UserCreated"
//! ```
//!
//! # Custom Event Names
//!
//! Use the `#[event(name = "...")]` attribute to override the event type:
//!
//! ```rust,ignore
//! #[derive(Event, serde::Serialize)]
//! #[event(name = "user.created")]
//! struct UserCreated {
//!     user_id: String,
//! }
//!
//! // Event type is now "user.created"
//! ```

use darling::FromDeriveInput;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

/// Arguments parsed from `#[event(...)]` attributes.
#[derive(Debug, FromDeriveInput)]
#[darling(attributes(event))]
struct EventArgs {
    /// Custom event name. Defaults to the struct name if not specified.
    name: Option<String>,
}

/// Derives the `Event` trait for use with Firehose event recording.
///
/// The generated implementation provides an `event_type()` method that returns
/// a static string identifying the event type.
///
/// # Attributes
///
/// - `#[event(name = "custom.name")]` - Override the default event type name
///
/// # Example
///
/// ```rust,ignore
/// use wasabi::Event;
///
/// #[derive(Event, serde::Serialize)]
/// struct OrderPlaced {
///     order_id: String,
///     amount: f64,
/// }
///
/// let event = OrderPlaced { order_id: "123".into(), amount: 99.99 };
/// assert_eq!(event.event_type(), "OrderPlaced");
/// ```
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
