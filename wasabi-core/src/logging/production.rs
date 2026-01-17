//! Production log formatting for CloudWatch and log aggregation.
//!
//! Plain text output with span context, no ANSI colors.
//! Format: `LEVEL target: message [span1{field=value}][span2{field=value}]`

use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields};
use tracing_subscriber::registry::LookupSpan;

/// Production log formatter with span context.
///
/// Outputs logs in a format suitable for CloudWatch and log aggregation:
/// ```text
/// INFO myapp::handler: Processing request [handle_request{path=/api/users}][parse_jwt{bearer=Bearer eyJ...}]
/// ```
pub struct ProductionLogFormat;

impl<S, N> FormatEvent<S, N> for ProductionLogFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let metadata = event.metadata();

        // Level and target
        write!(writer, "{:<5} {}: ", metadata.level(), metadata.target())?;

        // Event fields (the actual message)
        ctx.field_format().format_fields(writer.by_ref(), event)?;

        // Append span context if we have parent spans
        if let Some(scope) = ctx.event_scope() {
            let spans: Vec<_> = scope.collect();

            if !spans.is_empty() {
                write!(writer, " ")?;

                // Iterate in reverse to show outermost span first
                for span in spans.into_iter().rev() {
                    write!(writer, "[{}", span.name())?;

                    let ext = span.extensions();
                    if let Some(fields) = ext.get::<FormattedFields<N>>() {
                        if !fields.is_empty() {
                            write!(writer, "{{{}}}", fields)?;
                        }
                    }

                    write!(writer, "]")?;
                }
            }
        }

        writeln!(writer)
    }
}
