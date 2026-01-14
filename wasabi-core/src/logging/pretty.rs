use nu_ansi_term::{Color, Style};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields};
use tracing_subscriber::registry::LookupSpan;

pub struct PrettyConsoleLogFormat;

macro_rules! styled {
    ($writer:expr, $style:expr, $block:block) => {
        let style = $style;
        write!($writer, "{}", style.prefix())?;
        $block;
        write!($writer, "{}", style.suffix())?;
    };
}

impl PrettyConsoleLogFormat {
    fn format_timestamp(writer: &mut Writer) -> std::fmt::Result {
        styled!(writer, Style::new().dimmed(), {
            write!(writer, "{} ", chrono::offset::Local::now().format("%T%.3f"))?;
        });

        Ok(())
    }

    fn format_level(writer: &mut Writer, event: &Event<'_>) -> std::fmt::Result {
        let metadata = event.metadata();
        let style = match *event.metadata().level() {
            Level::TRACE => Style::new().fg(Color::Purple),
            Level::DEBUG => Style::new().fg(Color::Blue),
            Level::INFO => Style::new().fg(Color::Green),
            Level::WARN => Style::new().fg(Color::Yellow),
            Level::ERROR => Style::new().fg(Color::Red),
        };

        styled!(writer, style, {
            write!(writer, "{:<5}", metadata.level(),)?;
        });

        Ok(())
    }

    fn format_nesting(writer: &mut Writer, nesting: usize) -> std::fmt::Result {
        styled!(writer, Style::new().fg(Color::Magenta), {
            write!(writer, " ")?;
            for _ in 0..nesting {
                write!(writer, "|")?;
            }
        });

        Ok(())
    }

    fn format_target(writer: &mut Writer, event: &Event<'_>) -> std::fmt::Result {
        styled!(writer, Style::new().dimmed(), {
            write!(writer, "{}: ", event.metadata().target())?;
        });

        Ok(())
    }

    fn format_new_span<S, N>(
        writer: &mut Writer,
        ctx: &FmtContext<'_, S, N>,
        event: &Event<'_>,
    ) -> std::fmt::Result
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
        N: for<'a> FormatFields<'a> + 'static,
    {
        if let Some(mut scope) = ctx.event_scope() {
            if event.metadata().is_span()
                && let Some(span) = scope.next()
            {
                    styled!(writer, Style::new().fg(Color::Magenta), {
                        write!(writer, "=> ")?;
                    });

                    Self::format_target(writer, event)?;
                    write!(writer, "{}", span.name())?;

                    let ext = span.extensions();
                    let fields = &ext
                        .get::<FormattedFields<N>>()
                        .expect("will never be `None`");

                    if !fields.is_empty() {
                        write!(writer, "{{{}}}", fields)?;
                    }
            }
        } else {
            Self::format_target(writer, event)?;
            write!(writer, "new")?;
        }

        Ok(())
    }
}
impl<S, N> FormatEvent<S, N> for PrettyConsoleLogFormat
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
        Self::format_timestamp(&mut writer)?;
        Self::format_level(&mut writer, event)?;

        if let Some(scope) = ctx.event_scope() {
            Self::format_nesting(&mut writer, scope.count())?;
        }

        write!(writer, " ")?;

        let mut fields_buf = String::new();
        ctx.field_format()
            .format_fields(Writer::new(&mut fields_buf), event)?;

        if event.metadata().is_span() && fields_buf == "new" {
            Self::format_new_span(&mut writer, ctx, event)?;
        } else {
            Self::format_target(&mut writer, event)?;
            write!(writer, "{}", fields_buf)?;
        }

        writeln!(writer)
    }
}
