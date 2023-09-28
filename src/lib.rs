//! Tracing subscriber that outputs json log lines compatible with ECS
//! ([Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/ecs-reference.html)).
//!
//! More specifically, this crate provides a [`Layer`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/layer/trait.Layer.html)
//! implementation that can be composed with an existing `Subscriber` from the
//! `tracing-subscribers` crate.
//!
//! See how is implemented the [`install`](struct.ECSLayer.html#method.install) method
//! to understand what's done under the hood.
//!
//! # How spans are handled
//!
//! All spans attributes are directly appended to the final json object.
//!
//! As a result, there might be duplicate keys in the resulting json if
//! static extra fields have the same keys as some span attributes, or if
//! an attribute is named `message` (which shall be reserved to the logged event).
//!
//! This behaviour can be customized by implementing the [`AttributeMapper`](trait.AttributeMapper.html) trait.
//!
//! # Examples
//!
//! Install a default subscriber that outputs json to stdout:
//!
//! ```rust
//! ECSLayerBuilder::default()
//!     .stdout()
//!     .install()
//!     .unwrap()
//! ```
//!
//! Install a subscriber with custom extra fields that outputs
//! json to stdout (here we use the `json!` macro but it accepts
//! anything that serializes to a json map):
//!
//! ```rust
//! use serde_json::json;
//!
//! ECSLayerBuilder::default()
//!     .with_extra_fields(json!({
//!         "labels": {
//!             "env": "prod",
//!         },
//!         "tags": ["service", "foobar"]
//!     }))
//!     .unwrap()
//!     .stdout()
//!     .install()
//!     .unwrap();
//! ```
//!
//! With attributes name mapping:
//!
//! ```rust
//! ECSLayerBuilder::default()
//!  .with_attribute_mapper(
//!     |_span_name: &str, name: Cow<'static, str>| match name.deref() {
//!         "txid" => "transaction.id".into(),
//!         _ => name,
//!     },
//!  ).stdout().install().unwrap()
//! ```
use chrono::Utc;
use ser::ECSLogLine;
use serde::Serialize;
use serde_json::Map;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::io::sink;
use std::io::stderr;
use std::io::stdout;
use std::io::Stderr;
use std::io::{Stdout, Write};
use std::sync::Mutex;
use tracing_core::dispatcher::SetGlobalDefaultError;
use tracing_core::span::Attributes;
use tracing_core::span::Id;
use tracing_core::span::Record;
use tracing_core::Event;
use tracing_core::Subscriber;
use tracing_log::log_tracer::SetLoggerError;
use tracing_log::LogTracer;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::SubscriberBuilder;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

mod ser;
pub mod utils;
mod visitor;

/// This span_name is used when processing event attributes
pub const EVENT_SPAN_NAME: &'static str = "__EVENT__";

/// Map span attributes to record name
pub trait AttributeMapper: Send + Sync + 'static {
    /// Given a span name and the name of the attribute,
    /// return the mapped attribute name
    fn map(&self, span_name: &str, name: Cow<'static, str>) -> Cow<'static, str>;
}

impl<F> AttributeMapper for F
where
    F: for<'a> Fn(&'a str, Cow<'static, str>) -> Cow<'static, str> + Send + Sync + 'static,
{
    fn map(&self, span_name: &str, name: Cow<'static, str>) -> Cow<'static, str> {
        self(span_name, name)
    }
}

/// The final Layer object to be used in a `tracing-subscriber` layered subscriber.
///
pub struct ECSLayer<W>
where
    W: for<'writer> MakeWriter<'writer> + 'static,
{
    writer: W,
    attribute_mapper: Box<dyn AttributeMapper>,
    extra_fields: serde_json::Map<String, Value>,
}

impl<W> ECSLayer<W>
where
    W: for<'writer> MakeWriter<'writer> + 'static + Send + Sync,
{
    /// Installs the layer in a no-output tracing subscriber.
    ///
    /// This also takes care of installing the [`tracing-log`](https://crates.io/crates/tracing-log)
    /// compatibility layer so regular logging done from the [`log` crate](https://crates.io/crates/log)
    ///
    pub fn install(self) -> Result<(), Error> {
        let noout = SubscriberBuilder::default().with_writer(|| sink()).finish();
        let subscriber = self.with_subscriber(noout);
        tracing_core::dispatcher::set_global_default(tracing_core::dispatcher::Dispatch::new(
            subscriber,
        ))
        .map_err(Error::from)?;
        LogTracer::init().map_err(Error::from)?;

        Ok(())
    }
}

impl<W, S> Layer<S> for ECSLayer<W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'writer> MakeWriter<'writer> + 'static,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("span not found, this is a bug");

        let mut extensions = span.extensions_mut();

        if extensions.get_mut::<Map<String, Value>>().is_none() {
            let mut object = HashMap::with_capacity(16);
            let mut visitor = visitor::FieldVisitor::new(
                &mut object,
                span.name(),
                self.attribute_mapper.as_ref(),
            );
            attrs.record(&mut visitor);
            extensions.insert(object);
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("span not found, this is a bug");
        let mut extensions = span.extensions_mut();
        if let Some(object) = extensions.get_mut::<HashMap<Cow<'static, str>, Value>>() {
            let mut add_field_visitor =
                visitor::FieldVisitor::new(object, span.name(), self.attribute_mapper.as_ref());
            values.record(&mut add_field_visitor);
        } else {
            let mut object = HashMap::with_capacity(16);
            let mut add_field_visitor = visitor::FieldVisitor::new(
                &mut object,
                span.name(),
                self.attribute_mapper.as_ref(),
            );
            values.record(&mut add_field_visitor);
            extensions.insert(object)
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        // GELF object
        let mut span_fields = HashMap::<Cow<'static, str>, Value>::new();

        // Get span name
        let span = ctx.current_span().id().and_then(|id| {
            ctx.span_scope(id).map(|scope| {
                scope.from_root().fold(String::new(), |mut spans, span| {
                    // Add span fields to the base object
                    if let Some(span_object) =
                        span.extensions().get::<HashMap<Cow<'static, str>, Value>>()
                    {
                        span_fields.extend(span_object.clone());
                    }
                    if !spans.is_empty() {
                        spans = format!("{}:{}", spans, span.name());
                    } else {
                        spans = span.name().to_string();
                    }

                    spans
                })
            })
        });

        if let Some(span) = span {
            span_fields.insert("span.name".into(), span.into());
        }

        // Extract metadata
        // Insert level
        let metadata = event.metadata();
        let level = metadata.level().as_str();
        let target = metadata.target();

        // extract fields
        let mut fields = HashMap::with_capacity(16);
        let mut visitor = visitor::FieldVisitor::new(
            &mut fields,
            EVENT_SPAN_NAME,
            self.attribute_mapper.as_ref(),
        );
        event.record(&mut visitor);
        let message = fields
            .remove("message")
            .map(|v| v.to_string())
            .unwrap_or_default();
        let line = ECSLogLine {
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            message,
            level,
            log_origin: metadata.into(),
            logger: target,
            dynamic_fields: self
                .extra_fields
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .chain(
                    span_fields
                        .into_iter()
                        .map(|(key, value)| (key.to_string(), value)),
                )
                .chain(
                    fields
                        .into_iter()
                        .map(|(key, value)| (key.to_string(), value)),
                )
                .collect(),
        };
        let mut writer = self.writer.make_writer_for(metadata);
        let _ = serde_json::to_writer(writer.by_ref(), &line);
        let _ = writer.write(&[b'\n']);
    }
}

/// Builder for a subscriber Layer writing ECS compatible json lines to a writer.
///
/// Example:
///
/// ```rust
/// // creates a minimal layer logging to stdout, and install it
/// ECSLoggerBuilder::default()
///     .stdout()
///     .install()
///     .unwrap();
/// ```
///
#[derive(Default)]
pub struct ECSLayerBuilder {
    extra_fields: Option<serde_json::Map<String, Value>>,
    attribute_mapper: Box<dyn AttributeMapper>,
}

impl Default for Box<dyn AttributeMapper> {
    fn default() -> Self {
        Box::new(|_span_name: &str, name: Cow<'static, str>| name)
    }
}

impl ECSLayerBuilder {
    pub fn with_extra_fields<F: Serialize>(mut self, extra_fields: F) -> Result<Self, Error> {
        let as_json = serde_json::to_value(&extra_fields)
            .map_err(|_| Error::ExtraFieldNotSerializableAsJson)?;
        match as_json {
            Value::Object(extra_fields) => {
                self.extra_fields = Some(extra_fields);
                Ok(self)
            }
            _ => Err(Error::ExtraFieldNotAMap),
        }
    }

    pub fn with_attribute_mapper<M>(mut self, attribute_mapper: M) -> Self
    where
        M: AttributeMapper,
    {
        self.attribute_mapper = Box::new(attribute_mapper);
        self
    }

    pub fn stderr(self) -> ECSLayer<fn() -> Stderr> {
        self.with_writer(io::stderr)
    }

    pub fn stdout(self) -> ECSLayer<fn() -> Stdout> {
        self.with_writer(io::stdout)
    }

    pub fn with_writer<W>(self, writer: W) -> ECSLayer<W>
    where
        W: for<'writer> MakeWriter<'writer> + 'static,
    {
        ECSLayer {
            writer,
            attribute_mapper: self.attribute_mapper,
            extra_fields: self.extra_fields.unwrap_or_default(),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Extra field cannot be serialized as json")]
    ExtraFieldNotSerializableAsJson,
    #[error("Extra field must be serializable as a json map")]
    ExtraFieldNotAMap,
    #[error("{0}")]
    SetGlobalError(#[from] SetGlobalDefaultError),
    #[error("{0}")]
    SetLoggerError(#[from] SetLoggerError),
}

#[cfg(test)]
mod test {

    use std::{borrow::Cow, ops::Deref};

    use serde::Serialize;
    use serde_json::json;
    use tracing::span;
    use tracing_core::Level;

    use crate::{
        utils::{Labels, Tags},
        ECSLayerBuilder,
    };

    #[derive(Serialize)]
    struct ExtraTestField {
        tags: Tags,
        labels: Labels,
    }

    #[test]
    fn test() {
        let buf: &'static mut Vec<u8> = Box::leak(Box::new(Vec::new()));
        ECSLayerBuilder::default()
            //.with_writer(buf)
            .with_extra_fields(ExtraTestField {
                tags: vec!["tag1".into(), "tag2".to_string().into()],
                labels: [("l1".into(), "v1".into()), ("l2".into(), "v2".into())]
                    .into_iter()
                    .collect(),
            })
            .unwrap()
            .stdout()
            .install()
            .unwrap();

        tracing::error!("this is an error");

        let span = span!(Level::INFO, "my span", myvalue = 112);
        let _enter = span.enter();
        let span = span!(Level::INFO, "nested", tx.id = "123", user = "jean");
        let _enter = span.enter();
        tracing::info!("plop");
    }
    #[test]
    fn test_extra_fields_json() {
        ECSLayerBuilder::default()
            .with_extra_fields(json!({
                "labels": {
                    "env": "prod",
                },
                "tags": ["service", "foobar"]
            }))
            .unwrap()
            .stdout()
            .install()
            .unwrap();
        tracing::info!("Alright!");
    }

    #[test]
    fn test_attribute_name_mapping() {
        ECSLayerBuilder::default()
            .with_attribute_mapper(
                |_span_name: &str, name: Cow<'static, str>| match name.deref() {
                    "txid" => "transaction.id".into(),
                    _ => name,
                },
            )
            .stdout()
            .install()
            .unwrap();
        let span = span!(Level::INFO, "my span", txid = 112, other = "hello");
        let _enter = span.enter();
        tracing::info!("Alright!");

        tracing::event!(Level::INFO, greetings = "hello")
    }
}
