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
//! This behavior can be customized by implementing the [`AttributeMapper`](trait.AttributeMapper.html) trait.
//!
//! # Examples
//!
//! Install a default subscriber that outputs json to stdout:
//!
//! ```rust
//! use tracing_ecs::ECSLayerBuilder;
//!
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
//! use tracing_ecs::ECSLayerBuilder;
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
//! use tracing_ecs::ECSLayerBuilder;
//! use std::borrow::Cow;
//! use std::ops::Deref;
//!
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
use ser::LogFile;
use ser::LogOrigin;
use serde::Serialize;
use serde_json::Map;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::io::sink;
use std::io::Stderr;
use std::io::{Stdout, Write};
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
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;

mod ser;
mod visitor;

/// This span_name is used when calling the current `AttributeMapper` while
/// processing event attributes.
pub const EVENT_SPAN_NAME: &str = "__EVENT__";

/// Map span attributes name to ECS field name
pub trait AttributeMapper: Send + Sync + 'static {
    /// Given a span name and the name of an attribute,
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
    /// The tracing subscriber is configured with `EnvFilter::from_default_env()`.
    ///
    /// This also takes care of installing the [`tracing-log`](https://crates.io/crates/tracing-log)
    /// compatibility layer so regular logging done from the [`log` crate](https://crates.io/crates/log) will
    /// be correctly reported as tracing events.
    ///
    /// This is an opinionated way to use this layer. Look at the source of this method if you want a tight control
    /// of how the underlying subscriber is constructed or if you want to disable classic logs to be output as tracing events...
    ///
    pub fn install(self) -> Result<(), Error> {
        let noout = SubscriberBuilder::default()
            .with_writer(sink)
            .with_env_filter(EnvFilter::from_default_env())
            .finish();
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
        let mut target = metadata.target().to_string();

        // extract fields
        let mut fields = HashMap::with_capacity(16);
        let mut visitor = visitor::FieldVisitor::new(
            &mut fields,
            EVENT_SPAN_NAME,
            self.attribute_mapper.as_ref(),
        );
        event.record(&mut visitor);

        // detect classic log message and convert them to our format
        let mut log_origin = LogOrigin::from(metadata);
        if target == "log"
            && fields.contains_key("log.target")
            && fields.contains_key("log.module_path")
        {
            fields.remove("log.module_path");
            target = value_to_string(fields.remove("log.target").unwrap()); // this is tested in the if condition

            if let (Some(file), Some(line)) = (fields.remove("log.file"), fields.remove("log.line"))
            {
                log_origin = LogOrigin {
                    file: LogFile {
                        line: line.as_u64().and_then(|u| u32::try_from(u).ok()),
                        name: file.as_str().map(|file| file.to_owned().into()),
                    },
                }
            }
        }

        let message = fields
            .remove("message")
            .map(value_to_string)
            .unwrap_or_default();
        let line = ECSLogLine {
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            message,
            level,
            log_origin,
            logger: &target,
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

fn value_to_string(value: Value) -> String {
    match value {
        Value::String(string) => string,
        _ => value.to_string(),
    }
}

/// Builder for a subscriber Layer writing ECS compatible json lines to a writer.
///
/// Example:
///
/// ```rust
/// use tracing_ecs::ECSLayerBuilder;
///
/// // creates a minimal layer logging to stdout, and install it
/// ECSLayerBuilder::default()
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
        self.build_with_writer(io::stderr)
    }

    pub fn stdout(self) -> ECSLayer<fn() -> Stdout> {
        self.build_with_writer(io::stdout)
    }

    pub fn build_with_writer<W>(self, writer: W) -> ECSLayer<W>
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

    use std::{
        borrow::{Borrow, Cow},
        io::{self, sink, BufRead, BufReader},
        sync::{Arc, Mutex, MutexGuard, Once, TryLockError},
    };

    use serde_json::{json, Map, Value};
    use tracing_log::LogTracer;
    use tracing_subscriber::{
        fmt::{MakeWriter, SubscriberBuilder},
        Layer,
    };

    use crate::ECSLayerBuilder;

    static START: Once = Once::new();

    pub(crate) struct MockWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl MockWriter {
        pub(crate) fn new(buf: Arc<Mutex<Vec<u8>>>) -> Self {
            Self { buf }
        }

        pub(crate) fn map_error<Guard>(err: TryLockError<Guard>) -> io::Error {
            match err {
                TryLockError::WouldBlock => io::Error::from(io::ErrorKind::WouldBlock),
                TryLockError::Poisoned(_) => io::Error::from(io::ErrorKind::Other),
            }
        }

        pub(crate) fn buf(&self) -> io::Result<MutexGuard<'_, Vec<u8>>> {
            self.buf.try_lock().map_err(Self::map_error)
        }
    }

    impl io::Write for MockWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buf()?.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.buf()?.flush()
        }
    }

    #[derive(Clone, Default)]
    pub(crate) struct MockMakeWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl MockMakeWriter {
        pub(crate) fn buf(&self) -> MutexGuard<'_, Vec<u8>> {
            self.buf.lock().unwrap()
        }
    }

    impl<'a> MakeWriter<'a> for MockMakeWriter {
        type Writer = MockWriter;

        fn make_writer(&'a self) -> Self::Writer {
            MockWriter::new(self.buf.clone())
        }
    }

    fn run_test<T>(builder: ECSLayerBuilder, test: T) -> Vec<Map<String, Value>>
    where
        T: FnOnce() -> (),
    {
        START.call_once(|| LogTracer::init().unwrap());

        let writer = MockMakeWriter::default();

        let noout = SubscriberBuilder::default().with_writer(|| sink()).finish();
        let subscriber = builder
            .build_with_writer(writer.clone())
            .with_subscriber(noout);
        tracing_core::dispatcher::with_default(
            &tracing_core::dispatcher::Dispatch::new(subscriber),
            test,
        );
        let bytes: Vec<u8> = writer.buf().iter().copied().collect();
        let mut ret = Vec::new();
        for line in BufReader::new(bytes.as_slice()).lines() {
            let line = line.expect("Unable to read line");
            println!("{line}");
            ret.push(serde_json::from_str(&line).expect("Invalid json line"));
        }
        ret
    }

    /// General tests
    #[test]
    fn test() {
        let result = run_test(ECSLayerBuilder::default(), || {
            log::info!("A classic log message outside spans");
            tracing::info!("A classic tracing event outside spans");
            let span = tracing::info_span!("span1", foo = "bar", transaction.id = "abcdef");
            let enter = span.enter();
            log::info!("A classic log inside a span");
            tracing::info!(target: "foo_event_target", "A classic tracing event inside a span");
            drop(enter);
            log::info!(target: "foo_bar_target", "outside a span");
        });
        assert_eq!(result.len(), 5);
        assert_string(
            result[0].get("message"),
            Some("A classic log message outside spans"),
        );
        assert_string(
            result[1].get("message"),
            Some("A classic tracing event outside spans"),
        );
        assert_string(
            result[2].get("message"),
            Some("A classic log inside a span"),
        );
        assert_string(
            result[3].get("message"),
            Some("A classic tracing event inside a span"),
        );
        assert_string(result[0].get("span.name"), None);
        assert_string(result[1].get("span.name"), None);
        assert_string(result[2].get("span.name"), Some("span1"));
        assert_string(result[4].get("span.name"), None);
        assert_string(result[3].get("span.name"), Some("span1"));
        assert_string(result[0].get("transaction.id"), None);
        assert_string(result[1].get("transaction.id"), None);
        assert_string(result[2].get("transaction.id"), Some("abcdef"));
        assert_string(result[3].get("transaction.id"), Some("abcdef"));
        assert_string(result[4].get("transaction.id"), None);

        // log.logger (aka rust target)
        assert_string(result[0].get("log.logger"), Some("tracing_ecs::test"));
        assert_string(result[1].get("log.logger"), Some("tracing_ecs::test"));
        assert_string(result[2].get("log.logger"), Some("tracing_ecs::test"));
        assert_string(result[3].get("log.logger"), Some("foo_event_target"));
        assert_string(result[4].get("log.logger"), Some("foo_bar_target"));

        // logs have a @timestamp value
        assert!(result[0]
            .get("@timestamp")
            .cloned()
            .filter(Value::is_string)
            .is_some());
        assert!(result[1]
            .get("@timestamp")
            .cloned()
            .filter(Value::is_string)
            .is_some());
    }

    fn assert_string(value: Option<&Value>, expected: Option<&str>) {
        assert_eq!(
            value,
            expected.map(|s| Value::String(s.to_string())).as_ref()
        );
    }

    /// Extra fields: we can pass anything that is Serialize as extra fields
    #[test]
    fn test_extra_fields() {
        let value = json!({
            "tags": ["t1", "t2"],
            "labels": {
                "env": "prod",
                "service": "foobar",
            }
        });
        let result = run_test(
            ECSLayerBuilder::default()
                .with_extra_fields(&value)
                .unwrap(),
            || {
                log::info!("A classic log message outside spans");
                tracing::info!("A classic tracing event outside spans");
                tracing::info!(tags = 123, "A classic tracing event outside spans");
            },
        );
        assert_eq!(result.len(), 3);
        assert_string(
            result[0].get("message"),
            Some("A classic log message outside spans"),
        );
        assert_string(
            result[1].get("message"),
            Some("A classic tracing event outside spans"),
        );
        assert_eq!(result[0].get("tags"), value.get("tags"));
        assert_eq!(result[1].get("tags"), value.get("tags"));
        assert_eq!(result[1].get("labels"), value.get("labels"));
        assert_eq!(result[1].get("labels"), value.get("labels"));

        // a span or an event overrode the tags value, the last prevails (in our case the event value)
        assert_eq!(result[2].get("tags"), Some(&json!(123)));
    }

    #[test]
    fn test_spans() {
        let result = run_test(ECSLayerBuilder::default(), || {
            tracing::info!("outside");
            let sp1 = tracing::info_span!("span1", sp1 = "val1", same = "same1");
            let _enter1 = sp1.enter();
            tracing::info!("inside 1");
            let sp2 = tracing::info_span!("span2", sp2 = "val2", same = "same2");
            let _enter2 = sp2.enter();
            tracing::info!("inside 2");
            tracing::info!(same = "last prevails", "inside 2");
        });
        // span name
        assert_string(result[0].get("span.name"), None);
        assert_string(result[1].get("span.name"), Some("span1"));
        assert_string(result[2].get("span.name"), Some("span1:span2"));
        assert_string(result[3].get("span.name"), Some("span1:span2"));

        // span attributes
        assert_string(result[0].get("sp1"), None);
        assert_string(result[1].get("sp1"), Some("val1"));
        assert_string(result[2].get("sp1"), Some("val1"));
        assert_string(result[3].get("sp1"), Some("val1"));

        assert_string(result[0].get("sp2"), None);
        assert_string(result[1].get("sp2"), None);
        assert_string(result[2].get("sp2"), Some("val2"));
        assert_string(result[3].get("sp2"), Some("val2"));

        assert_string(result[0].get("same"), None);
        assert_string(result[1].get("same"), Some("same1"));
        assert_string(result[2].get("same"), Some("same2"));
        assert_string(result[3].get("same"), Some("last prevails"));
    }

    #[test]
    fn test_attribute_mapping() {
        let result = run_test(
            ECSLayerBuilder::default().with_attribute_mapper(
                // this mapper will change "key1" name into "foobar" only in the "span1" span
                |span_name: &str, name: Cow<'static, str>| match span_name {
                    "span1" => match name.borrow() {
                        "key1" => "foobar".into(),
                        _ => name,
                    },
                    _ => name,
                },
            ),
            || {
                let sp1 = tracing::info_span!("span1", key1 = "val1", other1 = "o1");
                let _enter1 = sp1.enter();
                tracing::info!("inside 1");
                let sp2 = tracing::info_span!("span2", key1 = "val2", other2 = "o2");
                let _enter2 = sp2.enter();
                tracing::info!("inside 2");
            },
        );

        // span1 => key1 has been renamed
        assert_string(result[0].get("key1"), None);
        assert_string(result[0].get("foobar"), Some("val1"));
        assert_string(result[0].get("other1"), Some("o1"));
        assert_string(result[0].get("other2"), None);
        // span2 => key1 renamed in span1... but also defined in span2
        assert_string(result[1].get("key1"), Some("val2"));
        assert_string(result[1].get("foobar"), Some("val1"));
        assert_string(result[1].get("other1"), Some("o1"));
        assert_string(result[1].get("other2"), Some("o2"));
    }
}
