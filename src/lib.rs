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
//! # JSON Normalization
//!
//! Output is normalized by default so there is no dot anymore in the resulting json keys. See
//! <https://www.elastic.co/guide/en/ecs/current/ecs-guidelines.html>
//!
//! See [ECSLayerBuilder.normalize_json](struct.ECSLayerBuilder.html#method.normalize_json)
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
use ser::ECSSpanEvent;
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
use std::io::Stdout;
use std::io::Write;
use std::sync::Mutex;
use tracing_core::dispatcher::SetGlobalDefaultError;
use tracing_core::span::Attributes;
use tracing_core::span::Id;
use tracing_core::span::Record;
use tracing_core::Event;
use tracing_core::Subscriber;
use tracing_log::log_tracer::SetLoggerError;
use tracing_log::LogTracer;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::SubscriberBuilder;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;

mod attribute_mapper;
mod ser;
mod visitor;

pub use attribute_mapper::{AttributeMapper, EVENT_SPAN_NAME};

/// The final Layer object to be used in a `tracing-subscriber` layered subscriber.
///
pub struct ECSLayer<W>
where
    W: for<'writer> MakeWriter<'writer> + 'static,
{
    writer: Mutex<W>,
    attribute_mapper: Box<dyn AttributeMapper>,
    extra_fields: serde_json::Map<String, Value>,
    normalize_json: bool,
    span_events: FmtSpan,
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
            .with_span_events(FmtSpan::EXIT)
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

impl<W> ECSLayer<W>
where
    W: for<'writer> MakeWriter<'writer> + 'static,
{
    fn log_span_event<S: Subscriber + for<'a> LookupSpan<'a>>(
        &self,
        id: &Id,
        ctx: &Context<'_, S>,
        event_action: &'static str,
    ) {
        let span = ctx.span(id).expect("span not found, this is a bug");
        let span_name = span.name();
        let span_id = id.into_u64().to_string();

        let mut span_fields = HashMap::<Cow<'static, str>, Value>::new();
        if let Some(span_object) = span.extensions().get::<HashMap<Cow<'static, str>, Value>>() {
            span_fields.extend(span_object.clone());
        }

        let span_event = ECSSpanEvent {
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            event_kind: "span",
            event_action,
            span_id,
            span_name: span_name.to_string(),
            dynamic_fields: self
                .extra_fields
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .chain(
                    span_fields
                        .into_iter()
                        .map(|(key, value)| (key.to_string(), value)),
                )
                .collect(),
        };

        let writer = self.writer.lock().unwrap();
        let mut writer = writer.make_writer();
        let _ = if self.normalize_json {
            serde_json::to_writer(writer.by_ref(), &span_event.normalize())
        } else {
            serde_json::to_writer(writer.by_ref(), &span_event)
        };
        let _ = writer.write(&[b'\n']);
    }
}

impl<W, S> Layer<S> for ECSLayer<W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'writer> MakeWriter<'writer> + 'static,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if self.span_events.clone() & FmtSpan::NEW == FmtSpan::NEW {
            self.log_span_event(id, &ctx, "new");
        }

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
            extensions.insert(object);
        }
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        if self.span_events.clone() & FmtSpan::ENTER == FmtSpan::ENTER {
            self.log_span_event(id, &ctx, "enter");
        }
    }

    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        if self.span_events.clone() & FmtSpan::EXIT == FmtSpan::EXIT {
            self.log_span_event(id, &ctx, "exit");
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        if self.span_events.clone() & FmtSpan::CLOSE == FmtSpan::CLOSE {
            self.log_span_event(&id, &ctx, "close");
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
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
                };
            }
        }

        let message = fields
            .remove("message")
            .map(value_to_string)
            .unwrap_or_default();
        let line = ECSLogLine {
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
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
        let writer = self.writer.lock().unwrap(); // below code will not poison the lock so it should be safe here to unwrap()
        let mut writer = writer.make_writer_for(metadata);
        let _ = if self.normalize_json {
            serde_json::to_writer(writer.by_ref(), &line.normalize())
        } else {
            serde_json::to_writer(writer.by_ref(), &line)
        };
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
pub struct ECSLayerBuilder {
    extra_fields: Option<serde_json::Map<String, Value>>,
    attribute_mapper: Box<dyn AttributeMapper>,
    normalize_json: bool,
    span_events: FmtSpan,
}

impl Default for ECSLayerBuilder {
    fn default() -> Self {
        Self {
            extra_fields: Default::default(),
            attribute_mapper: Default::default(),
            normalize_json: true,
            span_events: FmtSpan::NONE,
        }
    }
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

    pub fn with_span_events(mut self, span_events: FmtSpan) -> Self {
        self.span_events = span_events;
        self
    }

    /// Control the normalization (keys de-dotting) of the generated json
    /// in the sense of <https://www.elastic.co/guide/en/ecs/current/ecs-guidelines.html>.
    ///
    /// By default, normalization is enabled, thus logging `host.hostname="localhost"` will output:
    ///
    /// ```json
    /// {"host":{"hostname": "localhost"}}
    /// ```
    ///
    /// With normalization disabled:
    ///
    /// ```json
    /// {"host.hostname": "localhost"}
    /// ```
    ///
    /// Depending on your use case you may want to disable normalization if it's done
    /// elsewhere in your log processing pipeline.
    ///
    /// Benchmarks suggests a 30% speed up on log generation. (benches run on an Apple M2 Pro) it will
    /// also allocate less because, normalization recursively recreates a brand new json `Value` (not measured).
    ///
    pub fn normalize_json(self, normalize_json: bool) -> Self {
        Self {
            normalize_json,
            ..self
        }
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
            writer: Mutex::new(writer),
            attribute_mapper: self.attribute_mapper,
            extra_fields: self.extra_fields.unwrap_or_default(),
            normalize_json: self.normalize_json,
            span_events: self.span_events,
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
        io::{self, sink, BufRead, BufReader},
        sync::{Arc, Mutex, MutexGuard, Once, TryLockError},
        thread::{self},
    };

    use maplit::hashmap;
    use serde_json::{json, Map, Value};
    use tracing_log::LogTracer;
    use tracing_subscriber::{
        fmt::{format::FmtSpan, MakeWriter, SubscriberBuilder},
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
        assert_string(result[0].get("span"), None);
        assert_string(result[1].get("span"), None);
        assert_string(result[2].get("span").unwrap().get("name"), Some("span1"));
        assert_string(result[4].get("span.name"), None);
        assert_string(result[3].get("span").unwrap().get("name"), Some("span1"));
        assert_string(result[0].get("transaction"), None);
        assert_string(result[1].get("transaction"), None);
        assert_string(
            result[2].get("transaction").unwrap().get("id"),
            Some("abcdef"),
        );
        assert_string(
            result[3].get("transaction").unwrap().get("id"),
            Some("abcdef"),
        );
        assert_string(result[4].get("transaction"), None);

        // log.logger (aka rust target)
        assert_string(
            result[0].get("log").unwrap().get("logger"),
            Some("tracing_ecs::test"),
        );
        assert_string(
            result[1].get("log").unwrap().get("logger"),
            Some("tracing_ecs::test"),
        );
        assert_string(
            result[2].get("log").unwrap().get("logger"),
            Some("tracing_ecs::test"),
        );
        assert_string(
            result[3].get("log").unwrap().get("logger"),
            Some("foo_event_target"),
        );
        assert_string(
            result[4].get("log").unwrap().get("logger"),
            Some("foo_bar_target"),
        );

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
        // span name (note that json is normalized so there is no dot anymore in keys)
        assert_string(result[0].get("span"), None);
        assert_string(result[1].get("span").unwrap().get("name"), Some("span1"));
        assert_string(
            result[2].get("span").unwrap().get("name"),
            Some("span1:span2"),
        );
        assert_string(
            result[3].get("span").unwrap().get("name"),
            Some("span1:span2"),
        );

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
                hashmap! {
                    "span1" => hashmap! {
                        "key1" => "foobar"
                    }
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

    #[test]
    fn test_normalization() {
        let value = json!({
            "host.hostname": "localhost"
        });
        let result = run_test(
            ECSLayerBuilder::default()
                .with_extra_fields(&value)
                .unwrap(),
            || {
                tracing::info!(source.ip = "1.2.3.4", "hello world");
            },
        );
        assert_eq!(
            result[0].get("host").unwrap(),
            &json!({
                "hostname": "localhost",
            })
        );
        assert_eq!(
            result[0].get("source").unwrap(),
            &json!({
                "ip": "1.2.3.4",
            })
        );
    }
    #[test]

    fn test_normalization_disabled() {
        let value = json!({
            "host.hostname": "localhost"
        });
        let result = run_test(
            ECSLayerBuilder::default()
                .normalize_json(false)
                .with_extra_fields(&value)
                .unwrap(),
            || {
                tracing::info!(source.ip = "1.2.3.4", "hello world");
            },
        );
        assert_eq!(result[0].get("host.hostname").unwrap(), &json!("localhost"));
        assert_eq!(result[0].get("source.ip").unwrap(), &json!("1.2.3.4"));
    }

    #[test]
    fn test_interleaving_logs() {
        let result = run_test(ECSLayerBuilder::default(), || {
            let mut join_handles = Vec::new();
            for i in 0..5 {
                // doing multi threaded test is a bit awkward as the current dispatcher needs
                // to be installed into each spawned thread.
                tracing_core::dispatcher::get_default(|dispatch| {
                    let dispatch = dispatch.clone();
                    join_handles.push(thread::spawn(move || {
                        tracing_core::dispatcher::with_default(&dispatch, move || {
                            for j in 0..1000 {
                                tracing::info!(thread = i, iteration = j, "hello world");
                            }
                        });
                    }));
                });
            }
            for join_handle in join_handles {
                join_handle.join().unwrap();
            }
        });
        assert_eq!(result.len(), 5000);
    }

    #[test]
    fn test_span_instrumentation() {
        let result = run_test(
            ECSLayerBuilder::default()
                .normalize_json(false)
                .with_span_events(FmtSpan::ENTER | FmtSpan::EXIT),
            || {
                let span = tracing::info_span!("test_span", foo = "bar");
                let _enter = span.enter();
                tracing::info!("inside span");
            },
        );

        assert_eq!(result.len(), 3); // span enter, event, span exit

        assert_eq!(result[0].get("event.kind"), Some(&json!("span")));
        assert_eq!(result[0].get("event.action"), Some(&json!("enter")));
        assert_eq!(result[0].get("span.name"), Some(&json!("test_span")));
        assert_eq!(result[0].get("foo"), Some(&json!("bar")));
        assert!(result[0].get("span.id").unwrap().is_string());

        assert_eq!(result[1].get("message"), Some(&json!("inside span")));
        assert_eq!(result[1].get("span.name"), Some(&json!("test_span")));
        assert_eq!(result[1].get("foo"), Some(&json!("bar")));

        assert_eq!(result[2].get("event.kind"), Some(&json!("span")));
        assert_eq!(result[2].get("event.action"), Some(&json!("exit")));
        assert_eq!(result[2].get("span.name"), Some(&json!("test_span")));
        assert_eq!(result[2].get("foo"), Some(&json!("bar")));
        assert_eq!(result[2].get("span.id"), result[0].get("span.id"));
    }
}
