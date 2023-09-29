use std::{borrow::Cow, collections::HashMap, ops::Deref};

/// This span_name is used when calling the current `AttributeMapper` while
/// processing event attributes.
pub const EVENT_SPAN_NAME: &str = "__EVENT__";

/// Map span attributes name to ECS field name
///
/// # Trait implementations
///
/// This trait is implemented on `HashMap<String, String>` and `HashMap<&'static str, &'static str>`
/// to allow a direct mapping from a map.
///
/// Example
///
/// ```rust
/// use tracing_ecs::ECSLayerBuilder;
/// use maplit::hashmap;
///
/// ECSLayerBuilder::default()
///     .with_attribute_mapper(hashmap!(
///         "txid" => "transaction.id",
///         "request_ip" => "source.ip",
///     )).stdout().install().unwrap();
/// ```
///
/// It is also implemented on `HashMap<String, HashMap<String, String>>` and
/// `HashMap<&'static str, HashMap<&'static str, &'static str>>`. In this case, the first map level
/// maps span names and the second attribute names.
///
/// Example
///
/// ```rust
/// use tracing_ecs::ECSLayerBuilder;
/// use maplit::hashmap;
///
/// ECSLayerBuilder::default()
///     .with_attribute_mapper(hashmap!(
///         "request" => hashmap!(
///             "method" => "http.request.method",
///             "request_ip" => "source.ip",
///         ),
///         "cron" => hashmap!(
///             "request_ip" => "cron.source.ip",
///         ),
///     )).stdout().install().unwrap();
/// ```
///
///
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

impl AttributeMapper for HashMap<String, String> {
    fn map(&self, _span_name: &str, name: Cow<'static, str>) -> Cow<'static, str> {
        self.get(name.deref())
            .cloned()
            .map(Cow::from)
            .unwrap_or(name)
    }
}

impl AttributeMapper for HashMap<&'static str, &'static str> {
    fn map(&self, _span_name: &str, name: Cow<'static, str>) -> Cow<'static, str> {
        self.get(name.deref())
            .copied()
            .map(Cow::from)
            .unwrap_or(name)
    }
}

impl AttributeMapper for HashMap<String, HashMap<String, String>> {
    fn map(&self, span_name: &str, name: Cow<'static, str>) -> Cow<'static, str> {
        self.get(span_name)
            .and_then(|span_map| span_map.get(name.deref()).cloned().map(Cow::from))
            .unwrap_or(name)
    }
}

impl AttributeMapper for HashMap<&'static str, HashMap<&'static str, &'static str>> {
    fn map(&self, span_name: &str, name: Cow<'static, str>) -> Cow<'static, str> {
        self.get(span_name)
            .and_then(|span_map| span_map.get(name.deref()).copied().map(Cow::from))
            .unwrap_or(name)
    }
}
