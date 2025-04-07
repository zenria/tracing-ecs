//! Types used in json serialization
//
use serde::Serialize;
use serde_json::{Map, Value};
use std::borrow::Cow;
use tracing_core::Metadata;

#[derive(Serialize)]
pub(crate) struct ECSLogLine<'a> {
    #[serde(rename = "@timestamp")]
    pub(crate) timestamp: String,

    pub(crate) message: String,

    #[serde(rename = "log.level")]
    pub(crate) level: &'static str,

    #[serde(rename = "log.logger")]
    pub(crate) logger: &'a str,

    #[serde(flatten)]
    #[serde(skip_serializing_if = "LogOrigin::is_empty")]
    pub(crate) log_origin: LogOrigin<'a>,

    #[serde(flatten)]
    pub(crate) dynamic_fields: serde_json::Map<String, Value>,
}

impl<'a> ECSLogLine<'a> {
    /// Normalize JSON dotted fields to nested maps. Aka de-dot fields into nested json objects.
    ///
    /// https://www.elastic.co/guide/en/ecs/current/ecs-guidelines.html
    ///
    /// > The document structure should be nested JSON objects. If you use Beats or Logstash,
    /// > the nesting of JSON objects is done for you automatically. If you’re ingesting
    /// > to Elasticsearch using the API, your fields must be nested objects, not strings containing dots.
    pub(crate) fn normalize(&self) -> Value {
        let ser = serde_json::to_value(self).unwrap(); // by construction this will not fail - trust me

        let Value::Object(obj) = ser else {
            panic!("this is not possible!")
        };

        let mut ret: Map<String, Value> = Map::with_capacity(obj.len());

        normalize_map(&mut ret, obj);

        Value::Object(ret)
    }
}

#[derive(Serialize)]
pub(crate) struct LogOrigin<'a> {
    #[serde(rename = "log.origin.file.line")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) line: Option<u32>,
    #[serde(rename = "log.origin.file.name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<Cow<'a, str>>,
}

impl<'a> LogOrigin<'a> {
    pub fn is_empty(&self) -> bool {
        self.line.is_none() && self.name.is_none()
    }
}

fn normalize_map(destination: &mut Map<String, Value>, map: Map<String, Value>) {
    for (key, value) in map {
        match value {
            Value::Object(map) => {
                let mut normalized = Map::with_capacity(map.len());
                normalize_map(&mut normalized, map);
                insert_in_destination(destination, &key, Value::Object(normalized));
            }
            other => {
                insert_in_destination(destination, &key, other);
            }
        }
    }
}

fn insert_in_destination(destination: &mut Map<String, Value>, key: &str, value: Value) {
    // iterate over nested keys and construct destination map if needed.
    if let Some((root, rest)) = key.split_once('.') {
        insert_in_destination(
            destination
                .entry(root)
                .and_modify(|in_place| {
                    if !in_place.is_object() {
                        *in_place = Value::Object(Map::new());
                    }
                })
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .expect("This must be an object by construction"),
            rest,
            value,
        );
    } else {
        // key is "final" (no dot in it)
        // the caller will insert directly in current map
        destination.insert(key.to_string(), value);
    }
}

impl<'a> From<&Metadata<'a>> for LogOrigin<'a> {
    fn from(meta: &Metadata<'a>) -> Self {
        Self {
            line: meta.line(),
            name: meta.file().map(|f| f.into()),
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::{json, Map, Value};

    fn assert_eq_normalize(to_normalize: Value, expected: Value) {
        let Value::Object(map) = to_normalize else {
            panic!("{to_normalize} is not a map!");
        };
        let mut normalized: Map<String, Value> = Map::with_capacity(map.len());
        super::normalize_map(&mut normalized, map);
        assert_eq!(Value::Object(normalized), expected);
    }

    #[test]
    fn test_normalize() {
        assert_eq_normalize(json!({}), json!({}));

        // no-op if no dot in keys
        assert_eq_normalize(
            json!({
                "foo": "bar",
                "baz": [1,2,3],
                "a bool": true,
                "a map": {
                    "foobar": "barfoo",
                    "a bool again": true,
                }
            }),
            json!({
                "foo": "bar",
                "baz": [1,2,3],
                "a bool": true,
                "a map": {
                    "foobar": "barfoo",
                    "a bool again": true,
                }
            }),
        );

        assert_eq_normalize(
            json!({
                "foo.bar": "baz",
            }),
            json!({
                "foo": {
                    "bar": "baz",
                }
            }),
        );
        assert_eq_normalize(
            json!({
                "host.id": "baz",
                "host.fqdn": "local.example.net"
            }),
            json!({
                "host": {
                    "id": "baz",
                    "fqdn": "local.example.net"
                }
            }),
        );

        assert_eq_normalize(
            json!({
                "foo": "this will be overwritten",
                "foo.bar": "baz",
                "foo": {
                    "another_key": "2 key pairs in foo"
                }
            }),
            json!({
                "foo": {
                    "bar": "baz",
                    "another_key": "2 key pairs in foo"
                }
            }),
        );

        assert_eq_normalize(
            json!({
                "message": "hello world",
                "host.hostname": "abcde-af-123.example.net",
                "http.request.method": "GET",
                "http.response.status_code": 200,
                "http.request.path": "/login",
            }),
            json!({
                "message": "hello world",
                "host": {
                    "hostname": "abcde-af-123.example.net"
                },
                "http": {
                    "request": {
                        "method": "GET",
                        "path": "/login",
                    },
                    "response": {
                        "status_code": 200
                    }
                }
            }),
        );
    }
}
