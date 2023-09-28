///! Types used in json serialization
use serde::Serialize;
use serde_json::Value;
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

    #[serde(rename = "log.origin", skip_serializing_if = "LogOrigin::is_empty")]
    pub(crate) log_origin: LogOrigin<'a>,

    #[serde(flatten)]
    pub(crate) dynamic_fields: serde_json::Map<String, Value>,
}

#[derive(Serialize)]
pub(crate) struct LogOrigin<'a> {
    pub(crate) file: LogFile<'a>,
}

impl<'a> LogOrigin<'a> {
    pub fn is_empty(&self) -> bool {
        self.file.line.is_none() && self.file.name.is_none()
    }
}

#[derive(Serialize)]
pub(crate) struct LogFile<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<&'a str>,
}

impl<'a> From<&Metadata<'a>> for LogOrigin<'a> {
    fn from(meta: &Metadata<'a>) -> Self {
        Self {
            file: LogFile {
                line: meta.line(),
                name: meta.file(),
            },
        }
    }
}
