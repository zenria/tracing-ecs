//! Visitor that records fields values

use std::{borrow::Cow, collections::HashMap, fmt};

use serde_json::Value;
use tracing_core::field::{Field, Visit};

use crate::AttributeMapper;

pub(crate) struct FieldVisitor<'a, 'm> {
    object: &'a mut HashMap<Cow<'static, str>, Value>,
    mapper: &'m dyn AttributeMapper,
    span_name: &'static str,
}

impl<'a, 'm> FieldVisitor<'a, 'm> {
    pub(crate) fn new(
        object: &'a mut HashMap<Cow<'static, str>, Value>,
        span_name: &'static str,
        mapper: &'m dyn AttributeMapper,
    ) -> Self {
        FieldVisitor {
            object,
            span_name,
            mapper,
        }
    }

    fn record_value<Field, V>(&mut self, field: Field, value: V)
    where
        Field: Into<Cow<'static, str>>,
        V: Into<Value>,
    {
        self.object
            .insert(self.mapper.map(self.span_name, field.into()), value.into());
    }
}

impl<'a, 'm> Visit for FieldVisitor<'a, 'm> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let value = format!("{:?}", value);
        let field_name = field.name();
        match field_name {
            _ => self.record_value(field_name, value),
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        let field_name = field.name();
        match field_name {
            _ => self.record_value(field_name, value),
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        let field_name = field.name();
        match field_name {
            _ => self.record_value(field_name, value),
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        let field_name = field.name();
        match field_name {
            _ => self.record_value(field_name, value),
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let field_name = field.name();
        match field_name {
            _ => self.record_value(field_name, value),
        }
    }
}
