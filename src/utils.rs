//! Utility types & structs

use std::{borrow::Cow, collections::HashMap};

pub type Tags = Vec<Cow<'static, str>>;

pub type Labels = HashMap<Cow<'static, str>, Cow<'static, str>>;
