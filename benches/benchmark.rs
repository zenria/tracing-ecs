use criterion::{criterion_group, criterion_main, Criterion};
use tracing_ecs::ECSLayerBuilder;

use std::{io::sink, sync::Once};

use serde_json::json;
use tracing_log::LogTracer;
use tracing_subscriber::{fmt::SubscriberBuilder, Layer};

static START: Once = Once::new();

fn run_with_builder<T>(builder: ECSLayerBuilder, test: T)
where
    T: FnOnce() -> (),
{
    START.call_once(|| LogTracer::init().unwrap());

    let noout = SubscriberBuilder::default().with_writer(|| sink()).finish();
    let subscriber = builder.build_with_writer(|| sink()).with_subscriber(noout);
    tracing_core::dispatcher::with_default(
        &tracing_core::dispatcher::Dispatch::new(subscriber),
        test,
    );
}

fn generate_logs() {
    tracing::info!("hello world");
    tracing::info!(
        transaction.id = "abcd-211a-a",
        http.request.method = "GET",
        "This event has attributes"
    );
    let span = tracing::info_span!("myspan", arg1 = "abcdef", arg2 = "ghijk", event.id = 951);
    let _enter = span.enter();
    tracing::info!("My message is in a span!!");
    tracing::info!("My second message is in a span!!")
}

fn builder() -> ECSLayerBuilder {
    ECSLayerBuilder::default()
        .with_extra_fields(json!({
            "labels": {
                "env": "prod",
                "service": "benches",
            },
            "host.hostname": "my-benches.localhost",
        }))
        .unwrap()
}

pub fn with_normalization(c: &mut Criterion) {
    c.bench_function("with_normalization", |b| {
        b.iter(|| {
            run_with_builder(builder(), generate_logs);
        })
    });
}

pub fn without_normalization(c: &mut Criterion) {
    c.bench_function("without_normalization", |b| {
        b.iter(|| {
            run_with_builder(builder().normalize_json(false), generate_logs);
        })
    });
}

criterion_group!(benches, with_normalization, without_normalization);
criterion_main!(benches);
