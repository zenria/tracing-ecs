# tracing-ecs [![crates.io](https://img.shields.io/crates/v/tracing-ecs.svg)](https://crates.io/crates/tracing-ecs) [![docs.rs](https://docs.rs/tracing-ecs/badge.svg)](https://docs.rs/tracing-ecs/)

Tracing subscriber that outputs json log lines in the ECS ([Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/ecs-reference.html)) log format.

## Usage

```rust
use tracing_ecs::ECSLayerBuilder;
ECSLayerBuilder::default()
    .stdout()
    .install()
    .unwrap()
```

## License

* Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license
   ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
