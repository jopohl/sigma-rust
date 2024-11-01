# sigma-rust

![Build](https://github.com/jopohl/sigma-rust/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/github/jopohl/sigma-rust/graph/badge.svg?token=6SOQK71524)](https://codecov.io/github/jopohl/sigma-rust)
[![Crates.io](https://img.shields.io/crates/v/sigma-rust)](https://crates.io/crates/sigma-rust)
[![Docs.rs](https://docs.rs/sigma-rust/badge.svg)](https://docs.rs/sigma-rust)


A Rust library for parsing and evaluating Sigma rules to create custom detection pipelines.

## Features

- Supports all [sigma modifiers](https://sigmahq.io/docs/basics/modifiers.html) except `expand`
- Supports the whole [Sigma condition](https://sigmahq.io/docs/basics/conditions.html) syntax using Pratt parsing
- Written in 100% safe Rust
- Extensive test suite

## Example

```rust
use sigma_rust::{rule_from_yaml, event_from_json};

fn main() {
    let rule_yaml = r#"
    title: A test rule
    logsource:
        category: test
    detection:
        selection_1:
            TargetFilename|contains: ':\temp\'
            TargetFilename|endswith:
                - '.au3'
                - '\autoit3.exe'
        selection_2:
            Image|contains: ':\temp\'
            Image|endswith:
                - '.au3'
                - '\autoit3.exe'
        condition: 1 of selection_*
    "#;

    let rule = rule_from_yaml(rule_yaml).unwrap();
    let event = event_from_json(
        r#"{"TargetFilename": "C:\\temp\\file.au3", "Image": "C:\\temp\\autoit4.exe"}"#,
    )
        .unwrap();

    assert!(rule.is_match(&event));
}
```

Check out the `examples` folder for more examples.

## Strong type checking

This library performs strong type checking. That is, if you have a rule like

```yaml
selection:
  - myname: 42
```

it would __not__ match the event `{"myname": "42"}`, however, it would match `{"myname": 42}` (note the difference
between string and integer).
If you need to match against several types you can define a rule such as the following.

```yaml
selection_1:
  field: 42
selection_2:
  field: "42"
condition: 1 of them
```


## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
