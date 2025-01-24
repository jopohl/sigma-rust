#![forbid(unsafe_code)]
//! `sigma-rust` is a library for parsing and checking Sigma rules against log events.

mod basevalue;
mod detection;
mod error;
mod event;
mod field;
mod rule;
mod selection;
mod wildcard;

pub use event::Event;
pub use rule::Rule;

/// Parse a rule from a YAML string
pub fn rule_from_yaml(yaml: &str) -> Result<Rule, serde_yml::Error> {
    serde_yml::from_str(yaml)
}

/// Parse an event from a JSON string
#[cfg(feature = "serde_json")]
pub fn event_from_json(json: &str) -> Result<Event, serde_json::Error> {
    serde_json::from_str(json)
}

/// Parse a list of events from a JSON string
#[cfg(feature = "serde_json")]
pub fn events_from_json(json: &str) -> Result<Vec<Event>, serde_json::Error> {
    serde_json::from_str(json)
}

/// Check if a rule matches an event
pub fn check_rule(rule: &Rule, event: &Event) -> bool {
    rule.is_match(event)
}
