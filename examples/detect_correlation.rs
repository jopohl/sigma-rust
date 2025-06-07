use chrono::{DateTime, Utc};
use sigma_rust::{
    events_from_json, parse_rules_from_yaml, CorrelationEngine, Event, TimestampedEvent,
};
use std::error::Error;

/// # Correlation Detection Example
///
/// This example demonstrates how to:
/// 1. Configure a correlation engine with Sigma rules
/// 2. Process events against these rules
/// 3. Detect patterns across multiple events
#[cfg(feature = "serde_json")]
fn main() -> Result<(), Box<dyn Error>> {
    // Set up the correlation engine with rules
    let engine = setup_engine()?;

    // Load sample events
    let events = load_events()?;

    // Process events and detect matches
    let matched_events = find_matching_events(&events, &engine);

    // Run correlation analysis on the matched events
    analyze_correlations(&engine, &matched_events)?;

    Ok(())
}

/// Sets up the correlation engine with base and correlation rules
fn setup_engine() -> Result<CorrelationEngine, Box<dyn Error>> {
    let mut engine = CorrelationEngine::new();

    // Define rules in YAML format
    let correlation_rule_yaml = r#"
title: Windows Failed Logon Event
name: failed_logon
description: Detects failed logon events on Windows systems.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Multiple failed logons for a single user
status: test
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
  timespan: 1m
  condition:
    gte: 3
tags:
  - brute_force
"#;

    // Parse and register rules with the engine
    let (correlation_rules, base_rules) = parse_rules_from_yaml(correlation_rule_yaml)?;

    for (name, rule) in base_rules {
        engine.add_base_rule(name, rule);
    }

    for rule in correlation_rules {
        engine.add_correlation_rule(rule);
    }

    Ok(engine)
}

/// Loads sample events for demonstration
fn load_events() -> Result<Vec<Event>, Box<dyn Error>> {
    // Sample events with failed login attempts for the same user
    let events_str = r#"
[
    {
        "EventID": 4625,
        "Timestamp": "2025-01-01T00:00:00Z",
        "TargetUserName": "admin"
    },
    {
        "EventID": 4625,
        "Timestamp": "2025-01-01T00:00:30Z",
        "TargetUserName": "admin"
    },
    {
        "EventID": 4625,
        "Timestamp": "2025-01-01T00:00:59Z",
        "TargetUserName": "admin"
    }
]"#;

    Ok(events_from_json(events_str)?)
}

/// Identifies events matching any of the base rules using functional style
fn find_matching_events(events: &[Event], engine: &CorrelationEngine) -> Vec<TimestampedEvent> {
    events
        .iter()
        .flat_map(|event| {
            engine
                .base_rules
                .values()
                .filter(|rule| rule.is_match(event))
                .filter_map(|rule| {
                    // Extract timestamp from event
                    let timestamp = event.get("Timestamp").and_then(|ts| {
                        let ts_str = ts.value_to_string();
                        DateTime::parse_from_rfc3339(&ts_str)
                            .ok()
                            .map(|dt| dt.with_timezone(&Utc))
                    })?;

                    // Create timestamped event with rule context
                    Some(TimestampedEvent {
                        event: event.clone(),
                        timestamp,
                        rule_name: rule.name.clone()?,
                    })
                })
        })
        .collect()
}

/// Processes matched events through the correlation engine and displays results
fn analyze_correlations(
    engine: &CorrelationEngine,
    events: &[TimestampedEvent],
) -> Result<(), Box<dyn Error>> {
    // Run correlation detection on matched events
    let results = engine.process_events(events)?;
    for result in &results {
        println!(
            "Rule: {}\nMatched Events: {}\nCorrelation Detected: {}",
            result.rule.title,
            result.count,
            if result.matched { "YES" } else { "NO" }
        );
    }

    Ok(())
}
