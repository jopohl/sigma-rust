use chrono::{DateTime, Utc};
use sigma_rust::{events_from_json, parse_rules_from_yaml, CorrelationEngine, TimestampedEvent};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("Step 1: Setting up correlation engine...");
    let mut engine = CorrelationEngine::new();

    println!("Step 2: Parsing and registering rules...");
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
    let (correlation_rules, base_rules) = parse_rules_from_yaml(correlation_rule_yaml)?;
    for (name, rule) in base_rules {
        engine.add_base_rule(name, rule);
    }

    for rule in correlation_rules {
        engine.add_correlation_rule(rule);
    }

    println!("Step 3: Loading sample events...");
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
    let events = events_from_json(events_str)?;

    println!("Step 4: Finding events that match base rules...");
    let mut matched_events = Vec::new();
    for event in &events {
        for rule in engine.base_rules.values() {
            if rule.is_match(event) {
                if let Some(timestamp_field) = event.get("Timestamp") {
                    let timestamp_str = timestamp_field.value_to_string();
                    if let Ok(parsed_time) = DateTime::parse_from_rfc3339(&timestamp_str) {
                        let utc_time = parsed_time.with_timezone(&Utc);
                        let timestamped_event = TimestampedEvent {
                            event: event.clone(),
                            timestamp: utc_time,
                            rule_name: rule.name.clone().unwrap_or("unnamed".to_string()),
                        };
                        matched_events.push(timestamped_event);
                    }
                }
            }
        }
    }

    println!("Step 5: Running correlation analysis...");
    let results = engine.process_events(&matched_events)?;
    println!("================================");
    for result in results.iter() {
        println!("Title: {}", result.rule_title);
        println!("Event Count: {} events", result.count);
        println!(
            "Correlation Detected: {}",
            if result.matched { "YES" } else { "NO" }
        );
    }
    Ok(())
}
