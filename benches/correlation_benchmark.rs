use chrono::{DateTime, Utc};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sigma_rust::correlation::*;
use sigma_rust::{event_from_json, rule_from_yaml, Rule};
use std::collections::HashMap;

fn create_test_rule(title: &str) -> Rule {
    let yaml = format!(
        "title: {}\nlogsource:\n  category: test\n  product: test\ndetection:\n  selection:\n    field: value\n  condition: selection",
        title
    );
    rule_from_yaml(&yaml).unwrap()
}
/// Generate test events for benchmarking
fn generate_test_events<'a>(
    count: usize,
    users: &[&str],
    time_spread_minutes: i64,
    rule: &'a Rule,
) -> Vec<TimestampedEvent<'a>> {
    let mut events = Vec::new();
    let base_time = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    for i in 0..count {
        let mut event_data = HashMap::new();
        event_data.insert(
            "EventID".to_string(),
            serde_json::Value::Number(4625.into()),
        );
        event_data.insert(
            "TargetUserName".to_string(),
            serde_json::Value::String(users[i % users.len()].to_string()),
        );
        event_data.insert(
            "SourceIP".to_string(),
            serde_json::Value::String(format!("192.168.1.{}", (i % 254) + 1)),
        );
        event_data.insert(
            "LogonType".to_string(),
            serde_json::Value::Number(((i % 10) + 1).into()),
        );

        let event = event_from_json(&serde_json::to_string(&event_data).unwrap())
            .expect("Failed to create event from JSON");

        // Spread events over time
        let minutes_offset = (i as i64 * time_spread_minutes) / count as i64;
        let timestamp = base_time + chrono::Duration::minutes(minutes_offset);
        events.push(TimestampedEvent {
            event,
            timestamp,
            rule,
        });
    }
    events
}

/// Create a test correlation engine with various rule types
fn create_test_engine() -> CorrelationEngine {
    let mut engine = CorrelationEngine::new();

    // Add base rule
    let base_rule_yaml = r#"
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
"#;

    if let Ok((_, base_rules)) = parse_rules_from_yaml(base_rule_yaml) {
        for (name, rule) in base_rules {
            engine.add_base_rule(name, rule);
        }
    }

    // Event counts correlation rule
    let event_count_rule = SigmaCorrelationRule {
        title: "Multiple Failed Logons - Event Count".to_string(),
        id: Some("ec-001".to_string()),
        correlation: CorrelationSection {
            correlation_type: CorrelationType::EventCount,
            rules: vec!["failed_logon".to_string()],
            group_by: Some(vec!["TargetUserName".to_string()]),
            timespan: "5m".to_string(),
            condition: CorrelationCondition {
                gte: Some(5),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    // Value count correlation rule
    let value_count_rule = SigmaCorrelationRule {
        title: "Multiple Source IPs - Value Count".to_string(),
        id: Some("vc-001".to_string()),
        correlation: CorrelationSection {
            correlation_type: CorrelationType::ValueCount,
            rules: vec!["failed_logon".to_string()],
            group_by: Some(vec!["TargetUserName".to_string()]),
            timespan: "10m".to_string(),
            condition: CorrelationCondition {
                gte: Some(3),
                field: Some("SourceIP".to_string()),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    // Temporal correlation rule
    let temporal_rule = SigmaCorrelationRule {
        title: "Temporal Pattern".to_string(),
        id: Some("temp-001".to_string()),
        correlation: CorrelationSection {
            correlation_type: CorrelationType::Temporal,
            rules: vec!["failed_logon".to_string()],
            group_by: Some(vec!["TargetUserName".to_string()]),
            timespan: "15m".to_string(),
            condition: CorrelationCondition {
                gte: Some(1),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    engine.add_correlation_rule(event_count_rule);
    engine.add_correlation_rule(value_count_rule);
    engine.add_correlation_rule(temporal_rule);

    engine
}

fn bench_process_events_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("process_events_scale");

    let users = vec!["admin", "user1", "user2", "user3", "user4", "guest"];
    let engine = create_test_engine();
    let rule: Rule = create_test_rule("failed_logon");
    // Test with different event counts
    for size in [100, 500, 1000, 2000, 5000].iter() {
        let events = generate_test_events(*size, &users, 60, &rule); // 1 hour

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::new("events", size), &events, |b, events| {
            b.iter(|| {
                let results = engine.process_events(black_box(events)).unwrap();
                black_box(results);
            });
        });
    }

    group.finish();
}

fn bench_process_events_time_windows(c: &mut Criterion) {
    let mut group = c.benchmark_group("process_events_time_windows");

    let users = vec!["admin", "user1", "user2"];
    let engine = create_test_engine();
    let event_count = 1000;

    // Test with different time spreads (affects bucketing)
    let time_spreads = vec![
        ("1min", 1),
        ("5min", 5),
        ("30min", 30),
        ("2hours", 120),
        ("1day", 1440),
    ];
    let rule: Rule = create_test_rule("failed_logon");
    for (name, minutes) in time_spreads {
        let events = generate_test_events(event_count, &users, minutes, &rule);

        group.bench_with_input(BenchmarkId::new("timespan", name), &events, |b, events| {
            b.iter(|| {
                let results = engine.process_events(black_box(events)).unwrap();
                black_box(results);
            });
        });
    }

    group.finish();
}

fn bench_process_events_user_groups(c: &mut Criterion) {
    let mut group = c.benchmark_group("process_events_user_groups");

    let engine = create_test_engine();
    let event_count = 1000;

    // Test with different numbers of unique users (affects grouping)
    let user_counts = vec![1, 5, 10, 50, 100];

    for user_count in user_counts {
        let users: Vec<String> = (0..user_count).map(|i| format!("user{}", i)).collect();
        let user_refs: Vec<&str> = users.iter().map(|s| s.as_str()).collect();
        let rule: Rule = create_test_rule("failed_logon");
        let events = generate_test_events(event_count, &user_refs, 30, &rule);

        group.bench_with_input(
            BenchmarkId::new("users", user_count),
            &events,
            |b, events| {
                b.iter(|| {
                    let results = engine.process_events(black_box(events)).unwrap();
                    black_box(results);
                });
            },
        );
    }

    group.finish();
}

fn bench_correlation_types(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_types");

    let users = vec!["admin", "user1", "user2", "user3"];
    let rule: Rule = create_test_rule("failed_logon");
    let events = generate_test_events(1000, &users, 30, &rule);

    // Test individual correlation types
    let correlation_types = vec![
        ("event_count", CorrelationType::EventCount),
        ("value_count", CorrelationType::ValueCount),
        ("temporal", CorrelationType::Temporal),
        ("temporal_ordered", CorrelationType::TemporalOrdered),
    ];

    for (name, corr_type) in correlation_types {
        let mut engine = CorrelationEngine::new();

        // Add base rule
        if let Ok((_, base_rules)) = parse_rules_from_yaml(
            r#"
title: Windows Failed Logon Event
name: failed_logon
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
"#,
        ) {
            for (rule_name, rule) in base_rules {
                engine.add_base_rule(rule_name, rule);
            }
        }

        // Create rule for a specific correlation type
        let rule = SigmaCorrelationRule {
            title: format!("Test Rule - {}", name),
            id: Some(format!("test-{}", name)),
            correlation: CorrelationSection {
                correlation_type: corr_type.clone(),
                rules: vec!["failed_logon".to_string()],
                group_by: Some(vec!["TargetUserName".to_string()]),
                timespan: "5m".to_string(),
                condition: CorrelationCondition {
                    gte: Some(2),
                    field: if matches!(corr_type, CorrelationType::ValueCount) {
                        Some("SourceIP".to_string())
                    } else {
                        None
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };

        engine.add_correlation_rule(rule);

        group.bench_with_input(BenchmarkId::new("type", name), &events, |b, events| {
            b.iter(|| {
                let results = engine.process_events(black_box(events)).unwrap();
                black_box(results);
            });
        });
    }

    group.finish();
}

fn bench_multiple_rules(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiple_rules");

    let users = vec!["admin", "user1", "user2"];
    let rule: Rule = create_test_rule("failed_logon");
    let events = generate_test_events(1000, &users, 30, &rule);

    // Test with different numbers of correlation rules
    for rule_count in [1, 3, 5, 10, 20].iter() {
        let mut engine = CorrelationEngine::new();

        // Add base rule
        if let Ok((_, base_rules)) = parse_rules_from_yaml(
            r#"
title: Windows Failed Logon Event
name: failed_logon
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
"#,
        ) {
            for (rule_name, rule) in base_rules {
                engine.add_base_rule(rule_name, rule);
            }
        }

        // Add multiple correlation rules
        for i in 0..*rule_count {
            let rule = SigmaCorrelationRule {
                title: format!("Test Rule {}", i),
                id: Some(format!("test-{}", i)),
                correlation: CorrelationSection {
                    correlation_type: CorrelationType::EventCount,
                    rules: vec!["failed_logon".to_string()],
                    group_by: Some(vec!["TargetUserName".to_string()]),
                    timespan: format!("{}m", (i % 10) + 1),
                    condition: CorrelationCondition {
                        gte: Some((i % 5) + 1),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            };
            engine.add_correlation_rule(rule);
        }

        group.bench_with_input(
            BenchmarkId::new("rules", rule_count),
            &events,
            |b, events| {
                b.iter(|| {
                    let results = engine.process_events(black_box(events)).unwrap();
                    black_box(results);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_process_events_scale,
    bench_process_events_time_windows,
    bench_process_events_user_groups,
    bench_correlation_types,
    bench_multiple_rules
);
criterion_main!(benches);
