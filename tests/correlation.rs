use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sigma_rust::correlation::*;
use sigma_rust::{event_from_json, rule_from_yaml, Rule};

fn create_test_rule(title: &str) -> Rule {
    let yaml = format!(
        "title: {}\nlogsource:\n  category: test\n  product: test\ndetection:\n  selection:\n    field: value\n  condition: selection",
        title
    );
    rule_from_yaml(&yaml).unwrap()
}
#[test]
fn test_parse_timespan() {
    assert_eq!(
        CorrelationEngine::parse_timespan("30s").unwrap(),
        std::time::Duration::from_secs(30)
    );
    assert_eq!(
        CorrelationEngine::parse_timespan("5m").unwrap(),
        std::time::Duration::from_secs(300)
    );
    assert_eq!(
        CorrelationEngine::parse_timespan("1h").unwrap(),
        std::time::Duration::from_secs(3600)
    );
    assert_eq!(
        CorrelationEngine::parse_timespan("2d").unwrap(),
        std::time::Duration::from_secs(172800)
    );

    // Test invalid formats
    assert!(CorrelationEngine::parse_timespan("").is_err());
    assert!(CorrelationEngine::parse_timespan("5x").is_err());
    assert!(CorrelationEngine::parse_timespan("abc").is_err());
    assert!(CorrelationEngine::parse_timespan("5").is_err());
}

#[test]
fn test_correlation_condition_comprehensive() {
    // Test gte condition
    let condition = CorrelationCondition {
        gte: Some(10),
        ..Default::default()
    };
    assert!(condition.matches(10));
    assert!(condition.matches(15));
    assert!(!condition.matches(5));

    // Test lte condition
    let condition = CorrelationCondition {
        lte: Some(20),
        ..Default::default()
    };
    assert!(condition.matches(20));
    assert!(condition.matches(15));
    assert!(!condition.matches(25));

    // Test eq condition
    let condition = CorrelationCondition {
        eq: Some(10),
        ..Default::default()
    };
    assert!(condition.matches(10));
    assert!(!condition.matches(15));
    assert!(!condition.matches(5));

    // Test gt condition
    let condition = CorrelationCondition {
        gt: Some(5),
        ..Default::default()
    };
    assert!(condition.matches(10));
    assert!(!condition.matches(5));
    assert!(!condition.matches(3));

    // Test lt condition
    let condition = CorrelationCondition {
        lt: Some(10),
        ..Default::default()
    };
    assert!(condition.matches(5));
    assert!(!condition.matches(10));
    assert!(!condition.matches(15));

    // Test combined conditions
    let condition = CorrelationCondition {
        gte: Some(5),
        lte: Some(20),
        ..Default::default()
    };
    assert!(condition.matches(10));
    assert!(condition.matches(5));
    assert!(condition.matches(20));
    assert!(!condition.matches(3));
    assert!(!condition.matches(25));
}

#[test]
fn test_parse_correlation_rule() {
    let yaml = r#"
title: Multiple failed logons for a single user
status: test
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
    - TargetDomainName
  timespan: 5m
  condition:
    gte: 10
tags:
  - brute_force
  - attack.t1110
"#;

    let rule = parse_correlation_rule_from_yaml(yaml).unwrap();
    assert_eq!(rule.title, "Multiple failed logons for a single user");
    assert_eq!(
        rule.correlation.correlation_type,
        CorrelationType::EventCount
    );
    assert_eq!(rule.correlation.rules, vec!["failed_logon"]);
    assert_eq!(rule.correlation.timespan, "5m");
    assert_eq!(rule.correlation.condition.gte, Some(10));
}

#[test]
fn test_parse_value_count_correlation_rule() {
    let yaml = r#"
title: Enumeration of multiple high-privilege groups
status: stable
correlation:
  type: value_count
  rules:
    - privileged_group_enumeration
  group-by:
    - SubjectUserName
  timespan: 15m
  condition:
    gte: 4
    field: TargetUserName
level: high
"#;

    let rule = parse_correlation_rule_from_yaml(yaml).unwrap();
    assert_eq!(
        rule.correlation.correlation_type,
        CorrelationType::ValueCount
    );
    assert_eq!(
        rule.correlation.condition.field,
        Some("TargetUserName".to_string())
    );
    assert_eq!(rule.correlation.condition.gte, Some(4));
}

#[test]
fn test_parse_temporal_correlation_rule() {
    let yaml = r#"
title: CVE-2023-22518 Exploit Chain
description: Access to endpoint vulnerable to CVE-2023-22518 with suspicious process creation
status: experimental
correlation:
  type: temporal
  rules:
    - a902d249-9b9c-4dc4-8fd0-fbe528ef965c
    - 1ddaa9a4-eb0b-4398-a9fe-7b018f9e23db
  timespan: 10s
  condition:
    gte: 2
level: high
"#;

    let rule = parse_correlation_rule_from_yaml(yaml).unwrap();
    assert_eq!(rule.correlation.correlation_type, CorrelationType::Temporal);
    assert_eq!(rule.correlation.rules.len(), 2);
    assert_eq!(rule.correlation.timespan, "10s");
}

#[test]
fn parse_correlation_and_base_rules() {
    let yaml = r#"
title: Correlation Rule
correlation:
  type: temporal
  rules:
    - rule1
    - rule2
  timespan: 15m
  condition:
    eq: 2
---
name: rule1
title: Base Rule 1
logsource:
    category: test
    product: windows
detection:
  selection:
    field1: value1
  condition: selection
---
name: rule2
title: Base Rule 2
logsource:
    category: test
    product: windows
detection:
  selection:
    field2: value2
  condition: selection
"#;

    let (correlation_rules, base_rules) = parse_rules_from_yaml(yaml).unwrap();

    assert_eq!(correlation_rules.len(), 1);
    assert_eq!(base_rules.len(), 2);

    assert_eq!(correlation_rules[0].title, "Correlation Rule");

    assert_eq!(base_rules[0].0, "rule1");
    assert_eq!(base_rules[1].0, "rule2");
}

#[test]
fn test_event_count_correlation() {
    let mut engine = CorrelationEngine::new();

    let rule = SigmaCorrelationRule {
        title: "Test Rule".to_string(),
        correlation: CorrelationSection {
            correlation_type: CorrelationType::EventCount,
            rules: vec!["test_rule".to_string()],
            group_by: Some(vec!["user".to_string()]),
            timespan: "5m".to_string(),
            condition: CorrelationCondition {
                gte: Some(3),
                ..Default::default()
            },
            generate: None,
            aliases: None,
        },
        ..Default::default()
    };

    engine.add_correlation_rule(rule);

    let base_time = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let rule: Rule = create_test_rule("test_rule");
    let events = vec![
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(30),
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(60),
            rule: &rule,
        },
    ];

    let results = engine.process_events(&events).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].matched);
    assert_eq!(results[0].count, 3);
}

#[test]
fn test_event_count_correlation_multiple_groups() {
    let mut engine = CorrelationEngine::new();

    let rule = SigmaCorrelationRule {
        title: "Test Rule".to_string(),
        correlation: CorrelationSection {
            correlation_type: CorrelationType::EventCount,
            rules: vec!["test_rule".to_string()],
            group_by: Some(vec!["user".to_string()]),
            timespan: "5m".to_string(),
            condition: CorrelationCondition {
                gte: Some(2),
                ..Default::default()
            },
            generate: None,
            aliases: None,
        },
        ..Default::default()
    };

    engine.add_correlation_rule(rule);

    let base_time = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let rule: Rule = create_test_rule("test_rule");
    let events = vec![
        // Alice events (should match)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(30),
            rule: &rule,
        },
        // Bob events (should match)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(60),
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(90),
            rule: &rule,
        },
        // Charlie events (should not match - only 1 event)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "charlie"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(120),
            rule: &rule,
        },
    ];

    let results = engine.process_events(&events).unwrap();
    assert_eq!(results.len(), 3); // One result per group

    let matched_results: Vec<_> = results.iter().filter(|r| r.matched).collect();
    assert_eq!(matched_results.len(), 2); // Alice and Bob should match

    for result in matched_results {
        assert_eq!(result.count, 2);
    }
}

#[test]
fn test_event_count_time_window() {
    let mut engine = CorrelationEngine::new();

    let rule = SigmaCorrelationRule {
        title: "Test Rule".to_string(),
        correlation: CorrelationSection {
            correlation_type: CorrelationType::EventCount,
            rules: vec!["test_rule".to_string()],
            group_by: Some(vec!["user".to_string()]),
            timespan: "5m".to_string(),
            condition: CorrelationCondition {
                gte: Some(3),
                lte: None,
                eq: None,
                gt: None,
                lt: None,
                field: None,
            },
            generate: None,
            aliases: None,
        },
        ..Default::default()
    };

    engine.add_correlation_rule(rule);
    let rule: Rule = create_test_rule("test_rule");
    let base_time = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let events = vec![
        // Events within 5 minutes - should be grouped together
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(2),
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(4),
            rule: &rule,
        },
        // Event outside 5-minutes window - should be in different bucket
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(10),
            rule: &rule,
        },
    ];

    let results = engine.process_events(&events).unwrap();
    assert_eq!(results.len(), 2); // Two time buckets

    let matched_results: Vec<_> = results.iter().filter(|r| r.matched).collect();
    assert_eq!(matched_results.len(), 1); // Only the first bucket should match (3 events)
    assert_eq!(matched_results[0].count, 3);
}

#[test]
fn test_value_count_correlation() {
    let mut engine = CorrelationEngine::new();

    let rule = SigmaCorrelationRule {
        title: "Test Value Count Rule".to_string(),
        correlation: CorrelationSection {
            correlation_type: CorrelationType::ValueCount,
            rules: vec!["test_rule".to_string()],
            group_by: Some(vec!["user".to_string()]),
            timespan: "15m".to_string(),
            condition: CorrelationCondition {
                gte: Some(3),
                lte: None,
                eq: None,
                gt: None,
                lt: None,
                field: Some("target".to_string()),
            },
            generate: None,
            aliases: None,
        },
        ..Default::default()
    };

    engine.add_correlation_rule(rule);

    let base_time = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let rule: Rule = create_test_rule("test_rule");
    let events = vec![
        // Alice targeting different systems
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice", "target": "system1"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice", "target": "system2"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(5),
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice", "target": "system3"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(10),
            rule: &rule,
        },
        // Bob targeting only two systems
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob", "target": "system1"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob", "target": "system2"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(5),
            rule: &rule,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob", "target": "system2"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(10),
            rule: &rule,
        },
    ];

    let results = engine.process_events(&events).unwrap();
    assert_eq!(results.len(), 2); // One result per user

    let matched_results: Vec<_> = results.iter().filter(|r| r.matched).collect();
    assert_eq!(matched_results.len(), 1); // Only Alice should match (3 distinct targets)

    for result in &matched_results {
        if result
            .aggregation_key
            .group_values
            .contains(&"alice".to_string())
        {
            assert_eq!(result.count, 3);
        }
    }

    let unmatched_results: Vec<_> = results.iter().filter(|r| !r.matched).collect();
    for result in &unmatched_results {
        if result
            .aggregation_key
            .group_values
            .contains(&"bob".to_string())
        {
            assert_eq!(result.count, 2); // Bob only has 2 distinct targets
        }
    }
}

#[test]
fn test_temporal_correlation() {
    let mut engine = CorrelationEngine::new();

    let rule = SigmaCorrelationRule {
        title: "Temporal Sequence Test".to_string(),
        correlation: CorrelationSection {
            correlation_type: CorrelationType::Temporal,
            rules: vec!["rule_a".to_string(), "rule_b".to_string()],
            group_by: Some(vec!["user".to_string()]),
            timespan: "1m".to_string(),
            condition: CorrelationCondition {
                gte: Some(2),
                ..Default::default()
            },
            generate: None,
            aliases: None,
        },
        ..Default::default()
    };

    engine.add_correlation_rule(rule);

    let base_time = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let rule_a: Rule = create_test_rule("rule_a");
    let rule_b: Rule = create_test_rule("rule_b");
    let events = vec![
        // Alice's valid sequence (within timespan)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_a,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(30),
            rule: &rule_b,
        },
        // Bob's valid sequence (within timespan)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(5),
            rule: &rule_a,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(45),
            rule: &rule_b,
        },
        // Charlie's incomplete sequence (only rule_a)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "charlie"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_a,
        },
        // Dave's sequence outside of timespan
        TimestampedEvent {
            event: event_from_json(r#"{"user": "dave"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_a,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "dave"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(2),
            rule: &rule_b,
        },
    ];

    let results = engine.process_events(&events).unwrap();

    // Processed events from 5 users
    assert_eq!(results.len(), 5);

    // Only two groups should match (alice, bob)
    let matched_results: Vec<_> = results.iter().filter(|r| r.matched).collect();
    assert_eq!(matched_results.len(), 2);

    // Verify results for alice and bob
    for result in &matched_results {
        // Each match should contain exactly 2 rules
        assert_eq!(result.count, 2);

        // Confirm that the group value is either alice or bob
        let group_value = &result.aggregation_key.group_values[0];
        assert!(group_value == "alice" || group_value == "bob");
    }
}

#[test]
fn test_ordered_temporal_correlation() {
    let mut engine = CorrelationEngine::new();

    let rule = SigmaCorrelationRule {
        title: "Ordered Temporal Sequence Test".to_string(),
        correlation: CorrelationSection {
            correlation_type: CorrelationType::TemporalOrdered,
            rules: vec![
                "rule_a".to_string(),
                "rule_b".to_string(),
                "rule_c".to_string(),
            ],
            group_by: Some(vec!["user".to_string()]),
            timespan: "1m".to_string(),
            condition: CorrelationCondition {
                gte: Some(3),
                ..Default::default()
            },
            generate: None,
            aliases: None,
        },
        ..Default::default()
    };

    engine.add_correlation_rule(rule);

    let base_time = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);

    let rule_a: Rule = create_test_rule("rule_a");
    let rule_b: Rule = create_test_rule("rule_b");
    let rule_c: Rule = create_test_rule("rule_c");

    let events = vec![
        // Alice's valid sequence (correct order within timespan)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_a,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(15),
            rule: &rule_b,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "alice"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(30),
            rule: &rule_c,
        },
        // Bob's invalid sequence (incorrect order - b comes before a)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_b,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(20),
            rule: &rule_a,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "bob"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(40),
            rule: &rule_c,
        },
        // Charlie's incomplete sequence (missing rule_b)
        TimestampedEvent {
            event: event_from_json(r#"{"user": "charlie"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_a,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "charlie"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(30),
            rule: &rule_c,
        },
        // Dave's valid sequence but outside of timespan
        TimestampedEvent {
            event: event_from_json(r#"{"user": "dave"}"#).unwrap(),
            timestamp: base_time,
            rule: &rule_a,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "dave"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::seconds(30),
            rule: &rule_b,
        },
        TimestampedEvent {
            event: event_from_json(r#"{"user": "dave"}"#).unwrap(),
            timestamp: base_time + ChronoDuration::minutes(2),
            rule: &rule_c,
        },
    ];

    let results = engine.process_events(&events).unwrap();

    // Processed events from 5 users
    assert_eq!(results.len(), 5);

    // Only one group should match (alice)
    let matched_results: Vec<_> = results.iter().filter(|r| r.matched).collect();
    assert_eq!(matched_results.len(), 1);

    // Verify results for alice
    for result in &matched_results {
        // Each match should contain exactly 3 rules
        assert_eq!(result.count, 3);

        // Confirm that the group value is alice
        let group_value = &result.aggregation_key.group_values[0];
        assert_eq!(group_value, "alice");
    }
}
