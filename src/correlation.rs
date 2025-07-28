use crate::{rule_from_yaml, Event, Rule};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Sigma Correlation Rule types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationType {
    #[default]
    EventCount,
    ValueCount,
    Temporal,
    TemporalOrdered,
}

/// Condition for correlation matching
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CorrelationCondition {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gte: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lte: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gt: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lt: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>, // Used for value_count type
}

impl CorrelationCondition {
    pub fn matches(&self, value: u64) -> bool {
        self.gte.map_or(true, |gte| value >= gte)
            && self.lte.map_or(true, |lte| value <= lte)
            && self.eq.map_or(true, |eq| value == eq)
            && self.gt.map_or(true, |gt| value > gt)
            && self.lt.map_or(true, |lt| value < lt)
    }
}

/// Field aliases for mapping different field names across log sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldAliases {
    pub aliases: HashMap<String, HashMap<String, String>>,
}

/// Correlation section of a Sigma rule
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CorrelationSection {
    #[serde(rename = "type")]
    pub correlation_type: CorrelationType,
    pub rules: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_by: Option<Vec<String>>,
    pub timespan: String,
    pub condition: CorrelationCondition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generate: Option<bool>, // Whether to retain base rule in output
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<FieldAliases>,
}

/// A complete Sigma Correlation Rule
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SigmaCorrelationRule {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub falsepositives: Option<Vec<String>>,
    pub correlation: CorrelationSection,
}

/// Event with timestamp for correlation processing
#[derive(Debug, Clone)]
pub struct TimestampedEvent<'a> {
    pub event: Event,
    pub timestamp: DateTime<Utc>,
    pub rule: &'a Rule,
}

/// Aggregation bucket for grouping events
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AggregationKey {
    pub time_bucket: DateTime<Utc>,
    pub group_values: Vec<String>,
}

/// Result of correlation processing
pub struct CorrelationResult<'a> {
    pub rule: &'a SigmaCorrelationRule,
    pub matched: bool,
    pub events: Vec<&'a TimestampedEvent<'a>>,
    pub aggregation_key: AggregationKey,
    pub count: u64,
}

/// Correlation Engine for processing Sigma correlation rules
pub struct CorrelationEngine {
    rules: Vec<SigmaCorrelationRule>,
    pub base_rules: HashMap<String, Rule>,
}

/// Result type for parsing rules from YAML
pub type ParseRulesResult = Result<(Vec<SigmaCorrelationRule>, Vec<(String, Rule)>)>;

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            base_rules: HashMap::new(),
        }
    }
    /// Add a correlation rule to the engine
    pub fn add_correlation_rule(&mut self, rule: SigmaCorrelationRule) {
        self.rules.push(rule);
    }

    /// Add a base Sigma rule that can be referenced by correlation rules
    pub fn add_base_rule(&mut self, name: String, rule: Rule) {
        self.base_rules.insert(name, rule);
    }

    /// Parse timespan string to Duration
    pub fn parse_timespan(timespan: &str) -> Result<Duration> {
        let timespan = timespan.trim();
        if timespan.is_empty() {
            return Err(anyhow!("Empty timespan"));
        }

        let (value_str, unit) = if let Some(pos) = timespan.find(|c: char| c.is_alphabetic()) {
            (&timespan[..pos], &timespan[pos..])
        } else {
            return Err(anyhow!("Invalid timespan format: {}", timespan));
        };

        let value: u64 = value_str
            .parse()
            .map_err(|_| anyhow!("Invalid timespan value: {}", value_str))?;

        let duration = match unit {
            "s" => Duration::from_secs(value),
            "m" => Duration::from_secs(value * 60),
            "h" => Duration::from_secs(value * 3600),
            "d" => Duration::from_secs(value * 86400),
            _ => return Err(anyhow!("Unknown timespan unit: {}", unit)),
        };

        Ok(duration)
    }

    /// Create time buckets based on timespan
    #[inline]
    fn create_time_bucket(timestamp: DateTime<Utc>, timespan: Duration) -> DateTime<Utc> {
        let bucket_size_secs = timespan.as_secs() as i64;
        let timestamp_secs = timestamp.timestamp();
        let bucket_timestamp = (timestamp_secs / bucket_size_secs) * bucket_size_secs;
        DateTime::from_timestamp(bucket_timestamp, 0).unwrap_or(timestamp)
    }

    /// Resolve field aliases for a given field in the context of a rule
    fn resolve_field_alias(field: &str, aliases: Option<&FieldAliases>, rule_name: &str) -> String {
        if let Some(aliases) = aliases {
            if let Some(rule_aliases) = aliases.aliases.get(field) {
                let f = field.to_string();
                return rule_aliases.get(rule_name).unwrap_or(&f).to_string();
            }
        }
        field.to_string()
    }

    /// Extract group-by values from an event
    fn extract_group_values(
        event: &Event,
        group_by: &[String],
        aliases: Option<&FieldAliases>,
        rule_name: &str,
    ) -> Result<Vec<String>> {
        group_by
            .iter()
            .map(|field| {
                let actual_field = Self::resolve_field_alias(field, aliases, rule_name);
                event
                    .get(actual_field.as_str())
                    .ok_or_else(|| anyhow!("Field '{}' not found in event", actual_field))
                    .map(|v| v.value_to_string())
            })
            .collect()
    }

    /// Extract distinct values for value_count correlation
    fn extract_field_values(
        events: &[&TimestampedEvent],
        field: &str,
        aliases: Option<&FieldAliases>,
    ) -> std::collections::HashSet<String> {
        let mut values = std::collections::HashSet::new();
        for event in events {
            let rule_name = &event.rule.title;
            let actual_field = Self::resolve_field_alias(field, aliases, rule_name);
            if let Some(value) = event.event.get(&actual_field) {
                values.insert(value.value_to_string());
            };
        }

        values
    }

    /// Helper method to group events into buckets based on timespan and grouping fields
    fn group_events_into_buckets<'a>(
        &self,
        rule: &SigmaCorrelationRule,
        events: &[&'a TimestampedEvent],
    ) -> Result<HashMap<AggregationKey, Vec<&'a TimestampedEvent<'a>>>> {
        let timespan = Self::parse_timespan(&rule.correlation.timespan)?;
        let mut buckets: HashMap<AggregationKey, Vec<&TimestampedEvent>> = HashMap::new();

        // Group events into time buckets
        for event in events {
            let time_bucket = Self::create_time_bucket(event.timestamp, timespan);
            let group_values = if let Some(group_by) = &rule.correlation.group_by {
                Self::extract_group_values(
                    &event.event,
                    group_by,
                    rule.correlation.aliases.as_ref(),
                    &event.rule.title,
                )
            } else {
                Ok(vec![])
            };

            let key = AggregationKey {
                time_bucket,
                group_values: group_values?,
            };

            buckets.entry(key).or_default().push(*event);
        }

        Ok(buckets)
    }

    /// Process event_count correlation
    fn process_event_count<'a>(
        &'a self,
        rule: &'a SigmaCorrelationRule,
        events: &[&'a TimestampedEvent],
    ) -> Result<Vec<CorrelationResult<'a>>> {
        let buckets = self.group_events_into_buckets(rule, events)?;
        // Check conditions for each bucket
        let mut results = Vec::new();
        for (key, bucket_events) in buckets {
            let count = bucket_events.len() as u64;
            let matched = rule.correlation.condition.matches(count);

            results.push(CorrelationResult {
                rule,
                matched,
                events: bucket_events,
                aggregation_key: key,
                count,
            });
        }

        Ok(results)
    }

    /// Process value_count correlation
    fn process_value_count<'a>(
        &'a self,
        rule: &'a SigmaCorrelationRule,
        events: &Vec<&'a TimestampedEvent>,
    ) -> Result<Vec<CorrelationResult<'a>>> {
        let field = rule
            .correlation
            .condition
            .field
            .as_ref()
            .ok_or_else(|| anyhow!("value_count correlation requires 'field' parameter"))?;
        let buckets = self.group_events_into_buckets(rule, events)?;

        // Check conditions for each bucket
        let mut results = Vec::new();
        for (key, bucket_events) in buckets {
            let distinct_values = Self::extract_field_values(
                &bucket_events,
                field,
                rule.correlation.aliases.as_ref(),
            );

            let count = distinct_values.len() as u64;
            let matched = rule.correlation.condition.matches(count);

            results.push(CorrelationResult {
                rule,
                matched,
                events: bucket_events,
                aggregation_key: key,
                count,
            });
        }

        Ok(results)
    }

    /// Process temporal correlation
    fn process_temporal<'a>(
        &'a self,
        rule: &'a SigmaCorrelationRule,
        events: &Vec<&'a TimestampedEvent>,
    ) -> Result<Vec<CorrelationResult<'a>>> {
        let buckets = self.group_events_into_buckets(rule, events)?;

        // Check conditions for each bucket
        let mut results = Vec::new();
        for (key, bucket_events) in buckets {
            // Count distinct rule types in the bucket
            let mut rule_types = std::collections::HashSet::new();
            for event in &bucket_events {
                rule_types.insert(&event.rule.title);
            }

            let distinct_rule_count = rule_types.len() as u64;
            let expected_rule_count = rule.correlation.rules.len() as u64;

            // For temporal correlation, we need at least as many distinct rules as specified
            let matched = distinct_rule_count >= expected_rule_count
                && rule.correlation.condition.matches(distinct_rule_count);

            results.push(CorrelationResult {
                rule,
                matched,
                events: bucket_events,
                aggregation_key: key,
                count: distinct_rule_count,
            });
        }

        Ok(results)
    }

    /// Process ordered temporal correlation
    fn process_ordered_temporal<'a>(
        &self,
        rule: &'a SigmaCorrelationRule,
        events: &Vec<&'a TimestampedEvent>,
    ) -> Result<Vec<CorrelationResult<'a>>> {
        let buckets = self.group_events_into_buckets(rule, events)?;

        // Check conditions for each bucket
        let mut results = Vec::new();
        for (key, mut bucket_events) in buckets {
            // Sort events by timestamp
            bucket_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

            // Check if events appear in the specified order
            let mut rule_order_matched = true;
            let mut last_rule_index = 0;

            for event in &bucket_events {
                if let Some(rule_index) = rule
                    .correlation
                    .rules
                    .iter()
                    .position(|r| r == &event.rule.title)
                {
                    if rule_index < last_rule_index {
                        rule_order_matched = false;
                        break;
                    }
                    last_rule_index = rule_index;
                }
            }

            // Count distinct rule types
            let mut rule_types = std::collections::HashSet::new();
            for event in &bucket_events {
                rule_types.insert(&event.rule.title);
            }

            let distinct_rule_count = rule_types.len() as u64;
            let expected_rule_count = rule.correlation.rules.len() as u64;

            let matched = rule_order_matched
                && distinct_rule_count >= expected_rule_count
                && rule.correlation.condition.matches(distinct_rule_count);

            results.push(CorrelationResult {
                rule,
                matched,
                events: bucket_events,
                aggregation_key: key,
                count: distinct_rule_count,
            });
        }

        Ok(results)
    }

    /// Process events against correlation rules
    pub fn process_events<'a>(
        &'a self,
        events: &'a [TimestampedEvent],
    ) -> Result<Vec<CorrelationResult<'a>>> {
        // Parallelize the processing of each rule
        let all_results: Result<Vec<Vec<CorrelationResult<'a>>>> = self
            .rules
            .par_iter()
            .map(|rule| {
                // Filter events that match the referenced rules
                let matching_events: Vec<&TimestampedEvent> = events
                    .iter()
                    .filter(|event| rule.correlation.rules.contains(&event.rule.title))
                    .collect();

                if matching_events.is_empty() {
                    return Ok(Vec::new());
                }

                let results = match rule.correlation.correlation_type {
                    CorrelationType::EventCount => {
                        self.process_event_count(rule, &matching_events)?
                    }
                    CorrelationType::ValueCount => {
                        self.process_value_count(rule, &matching_events)?
                    }
                    CorrelationType::Temporal => self.process_temporal(rule, &matching_events)?,
                    CorrelationType::TemporalOrdered => {
                        self.process_ordered_temporal(rule, &matching_events)?
                    }
                };

                Ok(results)
            })
            .collect();

        // Flatten the results
        let flattened_results: Vec<CorrelationResult<'a>> =
            all_results?.into_iter().flatten().collect();

        Ok(flattened_results)
    }
}

/// Parse a correlation rule from YAML
pub fn parse_correlation_rule_from_yaml(yaml: &str) -> Result<SigmaCorrelationRule> {
    serde_yml::from_str(yaml).map_err(|e| anyhow!("Failed to parse correlation rule: {}", e))
}

/// Parse multiple rules from YAML (separated by ---)
pub fn parse_rules_from_yaml(yaml: &str) -> ParseRulesResult {
    let documents: Vec<&str> = yaml.split("---").collect();
    let mut correlation_rules = Vec::new();
    let mut base_rules = Vec::new();

    for doc in documents {
        let doc = doc.trim();
        if doc.is_empty() {
            continue;
        }
        // Try to parse as correlation rule first
        if let Ok(correlation_rule) = parse_correlation_rule_from_yaml(doc) {
            correlation_rules.push(correlation_rule);
        } else {
            // Try to parse as regular Sigma rule
            if let Ok(rule) = rule_from_yaml(doc) {
                // Extract rule name from YAML metadata
                if let Ok(yaml_value) = serde_yml::from_str::<serde_yml::Value>(doc) {
                    let rule_name = yaml_value
                        .get("name")
                        .or_else(|| yaml_value.get("id"))
                        .or_else(|| yaml_value.get("title"))
                        .and_then(|v| v.as_str());
                    if let Some(name) = rule_name {
                        base_rules.push((name.to_string(), rule));
                    }
                }
            }
        }
    }

    Ok((correlation_rules, base_rules))
}
