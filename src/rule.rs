use crate::detection::Detection;
use crate::event::Event;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Declares the status of the rule
#[derive(Serialize, Deserialize, PartialEq, Copy, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// the rule is considered as stable and may be used in production systems or dashboards.
    Stable,
    /// a mostly stable rule that could require some slight adjustments depending on the environment.
    Test,
    /// an experimental rule that could lead to false positives results or be noisy, but could also identify interesting events.
    Experimental,
    /// the rule is replaced or covered by another one. The link is established by the related field.
    Deprecated,
    /// the rule cannot be used in its current state (old correlation format, custom fields)
    Unsupported,
}

/// To be able to keep track of the relationships between detections, Sigma rules may also contain references to related rule identifiers in the related attribute.
/// This allows to define common relationships between detections as follows:
/// ```yaml
/// related:
///   - id: 08fbc97d-0a2f-491c-ae21-8ffcfd3174e9
///     type: derived
///   - id: 929a690e-bef0-4204-a928-ef5e620d6fcc
///     type: obsolete
/// ```
#[derive(Deserialize, Debug)]
pub struct Related {
    pub id: String,
    #[serde(rename = "type")]
    pub related_type: RelatedType,
}

/// The related type describes the relationship between the rule and the referred rule.
#[derive(Deserialize, PartialEq, Copy, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RelatedType {
    /// The rule was derived from the referred rule or rules, which may remain active.
    Derived,
    /// The rule obsoletes the referred rule or rules, which aren't used anymore.
    Obsolete,
    /// The rule was merged from the referred rules. The rules may still exist and are in use.
    Merged,
    /// The rule had previously the referred identifier or identifiers but was renamed for whatever reason, e.g. from a private naming scheme to UUIDs, to resolve collisions etc. It's not expected that a rule with this id exists anymore.
    Renamed,
    /// Use to relate similar rules to each other (e.g. same detection content applied to different log sources, rule that is a modified version of another rule with a different level)
    Similar,
}

/// The logsource describes the log data on which the detection is meant to be applied to.
/// It describes the log source, the platform, the application and the type that is required in the detection.
#[derive(Deserialize, Debug)]
pub struct Logsource {
    /// The category value is used to select all log files written of a logical group.
    /// This may cover one or more sources of information depending on the system.
    /// e.g. "antivirus" for the scan result, "webserver" for the web access logs.
    pub category: Option<String>,
    /// The product value is used to select all log outputs of a certain product.
    /// It can be as generic as an operating system or the name of a particular software package.
    /// e.g. "windows" will include "Security", "System", "Application" and the other like "AppLocker" and "Windows Defender"...
    pub product: Option<String>,
    /// The service value is used to select a more specific subset of logs.
    /// e.g. "sshd" on Linux or the "Security" Eventlog on Windows systems.
    pub service: Option<String>,
    /// The definition can be used to describe the log source, including some information on the log verbosity level or configurations that have to be applied.
    pub definition: Option<String>,
}

/// The level describes the criticality of a triggered rule.
/// While low and medium level events have an informative character,
/// events with high and critical level should lead to immediate reviews by security analysts.
#[derive(Serialize, Deserialize, PartialEq, Copy, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Rule is intended for enrichment of events, e.g. by tagging them. No case or alerting should be triggered by such rules because it is expected that a huge amount of events will match these rules.
    Informational,
    /// Notable event but rarely an incident. Low rated events can be relevant in high numbers or combination with others. Immediate reaction shouldn't be necessary, but a regular review is recommended.
    Low,
    /// Relevant event that should be reviewed manually on a more frequent basis.
    Medium,
    /// Relevant event that should trigger an internal alert and requires a prompt review.
    High,
    /// Highly relevant event that indicates an incident. Critical events should be reviewed immediately. It is used only for cases in which probability borders certainty.
    Critical,
}

/// The `Rule` struct implements the Sigma rule specification 2.0.0 released 08.08.2024.
///
/// The full specification can be found at:
/// <https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md>
#[derive(Deserialize, Debug)]
pub struct Rule {
    /// A brief title for the rule that should contain what the rule is supposed to detect (max. 256 characters)
    pub title: String,
    /// Sigma rules should be identified by a globally unique identifier in the id attribute.
    /// For this purpose randomly generated UUIDs (version 4) is used.
    pub id: Option<String>,
    /// name is a unique human-readable name that can be used instead of the id as a reference in correlation rules.
    /// The goal is to improve the readability of correlation rules.
    pub name: Option<String>,
    /// To be able to keep track of the relationships between detections, Sigma rules may also contain references to related rule identifiers in the related attribute.
    pub related: Option<Vec<Related>>,
    pub taxonomy: Option<String>,
    pub status: Option<Status>,
    /// A short and accurate description of the rule and the malicious or suspicious activity that can be detected (max. 65,535 characters)
    pub description: Option<String>,
    /// License of the rule according to <https://spdx.dev/learn/handling-license-info/> format.
    pub license: Option<String>,
    /// Creator of the rule. (can be a name, nickname, twitter handle...etc)
    /// If there is more than one, they are separated by a comma.
    pub author: Option<String>,
    /// References to the sources that the rule was derived from.
    /// These could be blog articles, technical papers, presentations or even tweets.
    pub references: Option<Vec<String>>,
    /// Creation date of the rule.
    /// Use the ISO 8601 date with separator format : YYYY-MM-DD
    pub date: Option<String>,
    /// Last modification date of the rule.
    /// Use the ISO 8601 date with separator format : YYYY-MM-DD
    pub modified: Option<String>,
    /// This section describes the log data on which the detection is meant to be applied to.
    /// It describes the log source, the platform, the application and the type that is required in the detection.
    pub logsource: Logsource,
    /// A set of search-identifiers that represent properties of searches on log data.
    pub detection: Detection,
    /// A list of log fields that could be interesting for further analysis of the event
    /// and should be displayed to the analyst.
    pub fields: Option<Vec<String>>,
    /// A list of known false positives that may occur.
    pub falsepositives: Option<Vec<String>>,
    /// The level field contains one of five string values.
    /// It describes the criticality of a triggered rule.
    /// While low and medium level events have an informative character,
    /// events with high and critical level should lead to immediate reviews by security analysts.
    pub level: Option<Level>,
    ///  Tags should generally follow this syntax:
    /// * Character set: lower-case letters, numerals, underscores and hyphens
    /// * no spaces
    /// * Tags are namespaced, the dot is used as separator. e.g. attack.t1234 refers to technique 1234 in the namespace attack; Namespaces may also be nested
    /// * Keep tags short, e.g. numeric identifiers instead of long sentences
    pub tags: Option<Vec<String>>,
    /// Capture any additional fields
    #[serde(flatten)]
    pub custom_fields: HashMap<String, serde_yml::Value>,
}

impl Rule {
    /// Check if the event matches the rule
    ///
    /// # Example
    /// ```rust
    /// use sigma_rust::{rule_from_yaml, Event, Rule};
    /// let rule_yaml = r#"
    /// title: Some test title
    /// logsource:
    ///     category: test
    /// detection:
    ///     selection_1:
    ///         field_name|contains:
    ///             - this
    ///             - that
    ///     selection_2:
    ///         null_field: null
    ///     condition: all of selection_*
    /// "#;
    /// let rule = rule_from_yaml(rule_yaml).unwrap();
    /// let mut event = Event::from([("field_name", "this")]);
    /// event.insert("null_field", None);
    /// assert!(rule.is_match(&event));
    /// ```
    pub fn is_match(&self, event: &Event) -> bool {
        self.detection.evaluate(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::selection::Selection;
    use crate::wildcard::WildcardToken;

    #[test]
    fn test_load_from_yaml() {
        let rule_yaml = r#"
        title: Some test title
        id: fb97a1c5-9e86-4e15-9fd9-7d82a05a384e
        name: a unique name
        related:
            - id: ab97a1c5-9e86-4e15-9fd9-7d82a05a384e
              type: derived
            - id: bb97a1c5-9e86-4e15-9fd9-7d82a05a384e
              type: obsolete
        status: stable
        license: MIT
        author: Chuck Norris
        date: 2020-12-30
        logsource:
            category: process_creation
            product: windows
        level: medium
        detection:
          selection:
            field_name:
              - this # or
              - that
          condition: selection
        custom_field: some value
        another_custom_field:
            nested: nested_value
        "#;
        let rule: Rule = serde_yml::from_str(rule_yaml).unwrap();
        assert_eq!(rule.title, "Some test title");
        assert_eq!(
            rule.id,
            Some("fb97a1c5-9e86-4e15-9fd9-7d82a05a384e".to_string())
        );
        assert_eq!(rule.name, Some("a unique name".to_string()));
        let related = rule.related.as_ref().unwrap();
        assert_eq!(related.len(), 2);
        assert_eq!(related[0].id, "ab97a1c5-9e86-4e15-9fd9-7d82a05a384e");
        assert_eq!(related[0].related_type, RelatedType::Derived);
        assert_eq!(related[1].id, "bb97a1c5-9e86-4e15-9fd9-7d82a05a384e");
        assert_eq!(related[1].related_type, RelatedType::Obsolete);
        assert!(rule.taxonomy.is_none());
        assert_eq!(rule.status, Some(Status::Stable));
        assert!(rule.description.is_none());
        assert_eq!(rule.license, Some("MIT".to_string()));
        assert_eq!(rule.author, Some("Chuck Norris".to_string()));
        assert!(rule.references.is_none());
        assert_eq!(rule.date, Some("2020-12-30".to_string()));
        assert!(rule.modified.is_none());
        assert_eq!(
            rule.logsource.category.as_ref().unwrap(),
            "process_creation"
        );
        assert_eq!(rule.logsource.product.as_ref().unwrap(), "windows");
        assert!(rule.logsource.service.is_none());
        assert!(rule.logsource.definition.is_none());
        assert!(rule.fields.is_none());
        assert!(rule.falsepositives.is_none());
        assert_eq!(rule.level.as_ref().unwrap(), &Level::Medium);
        assert!(rule.tags.is_none());
        assert_eq!(rule.detection.get_selections().len(), 1);
        match rule.detection.get_selections().get("selection").unwrap() {
            Selection::Keyword(_) => panic!("Wrong selection type"),
            Selection::Field(field_groups) => {
                assert_eq!(field_groups.len(), 1);
                let fields = &field_groups[0].fields;
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].name, "field_name");
                assert_eq!(fields[0].values.len(), 2);

                assert!(
                    matches!(&fields[0].values[0], FieldValue::WildcardPattern(pattern) if pattern.len() == 1 && matches!(&pattern[0], WildcardToken::Pattern(p) if p == &"this".chars().collect::<Vec<char>>()))
                );

                assert!(
                    matches!(&fields[0].values[1], FieldValue::WildcardPattern(pattern) if pattern.len() == 1 && matches!(&pattern[0], WildcardToken::Pattern(p) if p == &"that".chars().collect::<Vec<char>>()))
                );
            }
        }

        assert_eq!(rule.detection.get_condition(), "selection".to_string());
        assert_eq!(rule.custom_fields["custom_field"], "some value");
        assert_eq!(
            rule.custom_fields["another_custom_field"]["nested"],
            "nested_value"
        );

        let event = Event::from([("field_name", "this")]);
        assert!(rule.is_match(&event));
    }
}
