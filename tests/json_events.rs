#[cfg(feature = "serde_json")]
use serde_json::json;
#[cfg(feature = "serde_json")]
use sigma_rust::{check_rule, event_from_json, events_from_json, rule_from_yaml, Event};

#[cfg(feature = "serde_json")]
#[test]
fn test_match_event_from_json() {
    let json = r#"
        {
            "Image": "C:\\rundll32.exe",
            "OriginalFileName": "RUNDLL32.EXE",
            "CommandLine": "hello test",
            "SomeValue": "yes"
        }"#;

    let rule = r#"
        title: Field list test
        logsource:
        detection:
            selection:
                Image|endswith: '\rundll32.exe'
                OriginalFileName: 'RUNDLL32.EXE'
            filter_main_known_extension:
                - CommandLine|contains:
                      # Note: This aims to cover: single and double quotes in addition to spaces and comma "," usage.
                      - 'test'
                      - 'something'
                  SomeValue: yes
                - CommandLine|endswith:
                      # Note: This aims to cover: single and double quotes in addition to spaces and comma "," usage.
                      - '.cpl'
                      - '.dll'
                      - '.inf'
            condition: selection and 1 of filter_*"#;

    let rule = rule_from_yaml(rule).unwrap();
    let event = event_from_json(json).unwrap();

    assert!(check_rule(&rule, &event));
}

#[cfg(feature = "serde_json")]
#[test]
fn test_match_multiple_events_from_json() {
    let events_json = r#"
        [
            {
                "Image": "C:\\rundll32.exe",
                "OriginalFileName": "RUNDLL32.EXE",
                "CommandLine": "hello test",
                "SomeValue": "yes"
            },
            {
                "Image": "C:\\rundll32.exe",
                "OriginalFileName": "RUNDLL32.EXE",
                "CommandLine": "a.dll",
                "SomeValue": "yes"
            }
        ]"#;

    let rule = r#"
        title: Multi event test
        logsource:
        detection:
            selection:
                Image|endswith: '\rundll32.exe'
                OriginalFileName: 'RUNDLL32.EXE'
            filter_main_known_extension:
                - CommandLine|contains:
                      - 'test'
                      - 'something'
                  SomeValue: yes
                - CommandLine|endswith:
                      - '.cpl'
                      - '.dll'
                      - '.inf'
            condition: selection and 1 of filter_*"#;

    let rule = rule_from_yaml(rule).unwrap();
    let events = events_from_json(events_json).unwrap();

    for event in events {
        assert!(check_rule(&rule, &event));
    }
}

#[cfg(feature = "serde_json")]
#[test]
fn test_match_nested_event() {
    let event: Event = json!({
        "Image": "test",
        "Image.source": "somewhere",
        "User": {
            "Name": {
                "First": "Chuck",
                "Last": "Norris",
            },
            "Mobile.phone": "1",
            "Age": 42,
        },
    })
    .try_into()
    .unwrap();

    let matching_rule = r#"
        title: Nested test
        logsource:
        detection:
            selection:
                Image|endswith: 'st'
                Image.source|startswith: 'some'
                User.Name.First: 'Chuck'
                User.Mobile.phone: '1'
            condition: selection"#;

    let not_matching_rule = r#"
        title: Nested test
        logsource:
        detection:
            selection:
                Image|endswith: 'st'
                User.Name.First: 'Son'
                User.Name.Last: 'Goku'
            condition: selection"#;

    let rule = rule_from_yaml(matching_rule).unwrap();
    assert!(check_rule(&rule, &event));

    let rule = rule_from_yaml(not_matching_rule).unwrap();
    assert!(!check_rule(&rule, &event));
}

#[cfg(feature = "serde_json")]
#[test]
fn test_match_fieldref() {
    let event: Event = json!({
        "Image": "testing",
        "User": {
            "Name": {
                "First": "Chuck",
                "Last": "Norris",
            },
            "Mobile.phone": "1",
            "Age": 42,
            "SomeName": "Chuck",
        },
        "reference": "test",
    })
    .try_into()
    .unwrap();

    let matching_rule = r#"
        title: Fieldref test
        logsource:
        detection:
            selection:
                Image|fieldref|startswith: reference
                User.Name.First|fieldref:
                    - User.SomeName
                    - reference
            condition: selection"#;

    let rule = rule_from_yaml(matching_rule).unwrap();
    assert!(check_rule(&rule, &event));
}
