#[cfg(feature = "serde_json")]
#[test]
fn test_match_event_from_json() {
    use sigma_rust::{check_rule, event_from_json, rule_from_yaml};
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
    use sigma_rust::{check_rule, events_from_json, rule_from_yaml};
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
