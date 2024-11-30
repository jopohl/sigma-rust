use sigma_rust::{rule_from_yaml, Event, Rule};

#[test]
fn test_match_rule_with_keywords() {
    let yaml = r#"title: A rule with keywords
logsource:
    service: test
detection:
    keywords:
        - 'hello world'
        - 'arch linux'
    condition: keywords
"#;
    let rule: Rule = serde_yml::from_str(yaml).unwrap();
    let event_1 = Event::from([("a", "this is hello world "), ("os", "is windows")]);
    let event_2 = Event::from([("b", "this is arch linux "), ("more", "something")]);
    let event_3 = Event::from([("c", "no keyword "), ("d", "no match")]);

    assert!(rule.is_match(&event_1));
    assert!(rule.is_match(&event_2));
    assert!(!rule.is_match(&event_3));
}

#[test]
fn test_match_rule_with_keywords_and_fields() {
    let yaml = r#"title: A rule with keywords
logsource:
    service: test
detection:
    keywords:
        - 'hello world'
        - 'arch linux'
    selection:
        a: test
        b: chuck
    condition: keywords and selection
"#;
    let rule: Rule = serde_yml::from_str(yaml).unwrap();
    let event_1 = Event::from([("a", "this is hello world "), ("os", "is windows")]);
    let event_2 = Event::from([("a", "test"), ("b", "chuck"), ("c", "hello world")]);
    let event_3 = Event::from([("a", "test"), ("b", "chuck")]);

    assert!(!rule.is_match(&event_1));
    assert!(rule.is_match(&event_2));
    assert!(!rule.is_match(&event_3));
}

#[test]
fn test_match_field_list() {
    let yaml = r#"
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
            condition: selection and 1 of filter_*
    "#;

    let rule: Rule = serde_yml::from_str(yaml).unwrap();

    let event_1 = Event::from([
        ("Image", "C:\\rundll32.exe"),
        ("OriginalFileName", "RUNDLL32.EXE"),
        ("CommandLine", "hello test"),
        ("SomeValue", "yes"),
    ]);
    let event_2 = Event::from([
        ("Image", "C:\\rundll32.exe"),
        ("OriginalFileName", "RUNDLL32.EXE"),
        ("CommandLine", "a.dll"),
    ]);
    let event_3 = Event::from([
        ("Image", "C:\\rundll32.exe"),
        ("OriginalFileName", "nomatch.EXE"),
        ("CommandLine", "a.dll"),
    ]);
    let event_4 = Event::from([
        ("Image", "C:\\rundll32.exe"),
        ("OriginalFileName", "RUNDLL32.EXE"),
        ("CommandLine", "hello test"),
    ]);

    assert!(rule.is_match(&event_1));
    assert!(rule.is_match(&event_2));
    assert!(!rule.is_match(&event_3));
    assert!(!rule.is_match(&event_4));
}

#[test]
fn test_match_null_fields() {
    let yaml = r#"
    title: Rule with null field
    logsource:
    detection:
        selection:
            - Image|endswith: '\rundll32.exe'
            - OriginalFileName: 'RUNDLL32.EXE'
        filter_main_null:
            CommandLine: null
        condition: selection and not 1 of filter_main_*
    "#;

    let rule = rule_from_yaml(yaml).unwrap();
    let event_1 = Event::from([("OriginalFileName", "RUNDLL32.EXE")]);
    let mut event_2 = Event::new();
    event_2.insert("Image", "c:\\rundll32.exe");
    event_2.insert("CommandLine", None);

    assert!(rule.is_match(&event_1));
    assert!(!rule.is_match(&event_2));
}
