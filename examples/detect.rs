use sigma_rust::{Event, Rule};

fn main() {
    let rule_yaml = r#"
title: DarkGate - Drop DarkGate Loader In C:\Temp Directory
id: df49c691-8026-48dd-94d3-4ba6a79102a8
status: experimental
description: Detects attackers attempting to save, decrypt and execute the DarkGate Loader in C:\temp folder.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-exploit-windows-smartscreen-flaw-to-drop-darkgate-malware/
    - https://www.trendmicro.com/en_us/research/24/c/cve-2024-21412--darkgate-operators-exploit-microsoft-windows-sma.html
author: Tomasz Dyduch, Josh Nickels
date: 2024-05-31
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: file_event
    product: windows
detection:
    selection_filename_suffix:
        TargetFilename|contains: ':\temp\'
        TargetFilename|endswith:
            - '.au3'
            - '\autoit3.exe'
    selection_image_suffix:
        Image|contains: ':\temp\'
        Image|endswith:
            - '.au3'
            - '\autoit3.exe'
    condition: 1 of selection_*
falsepositives:
    - Unlikely legitimate usage of AutoIT in temp folders.
level: medium
        "#;

    let rule: Rule = serde_norway::from_str(rule_yaml).unwrap();
    let event_1 = Event::from([
        ("TargetFilename", "C:\\temp\\file.au3"),
        ("Image", "C:\\temp\\autoit4.exe"),
    ]);

    let non_hitting_event = Event::from([
        ("TargetFilename", "C:\\temp\\file.txt"),
        ("Image", "C:\\temp\\calc.exe"),
    ]);

    if rule.is_match(&event_1) {
        println!("Rule matched event_1 as expected");
    }

    if !rule.is_match(&non_hitting_event) {
        println!("Rule did not match event_2 as expected");
    }

    #[cfg(feature = "serde_json")]
    {
        use sigma_rust::events_from_json;
        let event_json = r#"
        [
            {
                "TargetFilename": "C:\\temp\\autoit3.exe",
                "Image": "C:\\temp\\hello.au3"
            },
            {
                "TargetFilename": "C:\\temp\\file.au3",
                "Image": "C:\\temp\\autoit3.exe"
            },
            {
                "TargetFilename": "C:\\temp\\file.txt",
                "Image": "C:\\temp\\calc.exe"
            },
            {
                "Unrelated": "C:\\temp\\file.txt",
                "Fields": "C:\\temp\\calc.exe"
            }
        ]"#;
        let events = events_from_json(event_json).unwrap();

        for (i, event) in events.iter().enumerate() {
            println!(
                "JSON event #{} matches the rule '{}': {}",
                i + 1,
                rule.title,
                rule.is_match(event)
            );
        }
    }
}
