use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::json;
use sigma_rust::{check_rule, Event, Rule};

fn criterion_benchmark(c: &mut Criterion) {
    let rule_yaml = r#"
title: Rule for benchmarking
logsource:
detection:
    selection_filename_suffix:
        TargetFilename: ':\temp\'
        TargetFilename|endswith: .exe
    selection_image_suffix:
        Image: ':\temp\'
    condition: all of them
        "#;

    let rule: Rule = serde_yml::from_str(rule_yaml).unwrap();

    let event: Event = json!( {
        "EventID": 4624,
        "LogName": "Security",
        "TimeCreated": "2023-10-01T12:34:56.789Z",
        "EventRecordID": 123456,
        "Channel": "Security",
        "Computer": "DESKTOP-1234ABCD",
        "UserData": {
            "SubjectUserName": "johndoe",
            "SubjectDomainName": "WORKGROUP",
            "SubjectLogonId": "0x123456",
            "TargetUserName": "johndoe",
            "TargetDomainName": "WORKGROUP",
            "TargetLogonId": "0x654321",
            "LogonType": 2,
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
            "WorkstationName": "DESKTOP-1234ABCD",
            "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
            "TransmittedServices": "-",
            "LmPackageName": "-",
            "KeyLength": 0,
            "ProcessId": 1234,
            "ProcessName": "C:\\Windows\\System32\\winlogon.exe",
            "IpAddress": "192.168.1.100",
            "IpPort": "12345"
        },
        "SomeKey": {
            "SomeValue": "yes"
        },
        "TargetFilename": "C:\\temp\\autoit3.exe",
        "Image": "C:\\temp\\hello.au3"
    })
    .try_into()
    .unwrap();

    c.bench_function("rule_match", |b| {
        b.iter(|| check_rule(black_box(&rule), black_box(&event)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
