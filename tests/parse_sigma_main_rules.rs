use sigma_rust::rule_from_yaml;
use std::fs::File;
use std::io::Read;
use std::time::Instant;
use walkdir::WalkDir;

#[test]
fn test_parse_sigma_main_rules() {
    let sigma_dir = "sigma-main-rules";
    let mut num_successful = 0;
    let mut num_failed = 0;
    let mut total = 0;
    let mut errors = vec![];

    let start = Instant::now();
    for entry in WalkDir::new(sigma_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.path().extension().and_then(|s| s.to_str()) == Some("yml") {
            total += 1;
            let mut file = File::open(entry.path()).expect("Unable to open file");
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .expect("Unable to read file");

            let rule = rule_from_yaml(&contents);
            match rule {
                Ok(_) => {
                    num_successful += 1;
                }
                Err(err) => {
                    num_failed += 1;
                    errors.push(format!(
                        "Failed to parse YAML file {:?}: {:?}",
                        entry.path(),
                        err
                    ));
                }
            };
        }
    }
    let duration = start.elapsed();
    println!("-----------------------------------------------");
    println!("Parsing {} rules took {:?}", total, duration);

    println!("Successfully parsed {} rules", num_successful);
    println!("{} rules failed with errors", num_failed);
    for (i, error) in errors.iter().enumerate() {
        println!("{:02}: {}", i + 1, error);
    }

    assert!(num_successful > 0);
    assert_eq!(num_failed, 0);
}
