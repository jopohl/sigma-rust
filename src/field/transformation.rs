use crate::event::EventValue;
use crate::field::Utf16Modifier;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use std::collections::HashMap;

pub fn encode_base64(input: &str, utf16modifier: &Option<Utf16Modifier>) -> String {
    let mut encoded = match utf16modifier {
        Some(Utf16Modifier::Utf16le | Utf16Modifier::Wide) => STANDARD_NO_PAD.encode(
            input
                .encode_utf16()
                .flat_map(|x| x.to_le_bytes())
                .collect::<Vec<u8>>(),
        ),
        Some(Utf16Modifier::Utf16be) => STANDARD_NO_PAD.encode(
            input
                .encode_utf16()
                .flat_map(|x| x.to_be_bytes())
                .collect::<Vec<u8>>(),
        ),
        Some(Utf16Modifier::Utf16) => {
            let mut bytes = vec![0xFF, 0xFE];
            bytes.extend(input.encode_utf16().flat_map(|x| x.to_le_bytes()));
            STANDARD_NO_PAD.encode(bytes)
        }
        None => STANDARD_NO_PAD.encode(input),
    };
    if encoded.len() % 4 == 2 || encoded.len() % 4 == 3 {
        encoded.pop();
        encoded
    } else {
        encoded
    }
}

pub fn encode_base64_offset(input: &str, utf16modifier: &Option<Utf16Modifier>) -> Vec<String> {
    let mut encoded = vec![];

    let char_width = match utf16modifier {
        Some(_) => 2,
        None => 1,
    };

    let output_0 = encode_base64(input, utf16modifier);
    if !output_0.is_empty() {
        encoded.push(output_0);
    }

    let mut input_str_1 = input.to_string();
    for _ in 0..char_width {
        input_str_1.insert(0, '\0');
    }
    let mut output_1 = encode_base64(input_str_1.as_str(), utf16modifier);
    if output_1.len() > char_width * (1 + char_width) {
        // Remove first characters
        output_1.drain(0..char_width * (1 + char_width));
        encoded.push(output_1)
    }

    let mut input_str_2 = input.to_string();
    for _ in 0..2 * char_width {
        input_str_2.insert(0, '\0');
    }
    let mut output_2 = encode_base64(input_str_2.as_str(), utf16modifier);
    if output_2.len() > 2 * (char_width * (1 + char_width)) - 1 {
        // Remove first characters
        output_2.drain(0..2 * (char_width * (1 + char_width)) - 1);
        encoded.push(output_2)
    }

    encoded
}

pub fn windash_variations(input: &str) -> Vec<String> {
    let windash_chars = ["-", "/", "–", "—", "―"];

    let mut result = vec![input.to_string()];
    let mut replacements: HashMap<String, bool> = HashMap::new();
    for flag in input.split(" ") {
        match windash_chars
            .iter()
            .find(|x| flag.starts_with(&x.to_string()))
        {
            Some(_) => replacements.insert(flag.to_string(), true),
            None => continue,
        };
    }

    let original_str = input.to_string();
    for (flag, _) in replacements.iter() {
        for windash in windash_chars.iter() {
            if flag.starts_with(&windash.to_string()) {
                continue;
            }
            let mut new = flag.clone();
            new.replace_range(0..1, windash);
            result.push(original_str.replace(flag, new.as_str()))
        }
    }

    result
}

pub fn length(value: &EventValue) -> i64 {
    match value {
        EventValue::Sequence(seq) => seq.len() as i64,
        EventValue::Map(map) => map.len() as i64,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cidr::IpCidr;
    use std::net::IpAddr;

    #[test]
    fn test_base64_encoding() {
        assert_eq!(encode_base64("/bin/bash", &None), "L2Jpbi9iYXNo");
        assert_eq!(encode_base64("/bin/sh", &None), "L2Jpbi9za");
        assert_eq!(encode_base64("/bin/zsh", &None), "L2Jpbi96c2");
        assert_eq!(encode_base64("", &None), "");
    }

    #[test]
    fn test_base64_encoding_utf16_le() {
        assert_eq!(
            encode_base64("ping", &Some(Utf16Modifier::Utf16le)),
            "cABpAG4AZw"
        );
        assert_eq!(encode_base64("", &Some(Utf16Modifier::Utf16le)), "");
    }

    #[test]
    fn test_base64_encoding_utf16_be() {
        assert_eq!(
            encode_base64("ping", &Some(Utf16Modifier::Utf16be)),
            "AHAAaQBuAG"
        );
        assert_eq!(
            encode_base64("hello world", &Some(Utf16Modifier::Utf16be)),
            "AGgAZQBsAGwAbwAgAHcAbwByAGwAZ"
        );
        assert_eq!(encode_base64("", &Some(Utf16Modifier::Utf16be)), "");
    }

    #[test]
    fn test_base64_sub_modifiers_docs_example() {
        // https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#encoding
        // utf16le: Transforms value to UTF16-LE encoding, e.g. cmd > 63 00 6d 00 64 00
        assert_eq!(
            encode_base64("cmd", &Some(Utf16Modifier::Utf16le)),
            "YwBtAGQA"
        );

        // utf16be: Transforms value to UTF16-BE encoding, e.g. cmd > 00 63 00 6d 00 64
        assert_eq!(
            encode_base64("cmd", &Some(Utf16Modifier::Utf16be)),
            "AGMAbQBk"
        );

        // utf16: Prepends a byte order mark and encodes UTF16, e.g. cmd > FF FE 63 00 6d 00 64 00
        assert_eq!(
            encode_base64("cmd", &Some(Utf16Modifier::Utf16)),
            "//5jAG0AZA"
        );

        // wide: an alias for the utf16le modifier.
        assert_eq!(encode_base64("cmd", &Some(Utf16Modifier::Wide)), "YwBtAGQA");
    }

    #[test]
    fn test_base64_offset_bash() {
        let encoded = encode_base64_offset("/bin/bash", &None);
        let expected = ["L2Jpbi9iYXNo", "9iaW4vYmFza", "vYmluL2Jhc2"];
        assert_eq!(encoded.len(), 3);

        for (i, t) in encoded.iter().enumerate() {
            assert_eq!(expected[i], t, "{}", i);
        }
    }

    #[test]
    fn test_base64_offset_sh() {
        let encoded = encode_base64_offset("/bin/sh", &None);
        let expected = ["L2Jpbi9za", "9iaW4vc2", "vYmluL3No"];
        assert_eq!(encoded.len(), 3);

        for (i, t) in encoded.iter().enumerate() {
            assert_eq!(expected[i], t, "{}", i);
        }
    }

    #[test]
    fn test_base64_offset_zsh() {
        let encoded = encode_base64_offset("/bin/zsh", &None);
        let expected = ["L2Jpbi96c2", "9iaW4venNo", "vYmluL3pza"];
        assert_eq!(encoded.len(), 3);

        for (i, t) in encoded.iter().enumerate() {
            assert_eq!(expected[i], t, "{}", i);
        }
    }

    #[test]
    fn test_base64_offset_1() {
        let encoded = encode_base64_offset("1", &None);
        let expected = ["M", "x"];
        assert_eq!(encoded.len(), 2);

        for (i, t) in encoded.iter().enumerate() {
            assert_eq!(expected[i], t, "{}", i);
        }
    }

    #[test]
    fn test_base64_offset_utf16le() {
        let encoded = encode_base64_offset("::FromBase64String", &Some(Utf16Modifier::Utf16le));
        let expected = [
            "OgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcA",
            "oAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnA",
            "6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZw",
        ];
        assert_eq!(encoded.len(), 3);

        for (i, t) in encoded.iter().enumerate() {
            assert_eq!(expected[i], t, "{}", i);
        }
    }

    #[test]
    fn test_base64_offset_utf16le_preference() {
        // values taken from
        // https://github.com/SigmaHQ/sigma/blob/598d29f811c1859ba18e05b8c419cc94410c9a55/rules/windows/process_creation/proc_creation_win_powershell_base64_mppreference.yml
        let encoded = encode_base64_offset("Add-MpPreference ", &Some(Utf16Modifier::Utf16le));
        let expected = [
            "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA",
            "EAZABkAC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA",
            "BAGQAZAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA",
        ];
        assert_eq!(encoded.len(), 3);

        for (i, t) in encoded.iter().enumerate() {
            assert_eq!(expected[i], t, "{}", i);
        }

        let encoded = encode_base64_offset("Set-MpPreference ", &Some(Utf16Modifier::Utf16le));
        let expected = [
            "UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA",
            "MAZQB0AC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA",
            "TAGUAdAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA",
        ];
        assert_eq!(encoded.len(), 3);

        for (i, t) in encoded.iter().enumerate() {
            assert_eq!(expected[i], t, "{}", i);
        }

        let encoded = encode_base64_offset("add-mppreference ", &Some(Utf16Modifier::Utf16le));
        let expected = [
            "YQBkAGQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA",
            "EAZABkAC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA",
            "hAGQAZAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA",
        ];
        assert_eq!(encoded.len(), 3);

        for (i, t) in encoded.iter().enumerate() {
            assert_eq!(expected[i], t, "{}", i);
        }

        let encoded = encode_base64_offset("set-mppreference ", &Some(Utf16Modifier::Utf16le));
        let expected = [
            "cwBlAHQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA",
            "MAZQB0AC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA",
            "zAGUAdAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA",
        ];
        assert_eq!(encoded.len(), 3);

        for (i, t) in encoded.iter().enumerate() {
            assert_eq!(expected[i], t, "{}", i);
        }
    }

    #[test]
    fn test_base64_offset_empty() {
        let encoded = encode_base64_offset("", &None);
        assert_eq!(encoded.len(), 0);

        let encoded = encode_base64_offset("", &Some(Utf16Modifier::Utf16be));
        assert_eq!(encoded.len(), 0);

        let encoded = encode_base64_offset("", &Some(Utf16Modifier::Utf16le));
        assert_eq!(encoded.len(), 0);
    }

    #[test]
    fn test_windash_one_param() {
        let variations = windash_variations(" -param-name ");
        let expected = [
            " -param-name ",
            " /param-name ",
            " –param-name ",
            " —param-name ",
            " ―param-name ",
        ];

        assert_eq!(variations.len(), expected.len());

        for (i, variation) in variations.iter().enumerate() {
            assert_eq!(expected[i], variation, "{}", i);
        }
    }

    #[test]
    fn test_windash_no_variation() {
        let variations = windash_variations(" param-name ");
        let expected = [" param-name "];

        assert_eq!(variations.len(), expected.len());

        for (i, variation) in variations.iter().enumerate() {
            assert_eq!(expected[i], variation, "{}", i);
        }
    }

    #[test]
    fn test_windash_two_params() {
        let variations = windash_variations(" -param-name /another-param");
        let expected = [
            " -param-name /another-param",
            " /param-name /another-param",
            " –param-name /another-param",
            " —param-name /another-param",
            " ―param-name /another-param",
            " -param-name -another-param",
            " -param-name –another-param",
            " -param-name —another-param",
            " -param-name ―another-param",
        ];

        assert_eq!(variations.len(), expected.len());

        for variation in variations.into_iter() {
            assert!(expected.contains(&&*variation), "{}", variation);
        }
    }

    #[test]
    fn test_cidr_ipv4() {
        let cidr: IpCidr = "192.168.1.0/24".parse().expect("Invalid CIDR");
        let ip: IpAddr = "192.168.1.10".parse().expect("Invalid IP address");

        assert!(cidr.contains(&ip))
    }

    #[test]
    fn test_cidr_ipv6() {
        let cidr: IpCidr = "2001:db8::/32".parse().expect("Invalid CIDR");
        let ip: IpAddr = "2001:db8::1".parse().expect("Invalid IP address");

        assert!(cidr.contains(&ip))
    }
}
