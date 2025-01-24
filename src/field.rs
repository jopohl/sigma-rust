mod modifier;
mod transformation;
mod value;

pub use modifier::*;
pub use value::*;

use crate::basevalue::BaseValue;
use crate::error::ParserError;
use crate::error::ParserError::{IPParsing, InvalidYAML};
use crate::event::{Event, EventValue};
use crate::field::transformation::{encode_base64, encode_base64_offset, windash_variations};
use crate::field::ValueTransformer::{Base64, Base64offset, Windash};
use crate::wildcard::tokenize;
use cidr::IpCidr;
use regex::Regex;
use serde_yml::Value;
use std::str::FromStr;

// https://sigmahq.io/docs/basics/modifiers.html
#[derive(Debug)]
pub struct Field {
    pub name: String,
    pub values: Vec<FieldValue>,
    pub(crate) modifier: Modifier,
}

impl FromStr for Field {
    type Err = ParserError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let result = Self {
            name: s.split("|").next().unwrap_or("").to_string(),
            values: vec![],
            modifier: Modifier::from_str(s)?,
        };

        Ok(result)
    }
}

impl Field {
    pub(crate) fn new<S: AsRef<str>>(
        name_with_modifiers: S,
        values: Vec<FieldValue>,
    ) -> Result<Field, ParserError> {
        match Self::from_str(name_with_modifiers.as_ref()) {
            Ok(mut field) => {
                field.values = values;
                match field.bootstrap() {
                    Ok(_) => Ok(field),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }

    pub(crate) fn from_yaml<S: AsRef<str>>(name: S, value: Value) -> Result<Field, ParserError> {
        let field_values = match value {
            Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Null => {
                vec![FieldValue::try_from(value)?]
            }
            Value::Sequence(seq) => {
                let mut result = Vec::with_capacity(seq.len());
                for item in seq {
                    result.push(FieldValue::try_from(item)?);
                }
                result
            }
            _ => return Err(InvalidYAML(format!("{:?}", value))),
        };
        Self::new(name, field_values)
    }

    fn bootstrap(&mut self) -> Result<(), ParserError> {
        if self.values.is_empty() {
            return Err(ParserError::EmptyValues(self.name.to_string()));
        }

        if self.modifier.exists.is_some() {
            if self.values.len() != 1 {
                return Err(ParserError::InvalidValueForExists());
            }
            if let FieldValue::Base(BaseValue::Boolean(b)) = self.values[0] {
                self.modifier.exists = Some(b);
            } else {
                return Err(ParserError::InvalidValueForExists());
            }
        }

        if self.modifier.value_transformer.is_some() {
            let mut transformed_values: Vec<FieldValue> = Vec::with_capacity(self.values.len());

            for val in &self.values {
                let s = val.as_string()?;
                match &self.modifier.value_transformer {
                    Some(Base64(utf16)) => {
                        transformed_values.push(FieldValue::from(encode_base64(s.as_str(), utf16)))
                    }
                    Some(Base64offset(utf16)) => transformed_values.extend(
                        encode_base64_offset(s.as_str(), utf16)
                            .into_iter()
                            .map(FieldValue::from),
                    ),
                    Some(Windash) => transformed_values.extend(
                        windash_variations(s.as_str())
                            .into_iter()
                            .map(FieldValue::from),
                    ),
                    None => {}
                }
            }

            self.values = transformed_values;
        }

        for v in self.values.iter_mut() {
            match self.modifier.match_modifier {
                Some(MatchModifier::Contains) => {
                    if self.modifier.fieldref {
                        continue;
                    }
                    if let FieldValue::Base(BaseValue::String(s)) = v {
                        s.insert(0, '*');
                        s.push('*');
                    } else {
                        return Err(ParserError::InvalidValueForStringModifier(
                            self.name.clone(),
                        ));
                    }
                }
                Some(MatchModifier::StartsWith) => {
                    if self.modifier.fieldref {
                        continue;
                    }
                    if let FieldValue::Base(BaseValue::String(s)) = v {
                        s.push('*');
                    } else {
                        return Err(ParserError::InvalidValueForStringModifier(
                            self.name.clone(),
                        ));
                    }
                }
                Some(MatchModifier::EndsWith) => {
                    if self.modifier.fieldref {
                        continue;
                    }
                    if let FieldValue::Base(BaseValue::String(s)) = v {
                        s.insert(0, '*');
                    } else {
                        return Err(ParserError::InvalidValueForStringModifier(
                            self.name.clone(),
                        ));
                    }
                }
                Some(MatchModifier::Cidr) => match IpCidr::from_str(v.as_string()?.as_str()) {
                    Ok(ip) => *v = FieldValue::Cidr(ip),
                    Err(err) => return Err(IPParsing(v.as_string()?, err.to_string())),
                },
                Some(MatchModifier::Re) => match Regex::new(v.as_string()?.as_str()) {
                    Ok(re) => *v = FieldValue::Regex(re),
                    Err(err) => return Err(ParserError::RegexParsing(err)),
                },
                _ => {}
            }
        }

        if !self.modifier.fieldref {
            for v in self.values.iter_mut() {
                if let FieldValue::Base(BaseValue::String(s)) = v {
                    if self.modifier.cased {
                        *v = FieldValue::WildcardPattern(tokenize(s));
                    } else {
                        *v = FieldValue::WildcardPattern(tokenize(s.to_lowercase().as_str()));
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) fn evaluate(&self, event: &Event) -> bool {
        let Some(event_value) = event.get(&self.name) else {
            return matches!(self.modifier.exists, Some(false));
        };

        if matches!(self.modifier.exists, Some(true)) {
            return true;
        };

        if self.values.is_empty() {
            // self.values should never be empty.
            // But, if it somehow happens we must return true, because
            //      1. the key exists in the event, and
            //      2. the field has no further conditions defined
            return true;
        }

        for val in self.values.iter() {
            let cmp = if self.modifier.fieldref {
                let event_fieldref_value = if let FieldValue::Base(BaseValue::String(s)) = val {
                    event.get(s)
                } else if let FieldValue::Base(b) = val {
                    event.get(b.value_to_string().as_str())
                } else {
                    // Should never happen as we do not compile values if fieldref modifier is given
                    continue;
                };

                match event_fieldref_value {
                    Some(EventValue::Value(v)) => &FieldValue::Base(v.clone()),
                    _ => return false,
                }
            } else {
                val
            };

            let fired = event_value.matches(cmp, &self.modifier);
            if fired && !self.modifier.match_all {
                return true;
            } else if !fired && self.modifier.match_all {
                return false;
            }
        }
        // After the loop, there are two options:
        // 1. match_all = false: no condition fired  => return false
        // 2. match_all = true: all conditions fired => return true
        self.modifier.match_all
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_name_only() {
        let field = Field::from_str("a").unwrap();
        assert_eq!(field.name, "a");
        assert!(field.modifier.match_modifier.is_none());
        assert!(field.modifier.value_transformer.is_none());
        assert!(!field.modifier.match_all);
    }

    #[test]
    fn test_parse_contains_modifier() {
        let field = Field::from_str("hello|contains").unwrap();
        assert_eq!(field.name, "hello");
        assert_eq!(
            field.modifier.match_modifier.unwrap(),
            MatchModifier::Contains
        );
        assert!(field.modifier.value_transformer.is_none());
        assert!(!field.modifier.match_all);
    }

    #[test]
    fn test_parse_value_transformer_modifier() {
        let field = Field::from_str("hello|windash|contains").unwrap();
        assert_eq!(field.name, "hello");
        assert_eq!(field.modifier.match_modifier, Some(MatchModifier::Contains));
        assert_eq!(field.modifier.value_transformer, Some(Windash));
    }

    #[test]
    fn test_parse_base64_modifier() {
        let field = Field::from_str("hello|base64|endswith").unwrap();
        assert_eq!(field.name, "hello");
        assert_eq!(field.modifier.match_modifier, Some(MatchModifier::EndsWith));
        assert_eq!(field.modifier.value_transformer, Some(Base64(None)));
    }

    #[test]
    fn test_parse_utf16_modifier() {
        let field = Field::from_str("hello|base64offset|utf16le|endswith").unwrap();
        assert_eq!(field.name, "hello");
        assert_eq!(field.modifier.match_modifier, Some(MatchModifier::EndsWith));
        assert_eq!(
            field.modifier.value_transformer,
            Some(Base64offset(Some(Utf16Modifier::Utf16le)))
        );
    }

    #[test]
    fn test_evaluate_equals() {
        let field = Field::new(
            "test",
            vec![
                FieldValue::from("zsh"),
                FieldValue::from("BASH"),
                FieldValue::from("pwsh"),
            ],
        )
        .unwrap();
        let event_no_match = Event::from([("test", "zsh shutdown")]);
        assert!(!field.evaluate(&event_no_match));
        let matching_event = Event::from([("test", "bash")]);
        assert!(field.evaluate(&matching_event));
    }

    #[test]
    fn test_evaluate_equals_cased() {
        let field = Field::new("test|cased", vec![FieldValue::from("bash")]).unwrap();
        let event_no_match = Event::from([("test", "BASH")]);
        assert!(!field.evaluate(&event_no_match));
        let matching_event = Event::from([("test", "bash")]);
        assert!(field.evaluate(&matching_event));
    }

    #[test]
    fn test_evaluate_startswith() {
        let mut field = Field::new(
            "test|startswith",
            vec![
                FieldValue::from("zsh"),
                FieldValue::from("bash"),
                FieldValue::from("pwsh"),
            ],
        )
        .unwrap();
        let event = Event::from([("test", "zsh shutdown")]);
        assert!(field.evaluate(&event));

        field.modifier.match_all = true;
        assert!(!field.evaluate(&event));
    }

    #[test]
    fn test_evaluate_endswith() {
        let field = Field::new(
            "test|endswith",
            vec![FieldValue::from("h"), FieldValue::from("sh")],
        )
        .unwrap();
        let event = Event::from([("test", "zsh")]);
        assert!(field.evaluate(&event));

        let field = Field::new(
            "test|endswith|all",
            vec![FieldValue::from("h"), FieldValue::from("sh")],
        )
        .unwrap();
        assert!(field.evaluate(&event));
    }

    #[test]
    fn test_evaluate_contains() {
        let field = Field::new(
            "test|contains",
            vec![FieldValue::from("zsh"), FieldValue::from("python2")],
        )
        .unwrap();
        let event = Event::from([("test", "zsh python3 -c os.remove('/')")]);
        assert!(field.evaluate(&event));

        let field = Field::new(
            "test|contains|all",
            vec![FieldValue::from("zsh"), FieldValue::from("python2")],
        )
        .unwrap();
        assert!(!field.evaluate(&event));
    }

    #[test]
    fn test_evaluate_lt() {
        let mut field =
            Field::new("test|lt", vec![FieldValue::from(10), FieldValue::from(15)]).unwrap();
        let event = Event::from([("test", 10)]);
        assert!(field.evaluate(&event));

        field.modifier.match_all = true;
        assert!(!field.evaluate(&event));
    }

    #[test]
    fn test_evaluate_lte() {
        let mut field =
            Field::new("test|lte", vec![FieldValue::from(15), FieldValue::from(20)]).unwrap();
        let event = Event::from([("test", 15)]);
        assert!(field.evaluate(&event));

        field.modifier.match_all = true;
        assert!(field.evaluate(&event));
    }

    #[test]
    fn test_evaluate_gt() {
        let mut field = Field::new("test|gt", vec![FieldValue::from(10.1)]).unwrap();
        let event = Event::from([("test", 10.2)]);
        assert!(field.evaluate(&event));

        field.modifier.match_all = true;
        assert!(field.evaluate(&event));
    }

    #[test]
    fn test_evaluate_gte() {
        let mut field =
            Field::new("test|gte", vec![FieldValue::from(15), FieldValue::from(10)]).unwrap();
        let event = Event::from([("test", 15)]);
        assert!(field.evaluate(&event));

        field.modifier.match_all = true;
        assert!(field.evaluate(&event));

        field.modifier.match_all = false;

        // We enforce strict type checking, so 15.0 will fail to compare against the int values
        let event = Event::from([("test", 14.0)]);
        assert!(!field.evaluate(&event));

        // If we add a float it will work though
        field.values.push(FieldValue::from(12.34));
        assert!(field.evaluate(&event));

        field.modifier.match_all = true;
        assert!(!field.evaluate(&event));
    }

    #[test]
    fn test_evaluate_regex() {
        let mut field = Field::new(
            "test|re",
            vec![
                FieldValue::from(r"hello (.*)d"),
                FieldValue::from(r"goodbye (.*)"),
            ],
        )
        .unwrap();

        for val in &field.values {
            assert!(matches!(val, FieldValue::Regex(_)));
        }

        let event = Event::from([("test", "hello world")]);
        assert!(field.evaluate(&event));

        field.modifier.match_all = true;
        assert!(!field.evaluate(&event));
    }

    #[test]
    fn test_cidr() {
        let cidrs = ["10.0.0.0/16", "10.0.0.0/24"];
        let mut field = Field::new(
            "test|cidr",
            cidrs.into_iter().map(FieldValue::from).collect(),
        )
        .unwrap();

        let event = Event::from([("test", "10.0.1.1")]);
        assert!(field.evaluate(&event));
        field.modifier.match_all = true;

        assert!(!field.evaluate(&event));

        let event = Event::from([("test", "10.1.2.3")]);
        field.modifier.match_all = false;
        assert!(!field.evaluate(&event));
    }

    #[test]
    fn test_base64_utf16le() {
        let patterns = ["Add-MpPreference ", "Set-MpPreference "];
        let field = Field::new(
            "test|base64|utf16le|contains",
            patterns
                .iter()
                .map(|x| FieldValue::from(x.to_string()))
                .collect(),
        )
        .unwrap();

        let event = Event::from([(
            "test",
            "jkdfgnhjkQQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAioskdfgjk",
        )]);
        assert!(field.evaluate(&event));

        let event = Event::from([(
            "test",
            "23234345UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA3535446d",
        )]);
        assert!(field.evaluate(&event));
    }

    #[test]
    fn test_base64offset_utf16le() {
        let patterns = [
            "Add-MpPreference ",
            "Set-MpPreference ",
            "add-mppreference ",
            "set-mppreference ",
        ];
        let field = Field::new(
            "test|base64offset|utf16le|contains",
            patterns.into_iter().map(FieldValue::from).collect(),
        )
        .unwrap();

        let expected = [
            "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA",
            "EAZABkAC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA",
            "BAGQAZAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA",
            "UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA",
            "MAZQB0AC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA",
            "TAGUAdAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA",
            "YQBkAGQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA",
            "EAZABkAC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA",
            "hAGQAZAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA",
            "cwBlAHQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA",
            "MAZQB0AC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA",
            "zAGUAdAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA",
        ];

        for pattern in expected.into_iter() {
            let mut scrambled_pattern = pattern.to_string().clone();
            scrambled_pattern.insert_str(0, "klsenf");
            scrambled_pattern.insert_str(scrambled_pattern.len(), "scvfv");
            let event = Event::from([("test", scrambled_pattern.clone())]);
            assert!(
                field.evaluate(&event),
                "pattern: {} || values: {:?}",
                scrambled_pattern,
                field.values
            );
        }
    }

    #[test]
    fn test_windash() {
        let patterns = ["-my-param", "/another-param"];
        let field = Field::new(
            "test|windash|contains",
            patterns.into_iter().map(FieldValue::from).collect(),
        )
        .unwrap();

        let event = Event::from([("test", "program.exe /my-param")]);
        assert!(field.evaluate(&event));

        let event = Event::from([("test", "another.exe -another-param")]);
        assert!(field.evaluate(&event));
    }

    #[test]
    fn test_empty_values() {
        let values: Vec<FieldValue> = vec![];
        let err = Field::new("test|contains", values).unwrap_err();
        assert!(matches!(err, ParserError::EmptyValues(a) if a == "test"));
    }

    #[test]
    fn test_invalid_contains() {
        let values: Vec<FieldValue> = vec![FieldValue::from("ok"), FieldValue::from(5)];
        let err = Field::new("test|contains", values).unwrap_err();
        assert!(matches!(err, ParserError::InvalidValueForStringModifier(name) if name == "test"));
    }

    #[test]
    fn test_parse_exists_modifier() {
        let values: Vec<FieldValue> = vec![FieldValue::from(true)];
        let field = Field::new("test|exists", values).unwrap();
        assert!(field.modifier.exists.unwrap());

        let values: Vec<FieldValue> = vec![FieldValue::from(false)];
        let field = Field::new("test|exists", values).unwrap();
        assert!(!field.modifier.exists.unwrap());
    }

    #[test]
    fn test_parse_exists_modifier_invalid_values() {
        let values_vec: Vec<Vec<FieldValue>> = vec![
            vec![FieldValue::from("not a boolean")],
            vec![FieldValue::from("something"), FieldValue::from(5.0)],
            vec![FieldValue::from(true), FieldValue::from(true)],
        ];

        for values in values_vec {
            let err = Field::new("test|exists", values).unwrap_err();
            assert!(matches!(err, ParserError::InvalidValueForExists()));
        }
    }
}
