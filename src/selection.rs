use crate::error::ParserError;
use crate::error::SelectionError::{
    InvalidKeywordSelection, InvalidSelectionType, MixedKeywordAndFieldlist,
    SelectionContainsNoFields,
};
use crate::event::Event;
use crate::field::Field;
use serde::Deserialize;
use serde_yml::Value;
use serde_yml::Value::{Mapping, Sequence};

/// A field group is a collection of fields that are to be combined with AND
/// In other words a fields group translates to a YAML dictionary
#[derive(Debug)]
pub struct FieldGroup {
    pub fields: Vec<Field>,
}

impl FieldGroup {
    fn evaluate(&self, event: &Event) -> bool {
        self.fields.iter().all(|field| field.evaluate(event))
    }
}

impl TryFrom<serde_yml::Mapping> for FieldGroup {
    type Error = ParserError;
    fn try_from(mapping: serde_yml::Mapping) -> Result<Self, Self::Error> {
        let mut fields = vec![];
        for (name, values) in mapping.into_iter() {
            match name {
                Value::String(name) => fields.push(Field::from_yaml(name, values)?),
                _ => return Err(Self::Error::InvalidFieldName(format!("{:?}", name))),
            }
        }
        Ok(Self { fields })
    }
}

#[derive(Deserialize)]
struct SelectionProxy {
    #[serde(flatten)]
    value: Value,
}

#[derive(Debug, Deserialize)]
#[serde(try_from = "SelectionProxy")]
pub enum Selection {
    Keyword(Vec<String>),
    Field(Vec<FieldGroup>),
}

impl TryFrom<SelectionProxy> for Selection {
    type Error = ParserError;

    fn try_from(other: SelectionProxy) -> Result<Self, Self::Error> {
        Self::try_from(other.value)
    }
}

impl TryFrom<Value> for Selection {
    type Error = ParserError;
    fn try_from(other: Value) -> Result<Self, Self::Error> {
        match other {
            Sequence(seq) => {
                if seq.is_empty() {
                    return Err(Self::Error::SelectionParsingError(
                        String::new(),
                        SelectionContainsNoFields(),
                    ));
                }
                let is_keyword_selection = !seq[0].is_mapping();
                if is_keyword_selection {
                    let mut keywords = vec![];
                    for value in seq.iter() {
                        match value {
                            Value::String(s) => keywords.push(s.to_string()),
                            Value::Number(n) => keywords.push(n.to_string()),
                            Value::Bool(b) => keywords.push(b.to_string()),
                            _ => {
                                return Err(Self::Error::SelectionParsingError(
                                    String::new(),
                                    InvalidKeywordSelection(format!("{:?}", value)),
                                ))
                            }
                        }
                    }
                    return Ok(Self::Keyword(keywords));
                }
                // field list selection
                let mut field_groups = vec![];
                for value in seq {
                    match value {
                        Mapping(map) => {
                            field_groups.push(FieldGroup::try_from(map)?);
                        }
                        _ => {
                            return Err(Self::Error::SelectionParsingError(
                                String::new(),
                                MixedKeywordAndFieldlist(),
                            ))
                        }
                    }
                }
                Ok(Self::Field(field_groups))
            }
            Mapping(mapping) => {
                let field_group = FieldGroup::try_from(mapping)?;
                Ok(Self::Field(vec![field_group]))
            }
            _ => Err(Self::Error::SelectionParsingError(
                String::new(),
                InvalidSelectionType(),
            )),
        }
    }
}

impl Selection {
    pub(crate) fn evaluate(&self, event: &Event) -> bool {
        match &self {
            Self::Keyword(keywords) => event
                .values()
                .any(|v| keywords.iter().any(|kw| v.contains(kw))),
            Self::Field(field_groups) => field_groups.iter().any(|g| g.evaluate(event)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basevalue::BaseValue;
    use crate::event::Event;
    use crate::field::{FieldValue, MatchModifier};
    use serde_yml::Value;

    #[test]
    fn test_keyword_selection() {
        let selection = Selection::Keyword(vec![
            "test".to_string(),
            "linux".to_string(),
            "arch".to_string(),
        ]);

        let event = Event::from([("key", "zsh shutdown test")]);
        assert!(selection.evaluate(&event));

        let event = Event::from([("nomatch", "zsh shutdown".to_string())]);
        assert!(!selection.evaluate(&event));

        let event = Event::from([("some", "the arch is on".to_string())]);
        assert!(selection.evaluate(&event));

        let event = Event::from([("some", "linux is best".to_string())]);
        assert!(selection.evaluate(&event));

        let event = Event::from([("some", " arch linux ".to_string())]);
        assert!(selection.evaluate(&event));
    }

    #[test]
    fn test_fields_selection() {
        let selection = Selection::Field(vec![FieldGroup {
            fields: vec![
                Field::new(
                    "name1|contains",
                    vec![FieldValue::from("hello"), FieldValue::from("world")],
                )
                .unwrap(),
                Field::new("name2|cidr", vec![FieldValue::from("10.0.0.0/16")]).unwrap(),
            ],
        }]);

        let event = Event::from([("name1", "the world is big"), ("name2", "10.0.43.44")]);
        assert!(selection.evaluate(&event));

        let event = Event::from([("nomatch", "the world is big"), ("name2", "10.42.43.44")]);
        assert!(!selection.evaluate(&event));
    }

    #[test]
    fn test_new_keyword_selection() {
        let keywords = vec!["test".to_string(), "linux".to_string(), "arch".to_string()];
        let value = Value::from(keywords.clone());

        let selection = Selection::try_from(value).unwrap();
        assert!(matches!(selection, Selection::Keyword(kw) if kw.len() == keywords.len()));
    }

    #[test]
    fn test_mixed_keyword_selection() {
        let yaml = r#"
            - 0
            - 6
            - hello
    "#;

        let value: Value = serde_yml::from_str(yaml).unwrap();
        let selection = Selection::try_from(value).unwrap();
        assert!(
            matches!(selection, Selection::Keyword(kw) if kw.len() == 3 && kw[0] == "0" && kw[1] == "6" && kw[2] == "hello")
        );
    }

    #[test]
    fn test_invalid_keyword_selection() {
        let yaml = r#"
            - 0
            - 6
            - hello: world
    "#;

        let value: Value = serde_yml::from_str(yaml).unwrap();
        let err = Selection::try_from(value).unwrap_err();
        assert!(matches!(
            err,
            ParserError::SelectionParsingError(_, InvalidKeywordSelection(_)),
        ));
    }

    #[test]
    fn test_new_fields_selection() {
        let yaml = r#"
    selection:
        EventID: 6416
        Float: 42.21
        ClassName: 'DiskDrive'
        RandomID|contains:
            - ab
            - cd
            - ed
"#;
        let data: serde_yml::Mapping = serde_yml::from_str(yaml).unwrap();
        assert_eq!(data.len(), 1);

        let value = data.values().next().unwrap().clone();
        let selection = Selection::try_from(value).unwrap();

        match selection {
            Selection::Field(field_group) => {
                assert_eq!(field_group.len(), 1);
                let fields = &field_group[0].fields;
                assert_eq!(fields[0].name, "EventID");
                assert_eq!(fields[0].values.len(), 1);
                assert!(matches!(
                    fields[0].values[0],
                    FieldValue::Base(BaseValue::Int(6416))
                ));

                assert_eq!(fields[1].name, "Float");
                assert_eq!(fields[1].values.len(), 1);
                assert!(matches!(
                    fields[1].values[0],
                    FieldValue::Base(BaseValue::Float(42.21))
                ));

                assert_eq!(fields[2].name, "ClassName");
                assert_eq!(fields[2].values.len(), 1);
                assert!(matches!(
                    fields[2].values[0],
                    FieldValue::WildcardPattern(_)
                ));

                assert_eq!(fields[3].name, "RandomID");
                assert_eq!(fields[3].values.len(), 3);
                assert!(matches!(
                    fields[3].values[0],
                    FieldValue::WildcardPattern(_)
                ));

                assert!(matches!(
                    fields[3].modifier.match_modifier,
                    Some(MatchModifier::Contains)
                ));
            }
            Selection::Keyword(_) => {
                panic!("wrong mode")
            }
        }
    }
}
