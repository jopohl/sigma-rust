mod ast;
mod lexer;

use crate::detection::ast::Ast;
use crate::error::ParserError;
use crate::event::Event;
use crate::selection::Selection;
use glob_match::glob_match;
use serde::Deserialize;
use serde_yml::Value;
use std::collections::HashMap;

#[derive(Deserialize, Debug)]
struct DetectionProxy {
    #[serde(flatten)]
    selections: HashMap<String, Value>,
    condition: String,
}

#[derive(Debug, Deserialize)]
#[serde(try_from = "DetectionProxy")]
pub struct Detection {
    #[serde(flatten)]
    selections: HashMap<String, Selection>,
    condition: String,
    #[serde(skip)]
    ast: Ast,
}

impl TryFrom<DetectionProxy> for Detection {
    type Error = ParserError;

    fn try_from(other: DetectionProxy) -> Result<Self, Self::Error> {
        let mut selections = HashMap::with_capacity(other.selections.len());
        for (name, selection) in other.selections {
            match Selection::try_from(selection) {
                Ok(selection) => {
                    selections.insert(name, selection);
                }
                Err(e) => {
                    return match e {
                        ParserError::SelectionParsingError(_, se) => {
                            Err(ParserError::SelectionParsingError(name, se))
                        }
                        _ => Err(e),
                    }
                }
            }
        }
        let result = Self::new(selections, other.condition)?;
        Ok(result)
    }
}

impl Detection {
    pub fn get_selections(&self) -> &HashMap<String, Selection> {
        &self.selections
    }

    pub fn get_condition(&self) -> &str {
        &self.condition
    }

    pub(crate) fn new<S: AsRef<str>>(
        selections: HashMap<String, Selection>,
        condition: S,
    ) -> Result<Self, ParserError> {
        let mut result = Self {
            selections,
            condition: condition.as_ref().into(),
            ast: Ast::default(),
        };
        result.parse_ast()?;
        Ok(result)
    }

    pub(crate) fn parse_ast(&mut self) -> Result<(), ParserError> {
        let ast = Ast::new(self.condition.as_str())?;
        let identifiers = ast.selections();

        let missing: Vec<String> = identifiers
            .into_iter()
            .filter(|i| !self.selections.contains_key(*i))
            .map(|i| i.to_string())
            .collect();

        if !missing.is_empty() {
            return Err(ParserError::UndefinedIdentifiers(missing));
        }

        self.ast = ast;
        Ok(())
    }

    pub(crate) fn evaluate(&self, event: &Event) -> bool {
        self.eval(event, &self.ast, &mut HashMap::new())
    }

    fn evaluate_selection(
        &self,
        name: &str,
        lookup: &mut HashMap<String, bool>,
        event: &Event,
    ) -> bool {
        if let Some(e) = lookup.get(name) {
            *e
        } else if let Some(selection) = self.selections.get(name) {
            let eval = selection.evaluate(event);
            lookup.insert(name.to_string(), eval);
            eval
        } else {
            // should never happen because we check before evaluate
            // whether all selections in the condition are covered
            false
        }
    }

    fn eval(&self, event: &Event, ast: &Ast, lookup: &mut HashMap<String, bool>) -> bool {
        match ast {
            Ast::Selection(s) => self.evaluate_selection(s, lookup, event),
            Ast::OneOf(s) => self
                .selections
                .keys()
                .filter(|name| glob_match(s, name))
                .map(|name| self.evaluate_selection(name, lookup, event))
                .any(|b| b),
            Ast::OneOfThem => self
                .selections
                .keys()
                .map(|name| self.evaluate_selection(name, lookup, event))
                .any(|b| b),
            Ast::AllOf(s) => self
                .selections
                .keys()
                .filter(|name| glob_match(s, name))
                .map(|name| self.evaluate_selection(name, lookup, event))
                .all(|b| b),
            Ast::AllOfThem => self
                .selections
                .keys()
                .map(|name| self.evaluate_selection(name, lookup, event))
                .all(|b| b),
            Ast::Not(ref operand) => !self.eval(event, operand, lookup),
            Ast::Or(ref left, ref right) => {
                self.eval(event, left, lookup) || self.eval(event, right, lookup)
            }
            Ast::And(ref left, ref right) => {
                self.eval(event, left, lookup) && self.eval(event, right, lookup)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_identifier() {
        let err = Detection::new(HashMap::new(), "selection1 and selection2").unwrap_err();
        assert!(matches!(err, ParserError::UndefinedIdentifiers(_)));
    }

    #[test]
    fn test_evaluate() {
        let detection_yaml = r#"
    selection_1:
        EventID: 6416
        RandomID|contains:
            - ab
            - cd
            - ed
    selection_2:
        EventID: 5555
    condition: selection_1 or selection_2
"#;

        let mut event = Event::from([("EventID", 6416)]);
        event.insert("RandomID", "ab");

        let detection: Detection = serde_yml::from_str(detection_yaml).unwrap();
        assert_eq!(detection.selections.len(), 2);
        let result = detection.evaluate(&event);
        assert!(result);

        let detection =
            Detection::new(detection.selections, "selection_1 and selection_2").unwrap();
        let result = detection.evaluate(&event);
        assert!(!result);
    }

    #[test]
    fn test_evaluate_one_all_of_them() {
        let detection_yaml = r#"
    selection_1:
        EventID: 6416
        RandomID|contains:
            - ab
            - cd
            - ed
    selection_2:
        EventID: 5555
    condition: 1 of them
"#;

        let mut event = Event::from([("EventID", 6416)]);
        event.insert("RandomID", "ab");

        let detection: Detection = serde_yml::from_str(detection_yaml).unwrap();
        assert_eq!(detection.selections.len(), 2);
        let result = detection.evaluate(&event);
        assert!(result);

        let detection = Detection::new(detection.selections, "all of them").unwrap();
        let result = detection.evaluate(&event);
        assert!(!result);
    }

    #[test]
    fn test_evaluate_one_of() {
        let detection_yaml = r#"
    selection_1:
        EventID: 6416
        RandomID|contains:
            - ab
            - cd
            - ed
    selection_2:
        EventID: 5555
    condition: 1 of selection*
"#;

        let mut event = Event::from([("EventID", 6416)]);
        event.insert("RandomID", "ab");

        let detection: Detection = serde_yml::from_str(detection_yaml).unwrap();
        assert_eq!(detection.selections.len(), 2);
        let result = detection.evaluate(&event);
        assert!(result);

        let detection = Detection::new(detection.selections, "1 of nothing*").unwrap();
        let result = detection.evaluate(&event);
        assert!(!result);
    }

    #[test]
    fn test_evaluate_all_of() {
        let detection_yaml = r#"
    selection_1:
        EventID: 6416
        RandomID|contains:
            - ab
            - cd
            - ed
    selection_2:
        EventID: 5555
    condition: all of selection*
"#;

        let mut event = Event::from([("EventID", 6416)]);
        event.insert("RandomID", "ab");

        let detection: Detection = serde_yml::from_str(detection_yaml).unwrap();
        assert_eq!(detection.selections.len(), 2);
        let result = detection.evaluate(&event);
        assert!(!result);

        let detection = Detection::new(detection.selections, "all of selection_1*").unwrap();
        let result = detection.evaluate(&event);
        assert!(result);

        let detection = Detection::new(detection.selections, "all of nothing*").unwrap();
        let result = detection.evaluate(&event);
        assert!(result);
    }
}
