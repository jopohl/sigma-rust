use crate::detection::lexer::{Lexer, Token};
use crate::error::ParserError;
use std::collections::HashSet;
use std::fmt;

enum PrefixOperator {
    Not,
}

impl PrefixOperator {
    fn binding_power(&self) -> u8 {
        match self {
            Self::Not => 3,
        }
    }
}

enum InfixOperator {
    And,
    Or,
}

impl InfixOperator {
    fn binding_power(&self) -> u8 {
        match self {
            Self::And => 2,
            Self::Or => 1,
        }
    }
}

#[derive(Debug)]
pub(crate) enum Ast {
    Selection(String),
    OneOf(String),
    OneOfThem,
    AllOf(String),
    AllOfThem,
    Not(Box<Ast>),
    And(Box<Ast>, Box<Ast>),
    Or(Box<Ast>, Box<Ast>),
}

impl Default for Ast {
    fn default() -> Self {
        Self::Selection("".to_string())
    }
}

impl Ast {
    pub(crate) fn new(input: &str) -> Result<Self, ParserError> {
        let mut lexer = Lexer::new(input);
        Self::parse_token_stream(&mut lexer, 0)
    }

    fn parse_token_stream(lexer: &mut Lexer, min_binding_power: u8) -> Result<Self, ParserError> {
        let mut left = match lexer.next() {
            Token::Selection(s) => Self::Selection(s),
            Token::OneOf(s) => Self::OneOf(s),
            Token::OneOfThem => Self::OneOfThem,
            Token::AllOf(s) => Self::AllOf(s),
            Token::AllOfThem => Self::AllOfThem,
            Token::OpeningParenthesis => {
                let left = Self::parse_token_stream(lexer, 0)?;
                if lexer.next() != Token::ClosingParenthesis {
                    return Err(ParserError::MissingClosingParenthesis());
                }
                left
            }
            Token::Not => {
                let right = Self::parse_token_stream(lexer, PrefixOperator::Not.binding_power())?;
                Self::Not(Box::new(right))
            }
            t => return Err(ParserError::UnexpectedToken(t.to_string())),
        };

        loop {
            let operator = match lexer.peek() {
                Token::End | Token::ClosingParenthesis => break,
                Token::And => InfixOperator::And,
                Token::Or => InfixOperator::Or,
                t => return Err(ParserError::InvalidOperator(t.to_string())),
            };

            let bp = operator.binding_power();
            if bp < min_binding_power {
                break;
            }
            lexer.next();

            left = {
                let right = Self::parse_token_stream(lexer, bp)?;
                match operator {
                    InfixOperator::And => Self::And(Box::new(left), Box::new(right)),
                    InfixOperator::Or => Self::Or(Box::new(left), Box::new(right)),
                }
            };
        }

        Ok(left)
    }

    pub(crate) fn selections(&self) -> HashSet<&str> {
        let mut result: HashSet<&str> = HashSet::new();
        Self::selections_recursive(self, &mut result);
        result
    }

    fn selections_recursive<'a>(current: &'a Self, acc: &mut HashSet<&'a str>) {
        match current {
            Self::Selection(s) => _ = acc.insert(s),
            Self::Not(s) => Self::selections_recursive(s, acc),
            Self::Or(left, right) | Self::And(left, right) => {
                Self::selections_recursive(left, acc);
                Self::selections_recursive(right, acc);
            }
            Self::OneOf(_) | Self::OneOfThem | Self::AllOf(_) | Self::AllOfThem => {}
        }
    }
}

impl fmt::Display for Ast {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selection(s) => write!(f, "{}", s),
            Self::OneOf(s) => write!(f, "1 of {}", s),
            Self::OneOfThem => write!(f, "1 of them"),
            Self::AllOf(s) => write!(f, "all of {}", s),
            Self::AllOfThem => write!(f, "all of them"),
            Self::Not(a) => write!(f, "not ({})", a),
            Self::And(a, b) => write!(f, "({} and {})", a, b),
            Self::Or(a, b) => write!(f, "({} or {})", a, b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_expression() {
        let ast = Ast::new("selection_1 and selection_2").unwrap();
        assert_eq!(ast.to_string(), "(selection_1 and selection_2)");
    }

    #[test]
    fn test_parse_binding_power() {
        let ast = Ast::new("x or y and z").unwrap();
        assert_eq!(ast.to_string(), "(x or (y and z))");
    }

    #[test]
    fn test_parse_all() {
        let ast = Ast::new("x or 1 of them and all of y* ").unwrap();
        assert_eq!(ast.to_string(), "(x or (1 of them and all of y*))");
    }

    #[test]
    fn test_parse_parentheses() {
        let ast = Ast::new("x or y and z").unwrap();
        assert_eq!(ast.to_string(), "(x or (y and z))");

        let ast = Ast::new("( x or y ) and z)").unwrap();
        assert_eq!(ast.to_string(), "((x or y) and z)");
    }

    #[test]
    fn test_not() {
        let ast = Ast::new("a and not b or not not c").unwrap();
        assert_eq!(ast.to_string(), "((a and not (b)) or not (not (c)))");
    }

    #[test]
    fn test_mismatching_parentheses() {
        let err = Ast::new("x and ( y or z ").unwrap_err();
        assert!(matches!(err, ParserError::MissingClosingParenthesis()));
    }

    #[test]
    fn test_get_identifiers() {
        let ast = Ast::new("x1 and x2 or x3 and 1 of x4* or all of x5* or x1").unwrap();
        let identifiers = ast.selections();
        assert_eq!(identifiers, HashSet::from(["x1", "x2", "x3"]));
    }

    #[test]
    fn test_selections_without_logical_operator() {
        let err =
            Ast::new(" write TargetLogonId from selection1 (if not selection2) ").unwrap_err();
        assert!(matches!(err, ParserError::InvalidOperator(ref a) if a == "TargetLogonId"));
    }
}
