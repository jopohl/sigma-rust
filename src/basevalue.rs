use crate::error::ParserError;
use std::cmp::Ordering;

#[derive(Debug, Clone)]
pub enum BaseValue {
    String(String),
    Int(i64),
    Unsigned(u64),
    Float(f64),
    Boolean(bool),
    Null,
}

impl From<i32> for BaseValue {
    fn from(i: i32) -> Self {
        Self::from(i as i64)
    }
}

impl From<Option<i32>> for BaseValue {
    fn from(option: Option<i32>) -> Self {
        match option {
            Some(i) => Self::from(i),
            None => Self::Null,
        }
    }
}

impl From<i64> for BaseValue {
    fn from(i: i64) -> Self {
        Self::Int(i)
    }
}

impl From<u32> for BaseValue {
    fn from(u: u32) -> Self {
        Self::from(u as u64)
    }
}

impl From<u64> for BaseValue {
    fn from(u: u64) -> Self {
        Self::Unsigned(u)
    }
}

impl From<f32> for BaseValue {
    fn from(f: f32) -> Self {
        Self::from(f as f64)
    }
}

impl From<f64> for BaseValue {
    fn from(f: f64) -> Self {
        Self::Float(f)
    }
}

impl From<bool> for BaseValue {
    fn from(b: bool) -> Self {
        Self::Boolean(b)
    }
}

impl From<String> for BaseValue {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for BaseValue {
    fn from(s: &str) -> Self {
        Self::from(s.to_string())
    }
}

impl PartialEq for BaseValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::String(a), Self::String(b)) => a.eq(b),
            (Self::Int(a), Self::Int(b)) => a.eq(b),
            (Self::Unsigned(a), Self::Unsigned(b)) => a.eq(b),
            (Self::Float(a), Self::Float(b)) => a.eq(b),
            (Self::Boolean(a), Self::Boolean(b)) => a.eq(b),
            (Self::Null, Self::Null) => true,
            _ => false,
        }
    }
}

impl PartialOrd for BaseValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::String(a), Self::String(b)) => a.partial_cmp(b),
            (Self::Int(a), Self::Int(b)) => a.partial_cmp(b),
            (Self::Unsigned(a), Self::Unsigned(b)) => a.partial_cmp(b),
            (Self::Float(a), Self::Float(b)) => a.partial_cmp(b),
            (Self::Boolean(a), Self::Boolean(b)) => a.partial_cmp(b),
            (Self::Null, Self::Null) => Some(Ordering::Equal),
            _ => None,
        }
    }
}

impl BaseValue {
    pub(crate) fn value_to_string(&self) -> String {
        match self {
            Self::String(s) => s.to_string(),
            Self::Int(i) => i.to_string(),
            Self::Float(f) => f.to_string(),
            Self::Unsigned(u) => u.to_string(),
            Self::Boolean(b) => b.to_string(),
            Self::Null => "".to_string(),
        }
    }
}

macro_rules! number {
    ($n:expr) => {
        if let Some(i) = $n.as_i64() {
            Ok(Self::Int(i))
        } else if let Some(u) = $n.as_u64() {
            Ok(Self::Unsigned(u))
        } else {
            Ok(Self::Float(
                $n.as_f64().expect("Number is neither Int nor Unsigned"),
            ))
        }
    };
}

#[cfg(feature = "serde_json")]
impl TryFrom<serde_json::Value> for BaseValue {
    type Error = crate::error::JSONError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        match value {
            serde_json::Value::String(s) => Ok(Self::String(s)),
            serde_json::Value::Number(n) => number!(n),
            serde_json::Value::Bool(b) => Ok(Self::Boolean(b)),
            serde_json::Value::Null => Ok(Self::Null),
            _ => Err(Self::Error::InvalidFieldValue(format!("{:?}", value))),
        }
    }
}

impl TryFrom<serde_yml::Value> for BaseValue {
    type Error = ParserError;

    fn try_from(value: serde_yml::Value) -> Result<Self, Self::Error> {
        match value {
            serde_yml::Value::Bool(b) => Ok(Self::Boolean(b)),
            serde_yml::Value::Number(n) => number!(n),
            serde_yml::Value::String(s) => Ok(Self::String(s)),
            serde_yml::Value::Null => Ok(Self::Null),
            _ => Err(ParserError::InvalidYAML(format!("{:?}", value))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::neg_cmp_op_on_partial_ord)]
    #[test]
    fn test_field_value_type() {
        assert_eq!(BaseValue::from("1"), BaseValue::String("1".to_string()));
        assert_eq!(BaseValue::from("2"), BaseValue::String("2".to_string()));
        assert_eq!(BaseValue::from(Some(42)), BaseValue::Int(42));
        assert_eq!(BaseValue::from(2u32), BaseValue::Unsigned(2));
        assert_eq!(BaseValue::from(3f32), BaseValue::Float(3.0));
        assert_ne!(BaseValue::from("1"), BaseValue::from("3"));
        assert_ne!(BaseValue::from("2"), BaseValue::Int(2_i64));
        assert_ne!(BaseValue::Int(3), BaseValue::Float(3.0));

        assert!(BaseValue::Int(10) < BaseValue::Int(20));
        assert!(!(BaseValue::Int(20) < BaseValue::from("30")));
        assert!(!(BaseValue::Int(20) < BaseValue::Float(30.0)));
        assert!(!(BaseValue::Int(34) < BaseValue::Float(30.0)));
        assert!(BaseValue::Boolean(false) < BaseValue::Boolean(true));
        assert!(BaseValue::Int(10) >= BaseValue::Int(10));
        assert!(BaseValue::Int(10) > BaseValue::Int(4));
        assert!(BaseValue::Int(10) >= BaseValue::Int(4));
        assert!(
            BaseValue::from(18446744073709551615_u64) > BaseValue::from(18446744073709551614_u64)
        );
        assert_eq!(
            BaseValue::from(18446744073709551615_u64),
            BaseValue::from(18446744073709551615_u64)
        );

        let yaml = r#"
        EventID: 18446744073709551615
"#;
        let v: serde_yml::Value = serde_yml::from_str(yaml).unwrap();
        let base_value = BaseValue::try_from(v["EventID"].clone()).unwrap();
        assert_eq!(base_value, BaseValue::Unsigned(18446744073709551615));
    }
}
