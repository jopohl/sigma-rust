use crate::basevalue::BaseValue;
use crate::field::ParserError;
use crate::wildcard::WildcardToken;
use cidr::IpCidr;
use regex::Regex;

#[derive(Debug)]
pub enum FieldValue {
    Base(BaseValue),
    WildcardPattern(Vec<WildcardToken>),
    Regex(Regex),
    Cidr(IpCidr),
}

impl<T> From<T> for FieldValue
where
    T: Into<BaseValue>,
{
    fn from(value: T) -> Self {
        Self::Base(value.into())
    }
}

impl TryFrom<serde_norway::Value> for FieldValue {
    type Error = ParserError;

    fn try_from(value: serde_norway::Value) -> Result<Self, Self::Error> {
        Ok(Self::Base(BaseValue::try_from(value)?))
    }
}

impl FieldValue {
    pub(super) fn as_string(&self) -> Result<String, ParserError> {
        if let Self::Base(BaseValue::String(s)) = self {
            Ok(s.clone())
        } else {
            Err(ParserError::NotAString(format!("{:?}", self)))
        }
    }
}
