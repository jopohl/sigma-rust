use crate::error::ParserError;
use crate::field::ValueTransformer::{Base64, Base64offset};
use std::str::FromStr;
use strum::{Display, EnumString};

#[derive(Debug, PartialEq, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum MatchModifier {
    Contains,
    StartsWith,
    EndsWith,
    Gt,
    Gte,
    Lt,
    Lte,
    Re,
    Cidr,
}

#[derive(Debug, PartialEq, Display)]
pub enum Utf16Modifier {
    Utf16le,
    Utf16be,
}

#[derive(Debug, PartialEq, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum ValueTransformer {
    Base64(Option<Utf16Modifier>),
    Base64offset(Option<Utf16Modifier>),
    Windash,
}

#[derive(Debug, Default)]
pub struct Modifier {
    pub(crate) match_all: bool,
    pub(crate) fieldref: bool,
    pub(crate) match_modifier: Option<MatchModifier>,
    pub(crate) value_transformer: Option<ValueTransformer>,
}

impl FromStr for Utf16Modifier {
    type Err = ParserError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "utf16le" => Ok(Utf16Modifier::Utf16le),
            "utf16be" => Ok(Utf16Modifier::Utf16be),
            "utf16" | "wide" => Err(ParserError::AmbiguousUtf16Modifier(s.to_string())),
            _ => Err(ParserError::UnknownModifier(s.to_string())),
        }
    }
}

impl FromStr for Modifier {
    type Err = ParserError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let mut utf16_modifier: Option<Utf16Modifier> = None;
        let mut result = Self::default();

        for s in string.split("|").skip(1).map(|s| s.to_lowercase()) {
            if s == "all" {
                result.match_all = true;
                continue;
            }
            if s == "fieldref" {
                result.fieldref = true;
                continue;
            }

            if let Ok(match_modifier) = MatchModifier::from_str(&s) {
                if let Some(m) = result.match_modifier {
                    return Err(Self::Err::ConflictingModifiers(
                        match_modifier.to_string(),
                        m.to_string(),
                    ));
                }
                result.match_modifier = Some(match_modifier);
                continue;
            }

            match Utf16Modifier::from_str(&s) {
                Ok(m) => match utf16_modifier {
                    Some(m2) => {
                        return Err(Self::Err::ConflictingModifiers(
                            m.to_string(),
                            m2.to_string(),
                        ))
                    }
                    None => {
                        utf16_modifier = Some(m);
                        continue;
                    }
                },
                Err(Self::Err::UnknownModifier(_)) => {}
                Err(err) => return Err(err),
            }

            if let Ok(value_transformer) = ValueTransformer::from_str(&s) {
                if let Some(v) = result.value_transformer {
                    return Err(Self::Err::ConflictingModifiers(
                        value_transformer.to_string(),
                        v.to_string(),
                    ));
                }
                result.value_transformer = Some(value_transformer);
                continue;
            }

            return Err(ParserError::UnknownModifier(s));
        }

        if utf16_modifier.is_some() {
            match result.value_transformer {
                Some(value_transformer) => match value_transformer {
                    Base64(_) => result.value_transformer = Some(Base64(utf16_modifier)),
                    Base64offset(_) => {
                        result.value_transformer = Some(Base64offset(utf16_modifier))
                    }
                    _ => return Err(Self::Err::Utf16WithoutBase64),
                },
                None => {
                    return Err(Self::Err::Utf16WithoutBase64);
                }
            }
        }

        if let (Some(MatchModifier::Re) | Some(MatchModifier::Cidr), Some(_)) =
            (&result.match_modifier, &result.value_transformer)
        {
            return Err(Self::Err::StandaloneViolation(
                result.match_modifier.unwrap().to_string(),
            ));
        }

        Ok(result)
    }
}
