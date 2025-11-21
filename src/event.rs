use crate::basevalue::BaseValue;
use crate::field::{FieldValue, MatchModifier, Modifier};
use crate::wildcard::{match_tokenized, tokenize};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::str::FromStr;

#[cfg(feature = "serde_json")]
#[derive(Debug, serde::Deserialize)]
struct EventProxy {
    #[serde(flatten)]
    value: serde_json::Value,
}

#[derive(Debug, PartialEq)]
pub enum EventValue {
    Value(BaseValue),
    Sequence(Vec<EventValue>),
    Map(HashMap<String, EventValue>),
}

#[cfg(feature = "serde_json")]
impl TryFrom<serde_json::Value> for EventValue {
    type Error = crate::error::JSONError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        match value {
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => Ok(Self::Value(BaseValue::try_from(value)?)),
            serde_json::Value::Array(a) => {
                let mut result = Vec::with_capacity(a.len());
                for item in a {
                    result.push(Self::try_from(item)?);
                }
                Ok(Self::Sequence(result))
            }
            serde_json::Value::Object(data) => {
                let mut result = HashMap::with_capacity(data.len());
                for (key, value) in data {
                    result.insert(key, Self::try_from(value)?);
                }
                Ok(Self::Map(result))
            }
        }
    }
}

impl EventValue {
    /// Returns the string representation of an EventValue
    pub fn value_to_string(&self) -> String {
        match self {
            Self::Value(v) => v.value_to_string(),
            Self::Sequence(v) => {
                let mut result = "[".to_string();
                result.push_str(
                    v.iter()
                        .map(|v| v.value_to_string())
                        .collect::<Vec<String>>()
                        .join(", ")
                        .as_str(),
                );
                result.push(']');
                result
            }
            Self::Map(m) => {
                let mut result = "{".to_string();
                result.push_str(
                    m.iter()
                        .map(|(k, v)| format!("{}: {}", k, v.value_to_string()))
                        .collect::<Vec<String>>()
                        .join(", ")
                        .as_str(),
                );
                result.push('}');
                result
            }
        }
    }

    pub(crate) fn contains_keyword(&self, s: &str) -> bool {
        match self {
            Self::Value(v) => {
                // Case-insensitive matching for keywords
                //https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#lists
                let tokens = tokenize(s, true);
                match_tokenized(&tokens, v.value_to_string().as_str(), true)
            }
            Self::Sequence(seq) => seq.iter().any(|v| v.contains_keyword(s)),
            Self::Map(m) => m.values().any(|v| v.contains_keyword(s)),
        }
    }

    pub(crate) fn matches(&self, field_value: &FieldValue, modifier: &Modifier) -> bool {
        match (&self, field_value) {
            (Self::Value(target), FieldValue::Base(value)) => match modifier.match_modifier {
                // Entered in fieldref case
                Some(MatchModifier::Contains) => match (target, value) {
                    (BaseValue::String(target), BaseValue::String(value)) => {
                        if modifier.cased {
                            target.contains(value)
                        } else {
                            target.to_lowercase().contains(&value.to_lowercase())
                        }
                    }
                    _ => false,
                },
                Some(MatchModifier::StartsWith) => match (target, value) {
                    (BaseValue::String(target), BaseValue::String(value)) => {
                        if modifier.cased {
                            target.starts_with(value)
                        } else {
                            target.to_lowercase().starts_with(&value.to_lowercase())
                        }
                    }
                    _ => false,
                },
                Some(MatchModifier::EndsWith) => match (target, value) {
                    (BaseValue::String(target), BaseValue::String(value)) => {
                        if modifier.cased {
                            target.ends_with(value)
                        } else {
                            target.to_lowercase().ends_with(&value.to_lowercase())
                        }
                    }
                    _ => false,
                },

                Some(MatchModifier::Gt) => target > value,
                Some(MatchModifier::Gte) => target >= value,
                Some(MatchModifier::Lt) => target < value,
                Some(MatchModifier::Lte) => target <= value,

                // Regex and CIDR would already be compiled into FieldValue::Regex and FieldValue::Cidr
                Some(MatchModifier::Re) | Some(MatchModifier::Cidr) => false,

                // implicit equals
                None => value == target,
            },
            (Self::Value(v), FieldValue::WildcardPattern(w)) => {
                if let BaseValue::String(s) = v {
                    match_tokenized(w, s, !modifier.cased)
                } else {
                    match_tokenized(w, v.value_to_string().as_str(), !modifier.cased)
                }
            }

            (Self::Value(v), FieldValue::Regex(r)) => r.is_match(&v.value_to_string()),
            (Self::Value(v), FieldValue::Cidr(c)) => {
                if let BaseValue::String(s) = v {
                    match IpAddr::from_str(s) {
                        Ok(ip) => c.contains(&ip),
                        Err(_) => false,
                    }
                } else {
                    false
                }
            }

            // We currently do not support matching against lists and hashmaps, see
            // https://github.com/jopohl/sigma-rust/issues/9
            (Self::Sequence(_), _) => false,
            (Self::Map(_), _) => false,
        }
    }
}

impl<T> From<T> for EventValue
where
    T: Into<BaseValue>,
{
    fn from(value: T) -> Self {
        Self::Value(value.into())
    }
}

/// `QueryableEvent` is used to run the sigma rules on top of any
/// struct that can be queryable, instead of creating an `Event`
/// which allocates a HashMap, this trait allows users to wrap their
/// own data structures and avoid an allocation. Another possibility is
/// to query files or databases if needed.
pub trait QueryableEvent {
    /// Iterate over the key-value pairs in the event
    fn iter(&self) -> impl Iterator<Item = (&String, &EventValue)>;

    /// Get the value for a key in the event
    fn get(&self, key: &str) -> Option<&EventValue>;

    fn values(&self) -> impl Iterator<Item = &EventValue>;
}

/// The `Event` struct represents a log event.
///
/// It is a collection of key-value pairs
/// where the key is a string and the value is a string, number, or boolean
/// The value may also be `None` to represent a null value.
#[derive(Debug, Default)]
#[cfg_attr(feature = "serde_json", derive(serde::Deserialize))]
#[cfg_attr(feature = "serde_json", serde(try_from = "EventProxy"))]
pub struct Event {
    inner: HashMap<String, EventValue>,
}

#[cfg(feature = "serde_json")]
impl TryFrom<EventProxy> for Event {
    type Error = crate::error::JSONError;

    fn try_from(other: EventProxy) -> Result<Self, Self::Error> {
        Self::try_from(other.value)
    }
}

impl<T, S, const N: usize> From<[(S, T); N]> for Event
where
    S: Into<String> + Hash + Eq,
    T: Into<EventValue>,
{
    fn from(values: [(S, T); N]) -> Self {
        let mut data = HashMap::with_capacity(N);
        for (k, v) in values {
            data.insert(k.into(), v.into());
        }
        Self { inner: data }
    }
}

impl Event {
    pub fn new() -> Self {
        Self::default()
    }
    /// Insert a key-value pair into the event.
    /// If the key already exists, the value will be replaced.
    ///
    /// # Example
    /// ```rust
    /// use sigma_rust::Event;
    /// let mut event = Event::new();
    /// event.insert("name", "John Doe");
    /// event.insert("age", 43);
    /// event.insert("is_admin", true);
    /// event.insert("null_value", None);
    /// ```
    pub fn insert<T, S>(&mut self, key: S, value: T)
    where
        S: Into<String> + Hash + Eq,
        T: Into<EventValue>,
    {
        self.inner.insert(key.into(), value.into());
    }
}

impl QueryableEvent for Event {
    /// Iterate over the key-value pairs in the event
    fn iter(&self) -> impl Iterator<Item = (&String, &EventValue)> {
        self.inner.iter()
    }

    /// Get the value for a key in the event
    fn get(&self, key: &str) -> Option<&EventValue> {
        if let Some(ev) = self.inner.get(key) {
            return Some(ev);
        }

        let mut nested_key = key;
        let mut current = &self.inner;
        while let Some((head, tail)) = nested_key.split_once('.') {
            if let Some(EventValue::Map(map)) = current.get(head) {
                if let Some(value) = map.get(tail) {
                    return Some(value);
                }
                current = map;
                nested_key = tail;
            } else {
                return None;
            }
        }
        None
    }

    fn values(&self) -> impl Iterator<Item = &EventValue> {
        self.inner.values()
    }
}

#[cfg(feature = "serde_json")]
impl TryFrom<serde_json::Value> for Event {
    type Error = crate::error::JSONError;

    fn try_from(data: serde_json::Value) -> Result<Self, Self::Error> {
        let mut result = Self::default();
        match data {
            serde_json::Value::Object(data) => {
                for (key, value) in data {
                    result.insert(key, EventValue::try_from(value)?);
                }
            }
            _ => return Err(Self::Error::InvalidEvent()),
        }
        Ok(result)
    }
}

#[cfg(feature = "serde_json")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::wildcard::tokenize;
    use serde_json::json;

    #[test]
    fn test_event_value_to_string() {
        let event_value = EventValue::Value(BaseValue::String("test".to_string()));
        assert_eq!(event_value.value_to_string(), "test");

        let event_value = EventValue::Sequence(vec![
            EventValue::Value(BaseValue::String("test".to_string())),
            EventValue::Value(BaseValue::Int(42)),
        ]);

        assert_eq!(event_value.value_to_string(), "[test, 42]");

        let event_value = EventValue::Map({
            let mut map = HashMap::new();
            map.insert(
                "key".to_string(),
                EventValue::Value(BaseValue::String("test".to_string())),
            );
            map.insert("number".to_string(), EventValue::Value(BaseValue::Int(42)));
            map
        });

        assert!(
            event_value.value_to_string() == "{key: test, number: 42}"
                || event_value.value_to_string() == "{number: 42, key: test}"
        );
    }

    #[test]
    fn test_matches() {
        let mut modifier = Modifier::default();

        assert!(EventValue::from("zsh").matches(&FieldValue::from("zsh"), &modifier));
        assert!(!EventValue::from("zsh").matches(&FieldValue::from("bash"), &modifier));

        modifier.match_modifier = Some(MatchModifier::StartsWith);

        assert!(EventValue::from("zsh").matches(&FieldValue::from("z"), &modifier));
        assert!(!EventValue::from("zsh").matches(&FieldValue::from("sd"), &modifier));

        modifier.match_modifier = Some(MatchModifier::EndsWith);
        assert!(EventValue::from("zsh").matches(&FieldValue::from("sh"), &modifier));
        assert!(!EventValue::from("zsh").matches(&FieldValue::from("sd"), &modifier));

        modifier.match_modifier = Some(MatchModifier::Contains);
        assert!(EventValue::from("zsh").matches(&FieldValue::from("s"), &modifier));
        assert!(!EventValue::from("zsh").matches(&FieldValue::from("d"), &modifier));
    }

    #[test]
    fn test_load_from_json() {
        let event: Event = json!({
            "name": "John Doe",
            "age": 43,
            "address": {
                "city": "New York",
                "state": "NY"
            }
        })
        .try_into()
        .unwrap();

        assert_eq!(event.inner["name"], EventValue::from("John Doe"));
        assert_eq!(event.inner["age"], EventValue::from(43));
        assert_eq!(
            event.inner["address"],
            EventValue::Map({
                let mut map = HashMap::new();
                map.insert("city".to_string(), EventValue::from("New York"));
                map.insert("state".to_string(), EventValue::from("NY"));
                map
            })
        );
    }

    #[test]
    fn test_wildcard_matches() {
        let modifier = Modifier::default();
        let wildcard = FieldValue::WildcardPattern(tokenize("4?", false));

        assert!(EventValue::from("42").matches(&wildcard, &modifier));
        assert!(EventValue::from(43).matches(&wildcard, &modifier));
        assert!(EventValue::from(43u32).matches(&wildcard, &modifier));
        assert!(!EventValue::from(53).matches(&wildcard, &modifier));
        assert!(!EventValue::from(433).matches(&wildcard, &modifier));
        assert!(!EventValue::from(None).matches(&wildcard, &modifier));

        let wildcard = FieldValue::WildcardPattern(tokenize("f*", false));
        assert!(EventValue::from(false).matches(&wildcard, &modifier));
        assert!(!EventValue::from(true).matches(&wildcard, &modifier));
        assert!(!EventValue::from(None).matches(&wildcard, &modifier));
    }

    #[test]
    fn test_iter() {
        let event = Event::from([("name", 2)]);
        let mut event_iter = event.iter();
        assert_eq!(
            event_iter.next(),
            Some((&"name".to_string(), &EventValue::from(2)))
        );
        assert_eq!(event_iter.next(), None);
    }
}
