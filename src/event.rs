use crate::field::FieldValue;
use std::collections::HashMap;
use std::hash::Hash;

#[cfg(feature = "serde_json")]
#[derive(Debug, serde::Deserialize)]
struct EventProxy {
    #[serde(flatten)]
    value: serde_json::Value,
}

#[derive(Debug, PartialEq)]
pub enum EventValue {
    Value(FieldValue),
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
            | serde_json::Value::String(_) => Ok(Self::Value(FieldValue::try_from(value)?)),
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
    pub(crate) fn contains(&self, s: &str) -> bool {
        match self {
            Self::Value(v) => v.value_to_string().contains(s),
            Self::Sequence(seq) => seq.iter().any(|v| v.contains(s)),
            Self::Map(m) => m.values().any(|v| v.contains(s)),
        }
    }
}

impl<T> From<T> for EventValue
where
    T: Into<FieldValue>,
{
    fn from(value: T) -> Self {
        Self::Value(value.into())
    }
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
    /// Create a new empty event
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

    /// Iterate over the key-value pairs in the event
    pub fn iter(&self) -> impl Iterator<Item = (&String, &EventValue)> {
        self.inner.iter()
    }

    /// Get the value for a key in the event
    pub fn get(&self, key: &str) -> Option<&EventValue> {
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

    pub fn values(&self) -> impl Iterator<Item = &EventValue> {
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
    use serde_json::json;

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
}
