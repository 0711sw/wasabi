use serde::Deserialize;
use serde::de::{Error, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone)]
pub enum I18nString {
    Empty,
    Simple(String),
    Translations {
        standard: Option<String>,
        translations: HashMap<String, String>,
    },
}

pub const DEFAULT_LANGUAGE: &str = "xx";

impl I18nString {
    pub fn standard(&self) -> Option<&str> {
        match self {
            I18nString::Empty => None,
            I18nString::Simple(standard) => Some(standard),
            I18nString::Translations { standard, .. } => standard.as_ref().map(String::as_str),
        }
    }

    pub fn get(&self, lang: &str) -> Option<&str> {
        match self {
            I18nString::Empty => None,
            I18nString::Simple(standard) => Some(standard),
            I18nString::Translations {
                standard,
                translations,
            } => translations
                .get(lang)
                .or(standard.as_ref())
                .map(String::as_str),
        }
    }
}

impl Serialize for I18nString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self {
            I18nString::Empty => serializer.serialize_none(),
            I18nString::Simple(value) => serializer.serialize_str(value),
            I18nString::Translations {
                standard,
                translations,
            } => {
                let effective_entries = if standard.is_some() {
                    translations.len() + 1
                } else {
                    translations.len()
                };
                let mut map = serializer.serialize_map(Some(effective_entries))?;

                if let Some(standard) = standard {
                    map.serialize_entry("xx", standard)?;
                }

                for (name, value) in translations.iter() {
                    map.serialize_entry(name.as_str(), value)?;
                }

                map.end()
            }
        }
    }
}

struct I18nStringVisitor;

impl<'de> Visitor<'de> for I18nStringVisitor {
    type Value = I18nString;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("either a string or a map of translations")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(if value.is_empty() {
            I18nString::Empty
        } else {
            I18nString::Simple(value.to_owned())
        })
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(I18nString::Empty)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(I18nString::Empty)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut standard: Option<String> = None;
        let mut translations = HashMap::new();

        while let Some((key, value)) = map.next_entry::<String, String>()? {
            if key == DEFAULT_LANGUAGE {
                standard = Some(value);
            } else if value.len() > 0 {
                translations.insert(key, value);
            }
        }

        if translations.is_empty() {
            if let Some(standard) = standard {
                if standard.is_empty() {
                    Ok(I18nString::Empty)
                } else {
                    Ok(I18nString::Simple(standard))
                }
            } else {
                Ok(I18nString::Empty)
            }
        } else {
            Ok(I18nString::Translations {
                standard,
                translations,
            })
        }
    }
}

impl<'de> Deserialize<'de> for I18nString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(I18nStringVisitor)
    }
}

impl Default for I18nString {
    fn default() -> Self {
        I18nString::Empty
    }
}

#[cfg(test)]
mod tests {
    use crate::tools::i18n_string::I18nString;
    use std::collections::HashMap;

    fn create_fallback_string() -> I18nString {
        I18nString::Simple("test".to_owned())
    }

    fn create_translated_string() -> I18nString {
        I18nString::Translations {
            standard: None,
            translations: HashMap::from([("de".to_owned(), "test".to_owned())]),
        }
    }

    fn create_translated_string_with_fallback() -> I18nString {
        I18nString::Translations {
            standard: Some("foo".to_owned()),
            translations: HashMap::from([("de".to_owned(), "test".to_owned())]),
        }
    }

    #[test]
    fn test_serialize() {
        let json = serde_json::to_string(&I18nString::Empty).unwrap();
        assert_eq!(json, "null");

        let json = serde_json::to_string(&create_fallback_string()).unwrap();
        assert_eq!(json, "\"test\"");

        let json = serde_json::to_string(&create_translated_string()).unwrap();
        assert_eq!(json, "{\"de\":\"test\"}");

        let json = serde_json::to_string(&create_translated_string_with_fallback()).unwrap();
        assert_eq!(json, "{\"xx\":\"foo\",\"de\":\"test\"}");
    }

    #[test]
    fn test_deserialize() {
        let str: I18nString = serde_json::from_str("null").unwrap();
        assert!(matches!(str, I18nString::Empty));

        let str: I18nString = serde_json::from_str("\"test\"").unwrap();
        assert_eq!(str.standard().unwrap(), "test");
        assert_eq!(str.get("de").unwrap(), "test");

        let str: I18nString = serde_json::from_str("{\"de\": \"test_de\"}").unwrap();
        assert_eq!(str.standard(), None);
        assert_eq!(str.get("de").unwrap(), "test_de");
        assert_eq!(str.get("en"), None);

        let str: I18nString =
            serde_json::from_str("{\"de\": \"test_de\",\"xx\": \"test\"}").unwrap();
        assert_eq!(str.standard().unwrap(), "test");
        assert_eq!(str.get("de").unwrap(), "test_de");
        assert_eq!(str.get("en").unwrap(), "test");
    }
}
