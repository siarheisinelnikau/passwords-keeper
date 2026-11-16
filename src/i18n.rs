use crate::settings::Language;
use std::{collections::HashMap, sync::LazyLock};
static STRINGS: LazyLock<[HashMap<String, String>; 6]> = LazyLock::new(|| {
    [
        include_str!("../locales/en.json"),
        include_str!("../locales/ru.json"),
        include_str!("../locales/fr.json"),
        include_str!("../locales/de.json"),
        include_str!("../locales/es.json"),
        include_str!("../locales/it.json"),
    ]
    .map(|json| serde_json::from_str(json).expect("embedded translations"))
});
pub fn text(language: Language, key: &str) -> &str {
    STRINGS[language.index()]
        .get(key)
        .or_else(|| STRINGS[0].get(key))
        .map(String::as_str)
        .unwrap_or(key)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_language_is_complete() {
        for language in &*STRINGS {
            assert_eq!(language.len(), STRINGS[0].len());
            for key in STRINGS[0].keys() {
                assert!(
                    language.get(key).is_some_and(|s| !s.is_empty()),
                    "missing {key}"
                );
            }
        }
    }
}
