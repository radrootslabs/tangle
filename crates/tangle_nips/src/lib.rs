#![forbid(unsafe_code)]

use tangle_protocol::Event;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTag {
    name: String,
    values: Vec<String>,
}

impl ParsedTag {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn values(&self) -> &[String] {
        &self.values
    }

    pub fn first_value(&self) -> Option<&str> {
        self.values.first().map(String::as_str)
    }
}

pub fn matching_tags(event: &Event, name: &str) -> Vec<ParsedTag> {
    event
        .unsigned()
        .tags()
        .iter()
        .filter(|tag| tag.name().as_str() == name)
        .map(|tag| ParsedTag {
            name: tag.name().to_string(),
            values: tag.values().iter().skip(1).cloned().collect(),
        })
        .collect()
}

pub fn tag_count(event: &Event, name: &str) -> usize {
    matching_tags(event, name).len()
}

pub fn optional_tag_value(event: &Event, name: &str) -> Result<Option<String>, String> {
    let tags = matching_tags(event, name);
    match tags.as_slice() {
        [] => Ok(None),
        [tag] => tag
            .first_value()
            .map(|value| Some(value.to_owned()))
            .ok_or_else(|| format!("tag `{name}` must include a value")),
        _ => Err(format!("tag `{name}` must not be repeated")),
    }
}

pub fn required_tag_value(event: &Event, name: &str) -> Result<String, String> {
    optional_tag_value(event, name)?.ok_or_else(|| format!("tag `{name}` is required"))
}

pub fn optional_tag_values(event: &Event, name: &str) -> Result<Option<Vec<String>>, String> {
    let tags = matching_tags(event, name);
    match tags.as_slice() {
        [] => Ok(None),
        [tag] => Ok(Some(tag.values().to_vec())),
        _ => Err(format!("tag `{name}` must not be repeated")),
    }
}

pub fn required_tag_values(event: &Event, name: &str) -> Result<Vec<String>, String> {
    optional_tag_values(event, name)?.ok_or_else(|| format!("tag `{name}` is required"))
}

pub fn parse_u64_field(field: &str, value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("field `{field}` must be an unsigned integer"))
}

pub fn parse_required_u64_tag(event: &Event, name: &str) -> Result<u64, String> {
    parse_u64_field(name, &required_tag_value(event, name)?)
}

pub fn repeated_or_missing_policy_boundary(
    event: &Event,
    name: &str,
) -> Result<Option<String>, String> {
    optional_tag_value(event, name)
}

#[cfg(test)]
mod tests {
    use super::{
        matching_tags, optional_tag_value, optional_tag_values, parse_required_u64_tag,
        parse_u64_field, repeated_or_missing_policy_boundary, required_tag_value,
        required_tag_values, tag_count,
    };
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
    };

    #[test]
    fn shared_parser_utilities_extract_matching_tags() {
        let event = event_with_tags(vec![
            Tag::from_parts("d", &["listing-a"]).expect("d"),
            Tag::from_parts("title", &["Carrots"]).expect("title"),
            Tag::from_parts("price", &["12.50", "USD"]).expect("price"),
        ]);
        let price = matching_tags(&event, "price");

        assert_eq!(tag_count(&event, "d"), 1);
        assert_eq!(tag_count(&event, "missing"), 0);
        assert_eq!(price[0].name(), "price");
        assert_eq!(price[0].first_value(), Some("12.50"));
        assert_eq!(price[0].values(), &["12.50".to_owned(), "USD".to_owned()]);
        assert_eq!(
            optional_tag_value(&event, "d"),
            Ok(Some("listing-a".to_owned()))
        );
        assert_eq!(optional_tag_value(&event, "missing"), Ok(None));
        assert_eq!(
            required_tag_value(&event, "title"),
            Ok("Carrots".to_owned())
        );
        assert_eq!(
            optional_tag_values(&event, "price"),
            Ok(Some(vec!["12.50".to_owned(), "USD".to_owned()]))
        );
        assert_eq!(
            required_tag_values(&event, "price"),
            Ok(vec!["12.50".to_owned(), "USD".to_owned()])
        );
    }

    #[test]
    fn shared_parser_utilities_reject_missing_repeated_and_malformed_values() {
        let repeated = event_with_tags(vec![
            Tag::from_parts("d", &["one"]).expect("d"),
            Tag::from_parts("d", &["two"]).expect("d"),
        ]);
        let missing_value = event_with_tags(vec![Tag::from_parts("d", &[]).expect("d")]);
        let missing = event_with_tags(Vec::new());

        assert_eq!(
            optional_tag_value(&repeated, "d").expect_err("repeated"),
            "tag `d` must not be repeated"
        );
        assert_eq!(
            optional_tag_values(&repeated, "d").expect_err("repeated values"),
            "tag `d` must not be repeated"
        );
        assert_eq!(
            optional_tag_value(&missing_value, "d").expect_err("value"),
            "tag `d` must include a value"
        );
        assert_eq!(
            required_tag_value(&missing, "d").expect_err("missing"),
            "tag `d` is required"
        );
        assert_eq!(
            required_tag_values(&missing, "d").expect_err("missing values"),
            "tag `d` is required"
        );
        assert_eq!(
            parse_u64_field("published_at", "now").expect_err("number"),
            "field `published_at` must be an unsigned integer"
        );
    }

    #[test]
    fn shared_parser_utilities_parse_numeric_tags_and_policy_boundaries() {
        let event = event_with_tags(vec![Tag::from_parts("published_at", &["42"]).expect("tag")]);
        let missing = event_with_tags(Vec::new());

        assert_eq!(parse_u64_field("published_at", "42"), Ok(42));
        assert_eq!(parse_required_u64_tag(&event, "published_at"), Ok(42));
        assert_eq!(repeated_or_missing_policy_boundary(&missing, "d"), Ok(None));
    }

    fn event_with_tags(tags: Vec<Tag>) -> Event {
        Event::new(
            EventId::new(&"a".repeat(EventId::HEX_LENGTH)).expect("id"),
            UnsignedEvent::new(
                PublicKeyHex::new(&"1".repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey"),
                UnixTimestamp::new(1_714_124_433),
                Kind::new(30_402).expect("kind"),
                tags,
                "",
            ),
            SignatureHex::new(&"b".repeat(SignatureHex::HEX_LENGTH)).expect("sig"),
        )
    }
}
