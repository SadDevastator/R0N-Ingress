//! Topic name and filter handling for MQTT.
//!
//! This module implements topic name validation and topic filter matching
//! according to the MQTT specification.

use crate::modules::mqtt_handler::error::{MqttError, MqttResult};
use std::cmp::Ordering;

/// An MQTT topic name (used in PUBLISH).
///
/// Topic names must not contain wildcard characters (+ or #).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TopicName {
    name: String,
}

impl TopicName {
    /// Create a new topic name.
    ///
    /// # Errors
    ///
    /// Returns an error if the topic name is invalid.
    pub fn new(name: impl Into<String>) -> MqttResult<Self> {
        let name = name.into();
        Self::validate(&name)?;
        Ok(Self { name })
    }

    /// Validate a topic name.
    pub fn validate(name: &str) -> MqttResult<()> {
        if name.is_empty() {
            return Err(MqttError::InvalidTopicName(
                "Topic name cannot be empty".to_string(),
            ));
        }

        // Check for null character
        if name.contains('\0') {
            return Err(MqttError::InvalidTopicName(
                "Topic name cannot contain null character".to_string(),
            ));
        }

        // Topic names must not contain wildcards
        if name.contains('+') || name.contains('#') {
            return Err(MqttError::InvalidTopicName(
                "Topic name cannot contain wildcards".to_string(),
            ));
        }

        Ok(())
    }

    /// Get the topic name as a string.
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// Get the topic levels.
    pub fn levels(&self) -> impl Iterator<Item = &str> {
        self.name.split('/')
    }

    /// Check if this topic matches a filter.
    pub fn matches(&self, filter: &TopicFilter) -> bool {
        filter.matches(self)
    }
}

impl std::fmt::Display for TopicName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl AsRef<str> for TopicName {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

/// An MQTT topic filter (used in SUBSCRIBE/UNSUBSCRIBE).
///
/// Topic filters can contain wildcard characters:
/// - `+` matches a single level
/// - `#` matches any number of levels (must be last)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TopicFilter {
    filter: String,
    /// Precomputed levels for faster matching.
    levels: Vec<FilterLevel>,
}

/// A level in a topic filter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FilterLevel {
    /// Exact match.
    Exact(String),
    /// Single-level wildcard (+).
    SingleWildcard,
    /// Multi-level wildcard (#).
    MultiWildcard,
}

impl TopicFilter {
    /// Create a new topic filter.
    ///
    /// # Errors
    ///
    /// Returns an error if the topic filter is invalid.
    pub fn new(filter: impl Into<String>) -> MqttResult<Self> {
        let filter = filter.into();
        Self::validate(&filter)?;

        let levels = filter
            .split('/')
            .map(|level| match level {
                "+" => FilterLevel::SingleWildcard,
                "#" => FilterLevel::MultiWildcard,
                s => FilterLevel::Exact(s.to_string()),
            })
            .collect();

        Ok(Self { filter, levels })
    }

    /// Validate a topic filter.
    pub fn validate(filter: &str) -> MqttResult<()> {
        if filter.is_empty() {
            return Err(MqttError::InvalidTopicFilter(
                "Topic filter cannot be empty".to_string(),
            ));
        }

        // Check for null character
        if filter.contains('\0') {
            return Err(MqttError::InvalidTopicFilter(
                "Topic filter cannot contain null character".to_string(),
            ));
        }

        let levels: Vec<&str> = filter.split('/').collect();

        for (i, level) in levels.iter().enumerate() {
            // # must be the last level and stand alone
            if level.contains('#') {
                if *level != "#" {
                    return Err(MqttError::InvalidTopicFilter(
                        "# must occupy entire level".to_string(),
                    ));
                }
                if i != levels.len() - 1 {
                    return Err(MqttError::InvalidTopicFilter(
                        "# must be the last level".to_string(),
                    ));
                }
            }

            // + must stand alone in its level
            if level.contains('+') && *level != "+" {
                return Err(MqttError::InvalidTopicFilter(
                    "+ must occupy entire level".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Get the topic filter as a string.
    pub fn as_str(&self) -> &str {
        &self.filter
    }

    /// Check if this filter matches a topic name.
    pub fn matches(&self, topic: &TopicName) -> bool {
        let topic_levels: Vec<&str> = topic.name.split('/').collect();
        self.matches_levels(&topic_levels)
    }

    /// Check if this filter matches topic levels.
    pub fn matches_str(&self, topic: &str) -> bool {
        let topic_levels: Vec<&str> = topic.split('/').collect();
        self.matches_levels(&topic_levels)
    }

    /// Check if this filter matches topic levels.
    fn matches_levels(&self, topic_levels: &[&str]) -> bool {
        let mut filter_iter = self.levels.iter();
        let mut topic_iter = topic_levels.iter();

        loop {
            match (filter_iter.next(), topic_iter.next()) {
                // Both exhausted - match
                (None, None) => return true,

                // Multi-level wildcard matches everything remaining
                (Some(FilterLevel::MultiWildcard), _) => return true,

                // Filter exhausted but topic has more levels
                (None, Some(_)) => return false,

                // Topic exhausted but filter has more levels (and not #)
                (Some(_), None) => return false,

                // Single-level wildcard matches any single level
                (Some(FilterLevel::SingleWildcard), Some(_)) => continue,

                // Exact match required
                (Some(FilterLevel::Exact(f)), Some(t)) => {
                    if f != *t {
                        return false;
                    }
                },
            }
        }
    }

    /// Check if this filter contains wildcards.
    pub fn has_wildcards(&self) -> bool {
        self.levels
            .iter()
            .any(|l| matches!(l, FilterLevel::SingleWildcard | FilterLevel::MultiWildcard))
    }

    /// Get the specificity of this filter (for routing priority).
    /// Higher values mean more specific.
    pub fn specificity(&self) -> usize {
        let mut score = 0;
        for level in &self.levels {
            match level {
                FilterLevel::Exact(_) => score += 100,
                FilterLevel::SingleWildcard => score += 10,
                FilterLevel::MultiWildcard => score += 1,
            }
        }
        score
    }

    /// Check if this is a shared subscription filter.
    /// Shared subscriptions have the format $share/{ShareName}/{filter}
    pub fn is_shared(&self) -> bool {
        self.filter.starts_with("$share/")
    }

    /// Parse a shared subscription filter.
    /// Returns (share_name, actual_filter) if this is a shared subscription.
    pub fn parse_shared(&self) -> Option<(&str, &str)> {
        if !self.is_shared() {
            return None;
        }

        // $share/{ShareName}/{filter}
        let rest = self.filter.strip_prefix("$share/")?;
        let slash_pos = rest.find('/')?;
        let share_name = &rest[..slash_pos];
        let filter = &rest[slash_pos + 1..];

        if share_name.is_empty() || filter.is_empty() {
            return None;
        }

        Some((share_name, filter))
    }
}

impl std::fmt::Display for TopicFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.filter)
    }
}

impl AsRef<str> for TopicFilter {
    fn as_ref(&self) -> &str {
        &self.filter
    }
}

impl PartialOrd for TopicFilter {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TopicFilter {
    fn cmp(&self, other: &Self) -> Ordering {
        // More specific filters come first
        other.specificity().cmp(&self.specificity())
    }
}

/// A topic tree for efficient topic matching.
///
/// This is used to route messages to subscribers based on their topic filters.
#[derive(Debug)]
pub struct TopicTree<T> {
    root: TopicNode<T>,
}

impl<T> Default for TopicTree<T> {
    fn default() -> Self {
        Self {
            root: TopicNode {
                values: Vec::new(),
                children: std::collections::HashMap::new(),
                single_wildcard: None,
                multi_wildcard: Vec::new(),
            },
        }
    }
}

/// A node in the topic tree.
#[derive(Debug)]
struct TopicNode<T> {
    /// Values at this exact node.
    values: Vec<T>,
    /// Child nodes keyed by level name.
    children: std::collections::HashMap<String, TopicNode<T>>,
    /// Values for single-level wildcard at this level.
    single_wildcard: Option<Box<TopicNode<T>>>,
    /// Values for multi-level wildcard at this level.
    multi_wildcard: Vec<T>,
}

impl<T> Default for TopicNode<T> {
    fn default() -> Self {
        Self {
            values: Vec::new(),
            children: std::collections::HashMap::new(),
            single_wildcard: None,
            multi_wildcard: Vec::new(),
        }
    }
}

impl<T: Clone> TopicTree<T> {
    /// Create a new empty topic tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a value with a topic filter.
    pub fn insert(&mut self, filter: &TopicFilter, value: T) {
        let mut node = &mut self.root;

        for level in &filter.levels {
            match level {
                FilterLevel::Exact(name) => {
                    node = node.children.entry(name.clone()).or_default();
                },
                FilterLevel::SingleWildcard => {
                    if node.single_wildcard.is_none() {
                        node.single_wildcard = Some(Box::default());
                    }
                    node = node.single_wildcard.as_mut().unwrap();
                },
                FilterLevel::MultiWildcard => {
                    node.multi_wildcard.push(value);
                    return;
                },
            }
        }

        node.values.push(value);
    }

    /// Find all values that match a topic name.
    pub fn find_matches(&self, topic: &TopicName) -> Vec<T> {
        let levels: Vec<&str> = topic.name.split('/').collect();
        let mut results = Vec::new();
        self.collect_matches(&self.root, &levels, &mut results);
        results
    }

    /// Recursively collect matching values.
    fn collect_matches(&self, node: &TopicNode<T>, levels: &[&str], results: &mut Vec<T>) {
        // Multi-level wildcard matches everything
        results.extend(node.multi_wildcard.iter().cloned());

        if levels.is_empty() {
            // End of topic - collect values at this node
            results.extend(node.values.iter().cloned());
            return;
        }

        let (current, rest) = (levels[0], &levels[1..]);

        // Check exact match
        if let Some(child) = node.children.get(current) {
            self.collect_matches(child, rest, results);
        }

        // Check single-level wildcard
        if let Some(ref wildcard) = node.single_wildcard {
            self.collect_matches(wildcard, rest, results);
        }
    }

    /// Remove all values matching a predicate.
    pub fn remove_if<F>(&mut self, predicate: F)
    where
        F: Fn(&T) -> bool + Copy,
    {
        self.root.remove_if(predicate);
    }
}

impl<T> TopicNode<T> {
    /// Remove values matching a predicate.
    fn remove_if<F>(&mut self, predicate: F)
    where
        F: Fn(&T) -> bool + Copy,
    {
        self.values.retain(|v| !predicate(v));
        self.multi_wildcard.retain(|v| !predicate(v));

        for child in self.children.values_mut() {
            child.remove_if(predicate);
        }

        if let Some(ref mut wildcard) = self.single_wildcard {
            wildcard.remove_if(predicate);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topic_name_valid() {
        assert!(TopicName::new("test").is_ok());
        assert!(TopicName::new("test/topic").is_ok());
        assert!(TopicName::new("a/b/c/d/e").is_ok());
        assert!(TopicName::new("/leading/slash").is_ok());
        assert!(TopicName::new("trailing/slash/").is_ok());
    }

    #[test]
    fn test_topic_name_invalid() {
        assert!(TopicName::new("").is_err());
        assert!(TopicName::new("test/+/topic").is_err());
        assert!(TopicName::new("test/#").is_err());
        assert!(TopicName::new("test\0topic").is_err());
    }

    #[test]
    fn test_topic_filter_valid() {
        assert!(TopicFilter::new("test").is_ok());
        assert!(TopicFilter::new("test/topic").is_ok());
        assert!(TopicFilter::new("+").is_ok());
        assert!(TopicFilter::new("#").is_ok());
        assert!(TopicFilter::new("test/+/topic").is_ok());
        assert!(TopicFilter::new("test/#").is_ok());
        assert!(TopicFilter::new("+/+/+").is_ok());
    }

    #[test]
    fn test_topic_filter_invalid() {
        assert!(TopicFilter::new("").is_err());
        assert!(TopicFilter::new("test+").is_err());
        assert!(TopicFilter::new("test#").is_err());
        assert!(TopicFilter::new("test/#/more").is_err());
        assert!(TopicFilter::new("test\0topic").is_err());
    }

    #[test]
    fn test_exact_match() {
        let filter = TopicFilter::new("test/topic").unwrap();
        let topic = TopicName::new("test/topic").unwrap();
        assert!(filter.matches(&topic));

        let topic2 = TopicName::new("test/other").unwrap();
        assert!(!filter.matches(&topic2));
    }

    #[test]
    fn test_single_wildcard() {
        let filter = TopicFilter::new("sensor/+/temp").unwrap();

        assert!(filter.matches_str("sensor/living/temp"));
        assert!(filter.matches_str("sensor/kitchen/temp"));
        assert!(!filter.matches_str("sensor/temp"));
        assert!(!filter.matches_str("sensor/a/b/temp"));
    }

    #[test]
    fn test_multi_wildcard() {
        let filter = TopicFilter::new("sensor/#").unwrap();

        assert!(filter.matches_str("sensor"));
        assert!(filter.matches_str("sensor/temp"));
        assert!(filter.matches_str("sensor/living/temp"));
        assert!(filter.matches_str("sensor/a/b/c/d"));
        assert!(!filter.matches_str("device/temp"));
    }

    #[test]
    fn test_multi_wildcard_alone() {
        let filter = TopicFilter::new("#").unwrap();

        assert!(filter.matches_str("anything"));
        assert!(filter.matches_str("any/thing"));
        assert!(filter.matches_str("a/b/c/d/e/f"));
    }

    #[test]
    fn test_combined_wildcards() {
        let filter = TopicFilter::new("+/sensor/#").unwrap();

        assert!(filter.matches_str("home/sensor"));
        assert!(filter.matches_str("home/sensor/temp"));
        assert!(filter.matches_str("office/sensor/humidity/value"));
        assert!(!filter.matches_str("sensor/temp"));
    }

    #[test]
    fn test_filter_specificity() {
        let f1 = TopicFilter::new("a/b/c").unwrap();
        let f2 = TopicFilter::new("a/+/c").unwrap();
        let f3 = TopicFilter::new("a/#").unwrap();
        let f4 = TopicFilter::new("#").unwrap();

        assert!(f1.specificity() > f2.specificity());
        assert!(f2.specificity() > f3.specificity());
        assert!(f3.specificity() > f4.specificity());
    }

    #[test]
    fn test_filter_ordering() {
        let mut filters = vec![
            TopicFilter::new("#").unwrap(),
            TopicFilter::new("a/b/c").unwrap(),
            TopicFilter::new("a/+/c").unwrap(),
        ];

        filters.sort();

        assert_eq!(filters[0].as_str(), "a/b/c");
        assert_eq!(filters[1].as_str(), "a/+/c");
        assert_eq!(filters[2].as_str(), "#");
    }

    #[test]
    fn test_shared_subscription() {
        let filter = TopicFilter::new("$share/group1/sensor/#").unwrap();
        assert!(filter.is_shared());

        let (name, actual) = filter.parse_shared().unwrap();
        assert_eq!(name, "group1");
        assert_eq!(actual, "sensor/#");
    }

    #[test]
    fn test_not_shared_subscription() {
        let filter = TopicFilter::new("sensor/#").unwrap();
        assert!(!filter.is_shared());
        assert!(filter.parse_shared().is_none());
    }

    #[test]
    fn test_topic_tree_insert_and_find() {
        let mut tree: TopicTree<String> = TopicTree::new();

        let filter1 = TopicFilter::new("sensor/+/temp").unwrap();
        let filter2 = TopicFilter::new("sensor/#").unwrap();
        let filter3 = TopicFilter::new("sensor/living/temp").unwrap();

        tree.insert(&filter1, "handler1".to_string());
        tree.insert(&filter2, "handler2".to_string());
        tree.insert(&filter3, "handler3".to_string());

        let topic = TopicName::new("sensor/living/temp").unwrap();
        let matches = tree.find_matches(&topic);

        assert_eq!(matches.len(), 3);
        assert!(matches.contains(&"handler1".to_string()));
        assert!(matches.contains(&"handler2".to_string()));
        assert!(matches.contains(&"handler3".to_string()));
    }

    #[test]
    fn test_topic_tree_multi_wildcard() {
        let mut tree: TopicTree<i32> = TopicTree::new();

        let filter = TopicFilter::new("sensor/#").unwrap();
        tree.insert(&filter, 1);

        let topic1 = TopicName::new("sensor/temp").unwrap();
        let topic2 = TopicName::new("sensor/a/b/c").unwrap();
        let topic3 = TopicName::new("device/temp").unwrap();

        assert_eq!(tree.find_matches(&topic1).len(), 1);
        assert_eq!(tree.find_matches(&topic2).len(), 1);
        assert_eq!(tree.find_matches(&topic3).len(), 0);
    }

    #[test]
    fn test_topic_tree_remove() {
        let mut tree: TopicTree<i32> = TopicTree::new();

        let filter1 = TopicFilter::new("a/b").unwrap();
        let filter2 = TopicFilter::new("a/c").unwrap();

        tree.insert(&filter1, 1);
        tree.insert(&filter1, 2);
        tree.insert(&filter2, 3);

        let topic = TopicName::new("a/b").unwrap();
        assert_eq!(tree.find_matches(&topic).len(), 2);

        tree.remove_if(|v| *v == 1);
        assert_eq!(tree.find_matches(&topic).len(), 1);
    }

    #[test]
    fn test_has_wildcards() {
        assert!(!TopicFilter::new("a/b/c").unwrap().has_wildcards());
        assert!(TopicFilter::new("a/+/c").unwrap().has_wildcards());
        assert!(TopicFilter::new("a/#").unwrap().has_wildcards());
    }

    #[test]
    fn test_leading_slash() {
        let filter = TopicFilter::new("/a/b").unwrap();
        assert!(filter.matches_str("/a/b"));
        assert!(!filter.matches_str("a/b"));
    }

    #[test]
    fn test_trailing_slash() {
        let filter = TopicFilter::new("a/b/").unwrap();
        assert!(filter.matches_str("a/b/"));
        assert!(!filter.matches_str("a/b"));
    }
}
