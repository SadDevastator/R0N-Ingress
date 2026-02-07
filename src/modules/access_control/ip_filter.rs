//! IP filtering for access control.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::config::{IpFilterConfig, IpRule, RuleAction};
use super::error::{AccessControlError, AccessControlResult};

/// IP filter for allow/deny list matching.
#[derive(Debug)]
pub struct IpFilter {
    /// Configuration.
    config: IpFilterConfig,

    /// Parsed CIDR rules sorted by priority.
    rules: Vec<ParsedIpRule>,

    /// Cache of IP -> action results.
    cache: Arc<RwLock<HashMap<String, RuleAction>>>,

    /// Maximum cache size.
    max_cache_size: usize,
}

/// A parsed IP rule with pre-computed CIDR data.
#[derive(Debug, Clone)]
struct ParsedIpRule {
    /// Original rule.
    rule: IpRule,

    /// Parsed addresses as CIDR entries.
    cidrs: Vec<CidrEntry>,
}

/// A parsed CIDR entry.
#[derive(Debug, Clone)]
struct CidrEntry {
    /// Network address as u32.
    network: u32,

    /// Subnet mask as u32.
    mask: u32,

    /// Original string for debugging.
    #[allow(dead_code)]
    original: String,
}

impl IpFilter {
    /// Create a new IP filter from configuration.
    pub fn new(config: IpFilterConfig) -> AccessControlResult<Self> {
        let mut rules = Vec::with_capacity(config.rules.len());

        for rule in &config.rules {
            let mut cidrs = Vec::with_capacity(rule.addresses.len());

            for addr in &rule.addresses {
                let cidr = Self::parse_cidr(addr)?;
                cidrs.push(cidr);
            }

            rules.push(ParsedIpRule {
                rule: rule.clone(),
                cidrs,
            });
        }

        // Sort by priority (higher first)
        rules.sort_by(|a, b| b.rule.priority.cmp(&a.rule.priority));

        Ok(Self {
            config,
            rules,
            cache: Arc::new(RwLock::new(HashMap::new())),
            max_cache_size: 10000,
        })
    }

    /// Parse a CIDR string into network/mask.
    fn parse_cidr(addr: &str) -> AccessControlResult<CidrEntry> {
        let (ip_str, prefix_len) = if let Some((ip, prefix)) = addr.split_once('/') {
            let prefix_len: u8 = prefix.parse().map_err(|_| {
                AccessControlError::InvalidCidr(format!("invalid prefix length in '{addr}'"))
            })?;

            if prefix_len > 32 {
                return Err(AccessControlError::InvalidCidr(format!(
                    "prefix length must be 0-32, got {prefix_len}"
                )));
            }

            (ip, prefix_len)
        } else {
            // Single IP, treat as /32
            (addr, 32)
        };

        let network = Self::parse_ip(ip_str)?;
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };

        Ok(CidrEntry {
            network: network & mask,
            mask,
            original: addr.to_string(),
        })
    }

    /// Parse an IP address string to u32.
    fn parse_ip(ip: &str) -> AccessControlResult<u32> {
        let parts: Vec<&str> = ip.split('.').collect();

        if parts.len() != 4 {
            return Err(AccessControlError::InvalidIpAddress(format!(
                "expected 4 octets, got {} in '{ip}'",
                parts.len()
            )));
        }

        let mut result = 0u32;
        for (i, part) in parts.iter().enumerate() {
            let octet: u8 = part.parse().map_err(|_| {
                AccessControlError::InvalidIpAddress(format!("invalid octet '{part}' in '{ip}'"))
            })?;
            result |= (octet as u32) << (24 - i * 8);
        }

        Ok(result)
    }

    /// Check if an IP address matches this filter.
    pub fn check(&self, ip: &str) -> AccessControlResult<RuleAction> {
        // Check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(action) = cache.get(ip) {
                return Ok(action.clone());
            }
        }

        // Parse the IP
        let ip_u32 = Self::parse_ip(ip)?;

        // Check rules in priority order
        let action = self.evaluate_rules(ip_u32);

        // Cache the result
        {
            let mut cache = self.cache.write().unwrap();
            if cache.len() < self.max_cache_size {
                cache.insert(ip.to_string(), action.clone());
            }
        }

        Ok(action)
    }

    /// Evaluate rules for an IP.
    fn evaluate_rules(&self, ip: u32) -> RuleAction {
        for parsed_rule in &self.rules {
            for cidr in &parsed_rule.cidrs {
                if (ip & cidr.mask) == cidr.network {
                    return parsed_rule.rule.action.clone();
                }
            }
        }

        // No rule matched, return default
        self.config.default_action.clone()
    }

    /// Check if an IP is allowed.
    pub fn is_allowed(&self, ip: &str) -> AccessControlResult<bool> {
        let action = self.check(ip)?;
        Ok(action.is_allow())
    }

    /// Get the client IP from headers.
    pub fn get_client_ip(
        &self,
        direct_ip: &str,
        headers: &HashMap<String, String>,
    ) -> AccessControlResult<String> {
        if !self.config.trust_proxy_headers {
            return Ok(direct_ip.to_string());
        }

        // If we have trusted proxies configured, verify the direct connection
        if !self.config.trusted_proxies.is_empty() {
            let direct_ip_u32 = Self::parse_ip(direct_ip)?;
            let mut is_trusted = false;

            for proxy in &self.config.trusted_proxies {
                let cidr = Self::parse_cidr(proxy)?;
                if (direct_ip_u32 & cidr.mask) == cidr.network {
                    is_trusted = true;
                    break;
                }
            }

            if !is_trusted {
                return Ok(direct_ip.to_string());
            }
        }

        // Try X-Forwarded-For first
        if let Some(xff) = headers
            .get("x-forwarded-for")
            .or_else(|| headers.get("X-Forwarded-For"))
        {
            // Take the leftmost IP (original client)
            if let Some(client_ip) = xff.split(',').next() {
                let client_ip = client_ip.trim();
                // Validate it's a proper IP
                if Self::parse_ip(client_ip).is_ok() {
                    return Ok(client_ip.to_string());
                }
            }
        }

        // Try X-Real-IP
        if let Some(real_ip) = headers
            .get("x-real-ip")
            .or_else(|| headers.get("X-Real-IP"))
        {
            let real_ip = real_ip.trim();
            if Self::parse_ip(real_ip).is_ok() {
                return Ok(real_ip.to_string());
            }
        }

        Ok(direct_ip.to_string())
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        self.cache.write().unwrap().clear();
    }

    /// Get cache size.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    /// Get the default action.
    #[must_use]
    pub fn default_action(&self) -> &RuleAction {
        &self.config.default_action
    }
}

/// A simple allow list that only allows specific IPs.
#[derive(Debug)]
pub struct AllowList {
    filter: IpFilter,
}

impl AllowList {
    /// Create a new allow list from IP addresses/CIDRs.
    pub fn new(addresses: Vec<String>) -> AccessControlResult<Self> {
        let config = IpFilterConfig {
            enabled: true,
            rules: vec![IpRule::allow(addresses)],
            default_action: RuleAction::Deny,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
        };

        Ok(Self {
            filter: IpFilter::new(config)?,
        })
    }

    /// Check if an IP is allowed.
    pub fn is_allowed(&self, ip: &str) -> AccessControlResult<bool> {
        self.filter.is_allowed(ip)
    }
}

/// A simple deny list that blocks specific IPs.
#[derive(Debug)]
pub struct DenyList {
    filter: IpFilter,
}

impl DenyList {
    /// Create a new deny list from IP addresses/CIDRs.
    pub fn new(addresses: Vec<String>) -> AccessControlResult<Self> {
        let config = IpFilterConfig {
            enabled: true,
            rules: vec![IpRule::deny(addresses)],
            default_action: RuleAction::Allow,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
        };

        Ok(Self {
            filter: IpFilter::new(config)?,
        })
    }

    /// Check if an IP is blocked.
    pub fn is_blocked(&self, ip: &str) -> AccessControlResult<bool> {
        let allowed = self.filter.is_allowed(ip)?;
        Ok(!allowed)
    }

    /// Check if an IP is allowed (not blocked).
    pub fn is_allowed(&self, ip: &str) -> AccessControlResult<bool> {
        self.filter.is_allowed(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip() {
        assert_eq!(IpFilter::parse_ip("192.168.1.1").unwrap(), 0xC0A80101);
        assert_eq!(IpFilter::parse_ip("10.0.0.1").unwrap(), 0x0A000001);
        assert_eq!(IpFilter::parse_ip("255.255.255.255").unwrap(), 0xFFFFFFFF);
        assert_eq!(IpFilter::parse_ip("0.0.0.0").unwrap(), 0);
    }

    #[test]
    fn test_parse_ip_invalid() {
        assert!(IpFilter::parse_ip("192.168.1").is_err());
        assert!(IpFilter::parse_ip("192.168.1.1.1").is_err());
        assert!(IpFilter::parse_ip("256.0.0.1").is_err());
        assert!(IpFilter::parse_ip("abc.0.0.1").is_err());
    }

    #[test]
    fn test_parse_cidr() {
        let cidr = IpFilter::parse_cidr("192.168.0.0/16").unwrap();
        assert_eq!(cidr.network, 0xC0A80000);
        assert_eq!(cidr.mask, 0xFFFF0000);

        let cidr = IpFilter::parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(cidr.network, 0x0A000000);
        assert_eq!(cidr.mask, 0xFF000000);

        let cidr = IpFilter::parse_cidr("192.168.1.1").unwrap();
        assert_eq!(cidr.network, 0xC0A80101);
        assert_eq!(cidr.mask, 0xFFFFFFFF);
    }

    #[test]
    fn test_ip_filter_basic() {
        let config = IpFilterConfig {
            enabled: true,
            rules: vec![
                IpRule::deny(vec!["10.0.0.0/8".to_string()]).with_priority(1),
                IpRule::allow(vec!["192.168.1.0/24".to_string()]).with_priority(2),
            ],
            default_action: RuleAction::Allow,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
        };

        let filter = IpFilter::new(config).unwrap();

        // Higher priority allow rule for 192.168.1.x
        assert!(filter.is_allowed("192.168.1.100").unwrap());

        // Deny rule for 10.x.x.x
        assert!(!filter.is_allowed("10.1.2.3").unwrap());

        // Default allow for other IPs
        assert!(filter.is_allowed("172.16.0.1").unwrap());
    }

    #[test]
    fn test_ip_filter_priority() {
        let config = IpFilterConfig {
            enabled: true,
            rules: vec![
                IpRule::allow(vec!["10.0.0.0/8".to_string()]).with_priority(1),
                IpRule::deny(vec!["10.1.0.0/16".to_string()]).with_priority(2),
            ],
            default_action: RuleAction::Deny,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
        };

        let filter = IpFilter::new(config).unwrap();

        // Higher priority deny for 10.1.x.x should win
        assert!(!filter.is_allowed("10.1.2.3").unwrap());

        // Lower priority allow for other 10.x.x.x
        assert!(filter.is_allowed("10.2.3.4").unwrap());
    }

    #[test]
    fn test_allow_list() {
        let allow_list =
            AllowList::new(vec!["192.168.1.0/24".to_string(), "10.0.0.1".to_string()]).unwrap();

        assert!(allow_list.is_allowed("192.168.1.1").unwrap());
        assert!(allow_list.is_allowed("192.168.1.254").unwrap());
        assert!(allow_list.is_allowed("10.0.0.1").unwrap());

        // Not in allow list
        assert!(!allow_list.is_allowed("10.0.0.2").unwrap());
        assert!(!allow_list.is_allowed("172.16.0.1").unwrap());
    }

    #[test]
    fn test_deny_list() {
        let deny_list = DenyList::new(vec!["10.0.0.0/8".to_string()]).unwrap();

        assert!(deny_list.is_blocked("10.1.2.3").unwrap());
        assert!(deny_list.is_blocked("10.255.255.255").unwrap());

        // Not in deny list
        assert!(!deny_list.is_blocked("192.168.1.1").unwrap());
        assert!(deny_list.is_allowed("192.168.1.1").unwrap());
    }

    #[test]
    fn test_cache() {
        let config = IpFilterConfig {
            enabled: true,
            rules: vec![IpRule::allow(vec!["192.168.1.0/24".to_string()])],
            default_action: RuleAction::Deny,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
        };

        let filter = IpFilter::new(config).unwrap();

        assert_eq!(filter.cache_size(), 0);

        // First check populates cache
        assert!(filter.is_allowed("192.168.1.1").unwrap());
        assert_eq!(filter.cache_size(), 1);

        // Second check uses cache
        assert!(filter.is_allowed("192.168.1.1").unwrap());
        assert_eq!(filter.cache_size(), 1);

        // Clear cache
        filter.clear_cache();
        assert_eq!(filter.cache_size(), 0);
    }

    #[test]
    fn test_get_client_ip_no_proxy() {
        let config = IpFilterConfig {
            enabled: true,
            rules: vec![],
            default_action: RuleAction::Allow,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
        };

        let filter = IpFilter::new(config).unwrap();

        let mut headers = HashMap::new();
        headers.insert("X-Forwarded-For".to_string(), "1.2.3.4".to_string());

        // Should ignore header when trust_proxy_headers is false
        let ip = filter.get_client_ip("192.168.1.1", &headers).unwrap();
        assert_eq!(ip, "192.168.1.1");
    }

    #[test]
    fn test_get_client_ip_with_proxy() {
        let config = IpFilterConfig {
            enabled: true,
            rules: vec![],
            default_action: RuleAction::Allow,
            trust_proxy_headers: true,
            trusted_proxies: Vec::new(),
        };

        let filter = IpFilter::new(config).unwrap();

        let mut headers = HashMap::new();
        headers.insert(
            "X-Forwarded-For".to_string(),
            "1.2.3.4, 5.6.7.8".to_string(),
        );

        // Should use first IP from X-Forwarded-For
        let ip = filter.get_client_ip("192.168.1.1", &headers).unwrap();
        assert_eq!(ip, "1.2.3.4");
    }

    #[test]
    fn test_get_client_ip_trusted_proxy() {
        let config = IpFilterConfig {
            enabled: true,
            rules: vec![],
            default_action: RuleAction::Allow,
            trust_proxy_headers: true,
            trusted_proxies: vec!["192.168.0.0/16".to_string()],
        };

        let filter = IpFilter::new(config).unwrap();

        let mut headers = HashMap::new();
        headers.insert("X-Forwarded-For".to_string(), "1.2.3.4".to_string());

        // Trusted proxy - use header
        let ip = filter.get_client_ip("192.168.1.1", &headers).unwrap();
        assert_eq!(ip, "1.2.3.4");

        // Untrusted direct connection - ignore header
        let ip = filter.get_client_ip("10.0.0.1", &headers).unwrap();
        assert_eq!(ip, "10.0.0.1");
    }

    #[test]
    fn test_cidr_edge_cases() {
        // /32 - exact match
        let allow_list = AllowList::new(vec!["192.168.1.1/32".to_string()]).unwrap();
        assert!(allow_list.is_allowed("192.168.1.1").unwrap());
        assert!(!allow_list.is_allowed("192.168.1.2").unwrap());

        // /0 - match all
        let allow_list = AllowList::new(vec!["0.0.0.0/0".to_string()]).unwrap();
        assert!(allow_list.is_allowed("1.2.3.4").unwrap());
        assert!(allow_list.is_allowed("255.255.255.255").unwrap());
    }
}
