//! IP filtering for access control.
//!
//! Uses a CIDR radix trie for O(32) worst-case lookups and a bloom filter
//! front guard for fast rejection of non-matching IPs.  Cache keyed on
//! pre-parsed `u32` addresses to eliminate per-lookup String allocation.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::config::{IpFilterConfig, IpRule, RuleAction};
use super::error::{AccessControlError, AccessControlResult};

// ── Bloom filter front guard ────────────────────────────────────────────────

/// Bloom filter sized for CIDR prefix entries.
/// Eliminates trie traversal for IPs that definitely match no rule.
struct BloomGuard {
    /// Bit storage (power-of-two sized for branchless masking).
    bits: Box<[u64]>,
    /// Total number of bits (always power of two).
    num_bits: usize,
    /// Prefix lengths that have at least one rule.
    active_prefixes: Vec<u8>,
}

impl BloomGuard {
    /// Number of hash functions (k=3 for ~1 % FP at 10 bits/entry).
    const K: u32 = 3;

    fn new(estimated_entries: usize) -> Self {
        let num_bits = (estimated_entries * 10).max(64).next_power_of_two();
        let num_words = num_bits / 64;
        Self {
            bits: vec![0u64; num_words].into_boxed_slice(),
            num_bits,
            active_prefixes: Vec::new(),
        }
    }

    fn insert(&mut self, prefix_len: u8, network: u32) {
        if !self.active_prefixes.contains(&prefix_len) {
            self.active_prefixes.push(prefix_len);
            self.active_prefixes.sort_unstable();
        }
        let key = Self::combine(prefix_len, network);
        for seed in 0..Self::K {
            let idx = Self::hash(key, seed) & (self.num_bits - 1);
            self.bits[idx >> 6] |= 1 << (idx & 63);
        }
    }

    /// Returns `false` when the IP **cannot** match any rule (no false negatives).
    #[inline]
    fn might_match(&self, ip: u32) -> bool {
        for &plen in &self.active_prefixes {
            let mask = prefix_mask(plen);
            let network = ip & mask;
            let key = Self::combine(plen, network);
            let mut hit = true;
            for seed in 0..Self::K {
                let idx = Self::hash(key, seed) & (self.num_bits - 1);
                if self.bits[idx >> 6] & (1 << (idx & 63)) == 0 {
                    hit = false;
                    break;
                }
            }
            if hit {
                return true;
            }
        }
        false
    }

    #[inline(always)]
    fn combine(prefix_len: u8, network: u32) -> u64 {
        (prefix_len as u64) << 32 | network as u64
    }

    /// FNV-1a inspired hash with seed mixing.
    #[inline(always)]
    fn hash(key: u64, seed: u32) -> usize {
        let mut h = 0x517c_c1b7_2722_0a95_u64;
        h ^= key;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        h ^= seed as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        h as usize
    }
}

impl std::fmt::Debug for BloomGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BloomGuard")
            .field("num_bits", &self.num_bits)
            .field("active_prefixes", &self.active_prefixes)
            .finish()
    }
}

// ── CIDR radix trie ─────────────────────────────────────────────────────────

/// Binary radix trie for CIDR longest-prefix matching.
///
/// Provides deterministic O(32) lookup for IPv4 addresses with
/// priority-aware matching across overlapping prefixes.
#[derive(Debug)]
struct CidrTrie {
    root: TrieNode,
}

#[derive(Debug)]
struct TrieNode {
    children: [Option<Box<TrieNode>>; 2],
    /// `(priority, action)` if a CIDR rule terminates here.
    entry: Option<(i32, RuleAction)>,
}

impl TrieNode {
    #[inline]
    const fn empty() -> Self {
        Self {
            children: [None, None],
            entry: None,
        }
    }
}

impl CidrTrie {
    fn new() -> Self {
        Self {
            root: TrieNode::empty(),
        }
    }

    /// Insert a CIDR rule.  Keeps the higher-priority action on conflict.
    fn insert(&mut self, network: u32, prefix_len: u8, priority: i32, action: RuleAction) {
        let mut node = &mut self.root;
        for i in 0..prefix_len {
            let bit = ((network >> (31 - i)) & 1) as usize;
            node = node.children[bit].get_or_insert_with(|| Box::new(TrieNode::empty()));
        }
        match node.entry {
            Some((ep, _)) if ep >= priority => {}, // existing wins
            _ => node.entry = Some((priority, action)),
        }
    }

    /// Longest-prefix match returning the highest-priority action along the path.
    #[inline]
    fn lookup(&self, ip: u32) -> Option<RuleAction> {
        let mut node = &self.root;
        let mut best: Option<(i32, RuleAction)> = node.entry;
        for i in 0..32u8 {
            let bit = ((ip >> (31 - i)) & 1) as usize;
            match &node.children[bit] {
                Some(child) => {
                    node = child;
                    if let Some(entry) = node.entry {
                        match best {
                            Some((bp, _)) if bp >= entry.0 => {},
                            _ => best = Some(entry),
                        }
                    }
                },
                None => break,
            }
        }
        best.map(|(_, action)| action)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Compute mask for a given prefix length.  `/0` → `0`, `/32` → `0xFFFF_FFFF`.
#[inline(always)]
const fn prefix_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    }
}

// ── IpFilter ────────────────────────────────────────────────────────────────

/// IP filter for allow/deny list matching.
///
/// Uses a CIDR radix trie for O(32) worst-case lookups and a bloom filter
/// front guard for O(1) fast rejection of non-matching IPs.
/// Cache is keyed on pre-parsed `u32` to eliminate per-lookup allocation.
#[derive(Debug)]
pub struct IpFilter {
    /// Configuration.
    config: IpFilterConfig,

    /// Radix trie for CIDR matching.
    trie: CidrTrie,

    /// Bloom filter for fast-path rejection.
    bloom: BloomGuard,

    /// Cache of ip_u32 → action (no String allocation).
    cache: Arc<RwLock<HashMap<u32, RuleAction>>>,

    /// Maximum cache size.
    max_cache_size: usize,

    /// Pre-parsed trusted proxy CIDRs: `(network, mask)`.
    trusted_proxy_cidrs: Vec<(u32, u32)>,
}

impl IpFilter {
    /// Create a new IP filter from configuration.
    pub fn new(config: IpFilterConfig) -> AccessControlResult<Self> {
        let total_cidrs: usize = config.rules.iter().map(|r| r.addresses.len()).sum();
        let mut trie = CidrTrie::new();
        let mut bloom = BloomGuard::new(total_cidrs.max(1));

        for rule in &config.rules {
            for addr in &rule.addresses {
                let (network, prefix_len) = Self::parse_cidr_pair(addr)?;
                let mask = prefix_mask(prefix_len);
                let masked = network & mask;
                trie.insert(masked, prefix_len, rule.priority, rule.action);
                bloom.insert(prefix_len, masked);
            }
        }

        // Pre-parse trusted proxies (avoids per-request allocation)
        let mut trusted_proxy_cidrs = Vec::with_capacity(config.trusted_proxies.len());
        for proxy in &config.trusted_proxies {
            let (network, prefix_len) = Self::parse_cidr_pair(proxy)?;
            let mask = prefix_mask(prefix_len);
            trusted_proxy_cidrs.push((network & mask, mask));
        }

        Ok(Self {
            config,
            trie,
            bloom,
            cache: Arc::new(RwLock::new(HashMap::with_capacity(256))),
            max_cache_size: 10_000,
            trusted_proxy_cidrs,
        })
    }

    /// Parse a CIDR string into `(network_u32, prefix_len)`.  Zero allocation.
    fn parse_cidr_pair(addr: &str) -> AccessControlResult<(u32, u8)> {
        let (ip_str, prefix_len) = if let Some((ip, prefix)) = addr.split_once('/') {
            let plen: u8 = prefix.parse().map_err(|_| {
                AccessControlError::InvalidCidr(format!("invalid prefix length in '{addr}'"))
            })?;
            if plen > 32 {
                return Err(AccessControlError::InvalidCidr(format!(
                    "prefix length must be 0-32, got {plen}"
                )));
            }
            (ip, plen)
        } else {
            (addr, 32)
        };

        let network = Self::parse_ip(ip_str)?;
        Ok((network, prefix_len))
    }

    /// Parse an IPv4 address string to `u32`.  Zero allocation (byte scan).
    #[inline]
    fn parse_ip(ip: &str) -> AccessControlResult<u32> {
        let bytes = ip.as_bytes();
        let mut result = 0u32;
        let mut octet: u32 = 0;
        let mut dots = 0u8;
        let mut digit_count = 0u8;

        for &b in bytes {
            match b {
                b'0'..=b'9' => {
                    digit_count += 1;
                    if digit_count > 3 {
                        return Err(AccessControlError::InvalidIpAddress(format!(
                            "octet too long in '{ip}'"
                        )));
                    }
                    octet = octet * 10 + (b - b'0') as u32;
                    if octet > 255 {
                        return Err(AccessControlError::InvalidIpAddress(format!(
                            "octet > 255 in '{ip}'"
                        )));
                    }
                },
                b'.' => {
                    if digit_count == 0 {
                        return Err(AccessControlError::InvalidIpAddress(format!(
                            "empty octet in '{ip}'"
                        )));
                    }
                    result = (result << 8) | octet;
                    octet = 0;
                    dots += 1;
                    digit_count = 0;
                    if dots > 3 {
                        return Err(AccessControlError::InvalidIpAddress(format!(
                            "too many octets in '{ip}'"
                        )));
                    }
                },
                _ => {
                    return Err(AccessControlError::InvalidIpAddress(format!(
                        "invalid character in '{ip}'"
                    )));
                },
            }
        }

        if dots != 3 || digit_count == 0 {
            return Err(AccessControlError::InvalidIpAddress(format!(
                "expected 4 octets in '{ip}'"
            )));
        }
        result = (result << 8) | octet;
        Ok(result)
    }

    /// Check if an IP address matches this filter.
    #[inline]
    pub fn check(&self, ip: &str) -> AccessControlResult<RuleAction> {
        // Parse first — enables u32 cache key (no String allocation)
        let ip_u32 = Self::parse_ip(ip)?;

        // Fast path: cache lookup with u32 key
        {
            let cache = self.cache.read().unwrap();
            if let Some(&action) = cache.get(&ip_u32) {
                return Ok(action);
            }
        }

        // Bloom filter: fast reject IPs that cannot match any rule
        let action = if !self.bloom.might_match(ip_u32) {
            self.config.default_action
        } else {
            // Trie lookup: O(32) deterministic, priority-aware
            self.trie
                .lookup(ip_u32)
                .unwrap_or(self.config.default_action)
        };

        // Populate cache (u32 key — zero heap allocation)
        {
            let mut cache = self.cache.write().unwrap();
            if cache.len() < self.max_cache_size {
                cache.insert(ip_u32, action);
            }
        }

        Ok(action)
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

        // Use pre-parsed trusted proxy CIDRs (no per-request allocation)
        if !self.trusted_proxy_cidrs.is_empty() {
            let direct_u32 = Self::parse_ip(direct_ip)?;
            let is_trusted = self
                .trusted_proxy_cidrs
                .iter()
                .any(|&(network, mask)| (direct_u32 & mask) == network);

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
        let (net, plen) = IpFilter::parse_cidr_pair("192.168.0.0/16").unwrap();
        assert_eq!(net & prefix_mask(plen), 0xC0A80000);
        assert_eq!(prefix_mask(plen), 0xFFFF0000);

        let (net, plen) = IpFilter::parse_cidr_pair("10.0.0.0/8").unwrap();
        assert_eq!(net & prefix_mask(plen), 0x0A000000);
        assert_eq!(prefix_mask(plen), 0xFF000000);

        let (net, plen) = IpFilter::parse_cidr_pair("192.168.1.1").unwrap();
        assert_eq!(net & prefix_mask(plen), 0xC0A80101);
        assert_eq!(prefix_mask(plen), 0xFFFFFFFF);
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
