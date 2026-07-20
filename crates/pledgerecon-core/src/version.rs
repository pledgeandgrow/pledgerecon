//! Version matching for different package ecosystems.
//!
//! Supports semver (npm, crates.io), PEP 440 (PyPI), and Go module versions
//! (including pseudo-versions and `+incompatible` suffixes).

/// Check if a version falls within a range using ecosystem-specific rules.
pub fn version_in_range(
    version: &str,
    introduced: Option<&str>,
    fixed: Option<&str>,
    last_affected: Option<&str>,
    ecosystem: &str,
) -> bool {
    match ecosystem {
        "PyPI" => pep440_in_range(version, introduced, fixed, last_affected),
        "Go" => go_in_range(version, introduced, fixed, last_affected),
        _ => semver_in_range(version, introduced, fixed, last_affected),
    }
}

/// Semver range matching (npm, crates.io).
/// Uses standard semver parsing and comparison.
pub fn semver_in_range(
    version: &str,
    introduced: Option<&str>,
    fixed: Option<&str>,
    last_affected: Option<&str>,
) -> bool {
    let ver = match semver::Version::parse(version) {
        Ok(v) => v,
        Err(_) => return true, // Can't parse — assume affected (safer default).
    };

    if let Some(intro) = introduced
        && let Ok(min) = semver::Version::parse(intro)
        && ver < min
    {
        return false;
    }

    if let Some(fix) = fixed
        && let Ok(fix_ver) = semver::Version::parse(fix)
        && ver >= fix_ver
    {
        return false;
    }

    if let Some(last) = last_affected
        && let Ok(last_ver) = semver::Version::parse(last)
        && ver > last_ver
    {
        return false;
    }

    true
}

/// Parse a semver version requirement string (e.g. ">=1.0.0, <2.0.0", "^1.2.0", "~1.0.0").
/// Returns true if the given version satisfies the requirement.
pub fn semver_matches_requirement(version: &str, requirement: &str) -> bool {
    let ver = match semver::Version::parse(version) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Handle caret requirements: ^1.2.3 => >=1.2.3, <2.0.0
    // Handle tilde requirements: ~1.2.3 => >=1.2.3, <1.3.0
    // Handle exact: 1.2.3
    // Handle comparators: >=1.0.0, <2.0.0, >1.0.0, <=1.0.0
    let req = requirement.trim();

    // Split on commas for multi-comparator requirements.
    for part in req.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if !match_single_comparator(&ver, part) {
            return false;
        }
    }

    true
}

fn match_single_comparator(ver: &semver::Version, req: &str) -> bool {
    if req.is_empty() {
        return true;
    }

    // Caret: ^1.2.3 => >=1.2.3, <2.0.0 (or <1.3.0 for 0.x, or <0.3.0 for 0.0.x)
    if let Some(rest) = req.strip_prefix('^')
        && let Ok(base) = semver::Version::parse(rest)
    {
        if ver < &base {
            return false;
        }
        let upper = if base.major > 0 {
            semver::Version::new(base.major + 1, 0, 0)
        } else if base.minor > 0 {
            semver::Version::new(0, base.minor + 1, 0)
        } else {
            semver::Version::new(0, 0, base.patch + 1)
        };
        if ver >= &upper {
            return false;
        }
        return true;
    }

    // Tilde: ~1.2.3 => >=1.2.3, <1.3.0
    if let Some(rest) = req.strip_prefix('~')
        && let Ok(base) = semver::Version::parse(rest)
    {
        if ver < &base {
            return false;
        }
        let upper = semver::Version::new(base.major, base.minor + 1, 0);
        if ver >= &upper {
            return false;
        }
        return true;
    }

    // Comparators: >=, <=, >, <, =
    if let Some(rest) = req.strip_prefix(">=")
        && let Ok(threshold) = semver::Version::parse(rest.trim())
    {
        return ver >= &threshold;
    }
    if let Some(rest) = req.strip_prefix("<=")
        && let Ok(threshold) = semver::Version::parse(rest.trim())
    {
        return ver <= &threshold;
    }
    if let Some(rest) = req.strip_prefix('>')
        && let Ok(threshold) = semver::Version::parse(rest.trim())
    {
        return ver > &threshold;
    }
    if let Some(rest) = req.strip_prefix('<')
        && let Ok(threshold) = semver::Version::parse(rest.trim())
    {
        return ver < &threshold;
    }
    if let Some(rest) = req.strip_prefix('=')
        && let Ok(threshold) = semver::Version::parse(rest.trim())
    {
        return ver == &threshold;
    }

    // Exact version match
    if let Ok(threshold) = semver::Version::parse(req) {
        return ver == &threshold;
    }

    // Wildcard: 1.x, 1.2.x, *
    if req == "*" || req == "x" {
        return true;
    }
    if req.ends_with(".x") || req.ends_with(".*") {
        let prefix = req.trim_end_matches(".x").trim_end_matches(".*");
        let parts: Vec<&str> = prefix.split('.').collect();
        if !parts.is_empty() {
            if let Ok(major) = parts[0].parse::<u64>()
                && ver.major != major
            {
                return false;
            }
            if parts.len() >= 2
                && let Ok(minor) = parts[1].parse::<u64>()
                && ver.minor != minor
            {
                return false;
            }
            return true;
        }
    }

    false
}

/// PEP 440 version matching (Python/PyPI).
///
/// PEP 440 versions can include:
/// - Epoch: 1!2.3.4
/// - Pre-release: 1.2.3a1, 1.2.3b2, 1.2.3rc1
/// - Post-release: 1.2.3.post1
/// - Dev-release: 1.2.3.dev1
/// - Local versions: 1.2.3+local
///
/// We normalize these for comparison.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pep440Version {
    epoch: u64,
    major: u64,
    minor: u64,
    patch: u64,
    pre: Option<(String, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
}

impl Pep440Version {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }

        let mut epoch = 0u64;
        let mut rest = s;

        // Parse epoch: 1!2.3.4
        if let Some(pos) = rest.find('!') {
            epoch = rest[..pos].parse().ok()?;
            rest = &rest[pos + 1..];
        }

        // Strip local version: 1.2.3+local
        let rest = rest.split('+').next().unwrap_or(rest);

        // Parse post-release: 1.2.3.post1
        let post = if let Some(pos) = rest.find(".post") {
            rest[pos + 5..].parse::<u64>().ok()
        } else if let Some(pos) = rest.find("-post") {
            rest[pos + 5..].parse::<u64>().ok()
        } else {
            None
        };

        // Parse dev-release: 1.2.3.dev1
        let dev = if let Some(pos) = rest.find(".dev") {
            rest[pos + 4..].parse::<u64>().ok()
        } else {
            None
        };

        // Parse pre-release: a1, b2, rc1, alpha1, beta2, pre1, preview1
        let pre = parse_pep440_pre(rest);

        // Parse the main version numbers.
        let base = rest
            .split(|c: char| !c.is_ascii_digit() && c != '.')
            .next()
            .unwrap_or(rest);
        let parts: Vec<&str> = base.split('.').collect();
        let major = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
        let patch = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);

        Some(Self {
            epoch,
            major,
            minor,
            patch,
            pre,
            post,
            dev,
        })
    }
}

fn parse_pep440_pre(s: &str) -> Option<(String, u64)> {
    // PEP 440 pre-release markers and their normalized forms.
    // Order matters: longer markers must be checked before shorter ones
    // (e.g. "alpha" before "a", "beta" before "b").
    let markers: &[(&str, &str)] = &[
        ("alpha", "a"),
        ("a", "a"),
        ("beta", "b"),
        ("b", "b"),
        ("preview", "rc"),
        ("pre", "rc"),
        ("rc", "rc"),
        ("c", "rc"),
    ];

    for (marker, normalized) in markers {
        // Try with separators: .alpha, -alpha, _alpha
        for sep in &['.', '-', '_'] {
            let pattern = format!("{}{}", sep, marker);
            if let Some(pos) = s.find(&pattern) {
                let after = &s[pos + pattern.len()..];
                let num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
                let n = if num.is_empty() {
                    0
                } else {
                    num.parse().unwrap_or(0)
                };
                return Some((normalized.to_string(), n));
            }
        }
        // Try direct concatenation after a digit: 1.2.3a1, 1.2.3rc2, 1.2.3beta1
        if let Some(pos) = s.find(marker)
            && pos > 0
            && s.as_bytes()[pos - 1].is_ascii_digit()
        {
            let after = &s[pos + marker.len()..];
            let num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            let n = if num.is_empty() {
                0
            } else {
                num.parse().unwrap_or(0)
            };
            return Some((normalized.to_string(), n));
        }
    }
    None
}

pub fn pep440_in_range(
    version: &str,
    introduced: Option<&str>,
    fixed: Option<&str>,
    last_affected: Option<&str>,
) -> bool {
    let ver = match Pep440Version::parse(version) {
        Some(v) => v,
        None => return true,
    };

    if let Some(intro) = introduced
        && let Some(min) = Pep440Version::parse(intro)
        && ver < min
    {
        return false;
    }

    if let Some(fix) = fixed
        && let Some(fix_ver) = Pep440Version::parse(fix)
        && ver >= fix_ver
    {
        return false;
    }

    if let Some(last) = last_affected
        && let Some(last_ver) = Pep440Version::parse(last)
        && ver > last_ver
    {
        return false;
    }

    true
}

/// Go module version matching.
///
/// Go versions can be:
/// - Semver: v1.2.3
/// - Pseudo-versions: v1.2.4-20191231235908-abcdef123456
/// - +incompatible suffix for modules that don't follow semver v2 rules
/// - Pre-release tags: v1.2.3-beta.1
pub fn go_in_range(
    version: &str,
    introduced: Option<&str>,
    fixed: Option<&str>,
    last_affected: Option<&str>,
) -> bool {
    let ver = match parse_go_version(version) {
        Some(v) => v,
        None => return true,
    };

    if let Some(intro) = introduced
        && let Some(min) = parse_go_version(intro)
        && ver < min
    {
        return false;
    }

    if let Some(fix) = fixed
        && let Some(fix_ver) = parse_go_version(fix)
        && ver >= fix_ver
    {
        return false;
    }

    if let Some(last) = last_affected
        && let Some(last_ver) = parse_go_version(last)
        && ver > last_ver
    {
        return false;
    }

    true
}

/// Parse a Go module version string into a comparable form.
/// Strips the leading "v" prefix and "+incompatible" suffix.
fn parse_go_version(s: &str) -> Option<GoVersion> {
    let s = s.trim();
    let s = s.strip_prefix('v').unwrap_or(s);
    let s = s.strip_suffix("+incompatible").unwrap_or(s);

    // Handle pseudo-versions: 1.2.4-20191231235908-abcdef123456
    // These sort after the base version.
    if let Some(pos) = s.find('-') {
        let base = &s[..pos];
        let suffix = &s[pos + 1..];

        let parts: Vec<&str> = base.split('.').collect();
        let major = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0u64);
        let minor = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0u64);
        let patch = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0u64);

        // For pseudo-versions, the suffix is a timestamp which sorts after the base.
        return Some(GoVersion {
            major,
            minor,
            patch,
            pre: Some(format!("-{}", suffix)),
        });
    }

    let parts: Vec<&str> = s.split('.').collect();
    let major = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0u64);
    let minor = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0u64);
    let patch = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0u64);

    Some(GoVersion {
        major,
        minor,
        patch,
        pre: None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GoVersion {
    major: u64,
    minor: u64,
    patch: u64,
    // Pre-release / pseudo-version suffix. None means a release version.
    // A version with a pre-release sorts before the same version without one.
    pre: Option<String>,
}

// Custom comparison: a release version sorts AFTER a pre-release with the same base.
impl std::cmp::PartialOrd for GoVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for GoVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch)) {
            std::cmp::Ordering::Equal => {
                // Same base version — release > pre-release.
                match (&self.pre, &other.pre) {
                    (None, None) => std::cmp::Ordering::Equal,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (Some(a), Some(b)) => a.cmp(b),
                }
            }
            ord => ord,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Semver tests ──────────────────────────────────────────────────

    #[test]
    fn test_semver_in_range() {
        assert!(semver_in_range("1.5.0", Some("1.0.0"), Some("2.0.0"), None));
        assert!(semver_in_range("1.0.0", Some("1.0.0"), Some("2.0.0"), None));
        assert!(!semver_in_range(
            "2.0.0",
            Some("1.0.0"),
            Some("2.0.0"),
            None
        ));
        assert!(!semver_in_range(
            "0.9.0",
            Some("1.0.0"),
            Some("2.0.0"),
            None
        ));
    }

    #[test]
    fn test_semver_last_affected() {
        assert!(semver_in_range("1.5.0", Some("1.0.0"), None, Some("1.5.0")));
        assert!(!semver_in_range(
            "1.5.1",
            Some("1.0.0"),
            None,
            Some("1.5.0")
        ));
    }

    #[test]
    fn test_semver_caret() {
        assert!(semver_matches_requirement("1.2.3", "^1.2.0"));
        assert!(semver_matches_requirement("1.9.0", "^1.2.0"));
        assert!(!semver_matches_requirement("2.0.0", "^1.2.0"));
        assert!(!semver_matches_requirement("1.1.0", "^1.2.0"));
    }

    #[test]
    fn test_semver_tilde() {
        assert!(semver_matches_requirement("1.2.3", "~1.2.0"));
        assert!(semver_matches_requirement("1.2.9", "~1.2.0"));
        assert!(!semver_matches_requirement("1.3.0", "~1.2.0"));
    }

    #[test]
    fn test_semver_comparators() {
        assert!(semver_matches_requirement("1.5.0", ">=1.0.0, <2.0.0"));
        assert!(!semver_matches_requirement("2.0.0", ">=1.0.0, <2.0.0"));
        assert!(semver_matches_requirement("1.0.0", ">=1.0.0"));
        assert!(semver_matches_requirement("1.0.0", "<=1.0.0"));
        assert!(!semver_matches_requirement("1.1.0", "<=1.0.0"));
        assert!(semver_matches_requirement("1.1.0", ">1.0.0"));
        assert!(!semver_matches_requirement("1.0.0", ">1.0.0"));
    }

    #[test]
    fn test_semver_wildcard() {
        assert!(semver_matches_requirement("1.2.3", "1.x"));
        assert!(!semver_matches_requirement("2.0.0", "1.x"));
        assert!(semver_matches_requirement("1.2.3", "1.2.x"));
        assert!(!semver_matches_requirement("1.3.0", "1.2.x"));
        assert!(semver_matches_requirement("99.0.0", "*"));
    }

    #[test]
    fn test_semver_exact() {
        assert!(semver_matches_requirement("1.2.3", "1.2.3"));
        assert!(!semver_matches_requirement("1.2.4", "1.2.3"));
        assert!(semver_matches_requirement("1.2.3", "=1.2.3"));
    }

    // ─── PEP 440 tests ─────────────────────────────────────────────────

    #[test]
    fn test_pep440_parse_basic() {
        let v = Pep440Version::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
        assert!(v.pre.is_none());
    }

    #[test]
    fn test_pep440_parse_epoch() {
        let v = Pep440Version::parse("1!2.3.4").unwrap();
        assert_eq!(v.epoch, 1);
        assert_eq!(v.major, 2);
    }

    #[test]
    fn test_pep440_parse_pre_release() {
        let v = Pep440Version::parse("1.2.3a1").unwrap();
        assert_eq!(v.pre, Some(("a".to_string(), 1)));

        let v = Pep440Version::parse("1.2.3rc2").unwrap();
        assert_eq!(v.pre, Some(("rc".to_string(), 2)));

        let v = Pep440Version::parse("1.2.3beta1").unwrap();
        assert_eq!(v.pre, Some(("b".to_string(), 1)));
    }

    #[test]
    fn test_pep440_parse_post_release() {
        let v = Pep440Version::parse("1.2.3.post1").unwrap();
        assert_eq!(v.post, Some(1));
    }

    #[test]
    fn test_pep440_parse_dev_release() {
        let v = Pep440Version::parse("1.2.3.dev1").unwrap();
        assert_eq!(v.dev, Some(1));
    }

    #[test]
    fn test_pep440_in_range() {
        assert!(pep440_in_range("1.5.0", Some("1.0.0"), Some("2.0.0"), None));
        assert!(!pep440_in_range(
            "2.0.0",
            Some("1.0.0"),
            Some("2.0.0"),
            None
        ));
        assert!(!pep440_in_range(
            "0.9.0",
            Some("1.0.0"),
            Some("2.0.0"),
            None
        ));
    }

    #[test]
    fn test_pep440_with_pre_release() {
        assert!(pep440_in_range(
            "1.2.3a1",
            Some("1.0.0"),
            Some("2.0.0"),
            None
        ));
        assert!(!pep440_in_range(
            "2.0.0a1",
            Some("1.0.0"),
            Some("2.0.0"),
            None
        ));
    }

    // ─── Go version tests ──────────────────────────────────────────────

    #[test]
    fn test_go_parse_basic() {
        let v = parse_go_version("v1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
        assert!(v.pre.is_none());
    }

    #[test]
    fn test_go_parse_incompatible() {
        let v = parse_go_version("v2.0.0+incompatible").unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_go_parse_pseudo_version() {
        let v = parse_go_version("v1.2.4-20191231235908-abcdef123456").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 4);
        assert!(!v.pre.is_none());
    }

    #[test]
    fn test_go_in_range() {
        assert!(go_in_range("v1.5.0", Some("v1.0.0"), Some("v2.0.0"), None));
        assert!(!go_in_range("v2.0.0", Some("v1.0.0"), Some("v2.0.0"), None));
        assert!(!go_in_range("v0.9.0", Some("v1.0.0"), Some("v2.0.0"), None));
    }

    #[test]
    fn test_go_in_range_incompatible() {
        assert!(go_in_range(
            "v2.0.0+incompatible",
            Some("v1.0.0+incompatible"),
            Some("v3.0.0+incompatible"),
            None
        ));
    }

    #[test]
    fn test_go_pseudo_version_comparison() {
        // Pseudo-version should sort after the base release.
        let release = parse_go_version("v1.2.3").unwrap();
        let pseudo = parse_go_version("v1.2.3-20191231235908-abcdef123456").unwrap();
        assert!(pseudo < release);
    }

    #[test]
    fn test_version_in_range_dispatch() {
        // Semver (default)
        assert!(version_in_range(
            "1.5.0",
            Some("1.0.0"),
            Some("2.0.0"),
            None,
            "npm"
        ));
        assert!(version_in_range(
            "1.5.0",
            Some("1.0.0"),
            Some("2.0.0"),
            None,
            "crates.io"
        ));

        // PEP 440
        assert!(version_in_range(
            "1.5.0",
            Some("1.0.0"),
            Some("2.0.0"),
            None,
            "PyPI"
        ));

        // Go
        assert!(version_in_range(
            "v1.5.0",
            Some("v1.0.0"),
            Some("v2.0.0"),
            None,
            "Go"
        ));
    }
}
