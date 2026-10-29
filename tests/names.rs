use ct_tiles_watch::names::matches;

#[test]
fn domain_filter_boundaries() {
    assert!(matches("debian.org", "debian.org"));
    assert!(matches("www.debian.org", "debian.org"));
    assert!(matches("*.debian.org", "debian.org"));
    assert!(matches("WWW.Debian.ORG.", "debian.org"));
    assert!(matches("a.b.debian.org", "debian.org."));
    assert!(!matches("notdebian.org", "debian.org"));
    assert!(!matches("debian.org.evil.com", "debian.org"));
    assert!(!matches("debian.or", "debian.org"));
    assert!(!matches("xdebian.org", "debian.org"));
    assert!(!matches("debian.org", "www.debian.org"));
    assert!(!matches("debian-org.com", "debian.org"));
}
