use qemu_timing_plugin::cache::{Cache, CacheLevel, FifoPolicy, LruPolicy, RandPolicy};

#[test]
fn test_fifo_eviction_scenario() {
    let mut cache: Cache<FifoPolicy> = Cache::new(64, 2, 128); // 1 set, 2 blocks

    cache.access(0x1000, None); // Block A
    cache.access(0x2000, None); // Block B

    // FIFO should evict A regardless of subsequent hits to A
    cache.access(0x1000, None); // Hit A

    cache.access(0x3000, None); // Should evict A

    let (hit_a, _) = cache.access(0x1000, None);
    assert!(!hit_a, "0x1000 should have been evicted by 0x3000");

    // Now the queue is [B, C]. Re-accessing A (miss) will evict B (FIFO).
    let (hit_b, _) = cache.access(0x2000, None);
    assert!(
        !hit_b,
        "Block 0x2000 should have been evicted by the re-access of 0x1000"
    );
}

#[test]
fn test_domain_violation_flow() {
    let mut cache: Cache<LruPolicy> = Cache::new(64, 8, 16384);
    let addr = 0x1000;

    // 1. Initial access by Domain 1
    cache.access(addr, Some((1, false)));

    // 2. Access by Domain 2 - Should trigger violation
    let (hit, violation) = cache.access(addr, Some((2, false)));
    assert!(hit, "Should be a hit because the data is in cache");

    let vio = violation.expect("Expected a domain violation");
    assert_eq!(vio.orig, 1);
    assert_eq!(vio.new, 2);
    assert!(!vio.orig_is_kernel);
    assert!(!vio.new_is_kernel);
    assert_eq!(vio.level, CacheLevel::Unknown);

    // 3. Kernel flag test
    cache.clear();
    cache.access(addr, Some((1, true))); // Kernel domain
    let (_, violation) = cache.access(addr, Some((2, false)));
    let vio = violation.expect("Expected violation from kernel domain");
    assert!(vio.orig_is_kernel);
}

#[test]
fn test_temporal_safety_with_no_domain() {
    let mut cache: Cache<LruPolicy> = Cache::new(64, 8, 16384);
    let addr = 0x1000;

    // If no domain tracking is used, no violations should occur
    cache.access(addr, None);
    let (_, violation) = cache.access(addr, Some((1, false)));
    assert!(
        violation.is_none(),
        "No violation should occur if previous access had no domain"
    );
}

#[test]
fn test_multiple_set_mapping() {
    let mut cache: Cache<LruPolicy> = Cache::new(64, 1, 256); // 4 sets

    // Access 4 different sets
    for i in 0..4 {
        let addr = i * 64;
        let (hit, _) = cache.access(addr, None);
        assert!(!hit, "Initial access to set {i} should miss");
    }

    assert_eq!(cache.misses, 4);

    // Verify they are all still there
    for i in 0..4 {
        let addr = i * 64;
        let (hit, _) = cache.access(addr, None);
        assert!(hit, "Block in set {i} should still be present");
    }
}

#[test]
fn test_rand_eviction_distribution() {
    // Since Rand is pseudo-random, we just verify it doesn't crash
    // and produces some evictions under pressure.
    let mut cache: Cache<RandPolicy> = Cache::new(64, 2, 128); // 1 set, 2 ways

    cache.access(0x1000, None);
    cache.access(0x2000, None);
    cache.access(0x3000, None); // Must evict something

    assert_eq!(cache.misses, 3);
    let (h1, _) = cache.access(0x1000, None);
    let (h2, _) = cache.access(0x2000, None);

    // One of them must have been evicted
    assert!(!(h1 && h2), "At least one block should have been evicted");
}
