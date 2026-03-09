#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use queues::{IsQueue, Queue, queue};
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Hash)]
pub enum CacheLevel {
    L1DCache,
    L1ICache,
    L2UCache,
    Unknown,
}

pub struct DomainViolation {
    pub orig: usize,
    pub orig_is_kernel: bool,
    pub new: usize,
    pub new_is_kernel: bool,
    pub block_idx: usize,
    pub set_idx: usize,
    pub level: CacheLevel,
}

pub struct CacheBlock {
    tag: usize,
    valid: bool,
    priority: usize,
    cur_domain: Option<(usize, bool)>,
}

pub struct LruPolicy {
    gen_counter: usize,
    priorities: Vec<usize>,
}

pub struct FifoPolicy {
    queue: Queue<usize>,
}

pub struct RandPolicy {
    rng: StdRng,
}

impl RandPolicy {
    pub fn new_with_seed(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
        }
    }
}

pub trait EvictionPolicy: Send {
    fn new(assoc: usize) -> Self;
    fn on_access(&mut self, idx: usize, is_hit: bool);
    fn choose_victim(&mut self, blocks: &[CacheBlock]) -> usize;
    fn reset(&mut self, assoc: usize);
}

pub struct BaseCacheSet<P: EvictionPolicy> {
    blocks: Vec<CacheBlock>,
    policy: P,
}

fn handle_domain(
    domain_option: Option<(usize, bool)>,
    replace_idx: usize,
    block: &mut CacheBlock,
    was_valid: bool,
) -> Option<DomainViolation> {
    let prev_domain = block.cur_domain;
    block.cur_domain = domain_option;
    match (domain_option, prev_domain) {
        (Some((new_domain, new_is_kernel)), Some((prev_domain, prev_is_kernel))) => {
            if was_valid && (prev_domain != new_domain) {
                return Some(DomainViolation {
                    orig: prev_domain,
                    orig_is_kernel: prev_is_kernel,
                    new: new_domain,
                    new_is_kernel,
                    block_idx: replace_idx,
                    set_idx: 0,
                    level: CacheLevel::Unknown,
                });
            }
            None
        }
        _ => None,
    }
}

impl CacheBlock {
    #[must_use]
    pub fn new(tag: usize, valid: bool) -> Self {
        Self {
            tag,
            valid,
            priority: 0,
            cur_domain: None,
        }
    }
}

impl<P: EvictionPolicy> BaseCacheSet<P> {
    fn new(assoc: usize) -> Self {
        let blocks = (0..assoc).map(|_| CacheBlock::new(0, false)).collect();
        let policy = P::new(assoc);
        Self { blocks, policy }
    }

    fn access(
        &mut self,
        tag: usize,
        domain_id: Option<(usize, bool)>,
    ) -> (bool, Option<DomainViolation>) {
        if let Some(idx) = self.blocks.iter().position(|b| b.valid && b.tag == tag) {
            self.policy.on_access(idx, true);

            let block = &mut self.blocks[idx];
            let was_valid = block.valid;
            let violation = handle_domain(domain_id, idx, block, was_valid);
            return (true, violation);
        }

        let replace_idx = self
            .blocks
            .iter()
            .position(|b| !b.valid)
            .unwrap_or_else(|| self.policy.choose_victim(&self.blocks));

        let block = &mut self.blocks[replace_idx];
        let was_valid = block.valid;
        block.tag = tag;
        block.valid = true;

        self.policy.on_access(replace_idx, false);

        (
            false,
            handle_domain(domain_id, replace_idx, block, was_valid),
        )
    }

    pub fn clear(&mut self) {
        for block in &mut self.blocks {
            block.valid = false;
            block.cur_domain = None;
        }
        self.policy.reset(self.blocks.len());
    }
}

impl EvictionPolicy for LruPolicy {
    fn new(assoc: usize) -> Self {
        Self {
            gen_counter: 0,
            priorities: (0..assoc).map(|_| 0).collect(),
        }
    }

    fn on_access(&mut self, idx: usize, _is_hit: bool) {
        self.priorities[idx] = self.gen_counter;
        self.gen_counter += 1;
    }

    fn choose_victim(&mut self, _blocks: &[CacheBlock]) -> usize {
        self.priorities
            .iter()
            .enumerate()
            .min_by_key(|&(_, &p)| p)
            .map_or(0, |(i, _)| i)
    }

    fn reset(&mut self, assoc: usize) {
        self.gen_counter = 0;
        self.priorities = (0..assoc).map(|_| 0).collect();
    }
}

impl EvictionPolicy for RandPolicy {
    fn new(_assoc: usize) -> Self {
        Self {
            rng: StdRng::try_from_rng(&mut SysRng).unwrap(),
        }
    }
    fn on_access(&mut self, _idx: usize, _is_hit: bool) {}
    fn choose_victim(&mut self, blocks: &[CacheBlock]) -> usize {
        self.rng.random_range(0..blocks.len())
    }

    fn reset(&mut self, _assoc: usize) {}
}

impl EvictionPolicy for FifoPolicy {
    fn new(_assoc: usize) -> Self {
        Self { queue: queue![] }
    }
    fn on_access(&mut self, idx: usize, is_hit: bool) {
        if !is_hit {
            let _ = self.queue.add(idx);
        }
    }
    fn choose_victim(&mut self, _blocks: &[CacheBlock]) -> usize {
        self.queue.remove().unwrap_or(0)
    }

    fn reset(&mut self, _assoc: usize) {
        self.queue = queue![];
    }
}

pub struct Cache<P: EvictionPolicy> {
    pub sets: Vec<BaseCacheSet<P>>,
    pub block_shift: u64,
    pub set_mask: usize,
    pub tag_mask: usize,
    pub accesses: usize,
    pub misses: usize,
}

impl<P: EvictionPolicy> Cache<P> {
    fn check_params(blk_size: usize, assoc: usize, cache_size: usize) -> Result<(), String> {
        if !cache_size.is_multiple_of(blk_size) || !cache_size.is_multiple_of(blk_size * assoc) {
            Err("Bad cache parameters".to_string())
        } else {
            Ok(())
        }
    }

    pub fn new(blk_size: usize, assoc: usize, cache_size: usize) -> Cache<P> {
        Cache::<P>::check_params(blk_size, assoc, cache_size)
            .expect("Bad cache params on creation");
        let num_sets = cache_size / (blk_size * assoc);
        let block_shift = u64::from(blk_size.ilog2());
        let blk_mask = blk_size - 1;
        let set_mask = (num_sets - 1) << block_shift;
        let tag_mask = !(set_mask | blk_mask);

        let mut sets = Vec::with_capacity(num_sets);
        for _ in 0..num_sets {
            sets.push(BaseCacheSet::<P>::new(assoc));
        }

        Cache {
            sets,
            block_shift,
            set_mask,
            tag_mask,
            accesses: 0,
            misses: 0,
        }
    }

    fn extract_tag(&self, addr: usize) -> usize {
        addr & self.tag_mask
    }
    fn extract_set(&self, addr: usize) -> usize {
        (addr & self.set_mask) >> self.block_shift
    }

    pub fn access(
        &mut self,
        addr: usize,
        domain_option: Option<(usize, bool)>,
    ) -> (bool, Option<DomainViolation>) {
        let tag = self.extract_tag(addr);
        let set = self.extract_set(addr);
        self.accesses += 1;

        let (hit, domain_violation) = self.sets[set].access(tag, domain_option);

        if !hit {
            self.misses += 1;
        }

        if let Some(mut violation) = domain_violation {
            violation.set_idx = set;
            return (hit, Some(violation));
        }

        (hit, None)
    }

    pub fn clear(&mut self) {
        for set in &mut self.sets {
            set.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_config_valid() -> Result<(), String> {
        Cache::<LruPolicy>::check_params(64, 8, 16384)?;
        Ok(())
    }

    #[test]
    fn test_cache_config_invalid_params() {
        let cases = vec![
            (64, 8, 10000, "Size not multiple of block size"),
            (64, 8, 16000, "Size not multiple of assoc * block size"),
        ];

        for (blk, assoc, size, msg) in cases {
            assert!(
                Cache::<LruPolicy>::check_params(blk, assoc, size).is_err(),
                "Expected error for: {msg}"
            );
        }
    }

    #[test]
    fn test_cache_hit_miss_logic() {
        let mut cache: Cache<LruPolicy> = Cache::new(64, 8, 16384);
        let addr = 0x1000;

        // Initial miss
        let (hit, _) = cache.access(addr, None);
        assert!(!hit, "Initial access to {addr:#x} should be a miss");
        assert_eq!(cache.misses, 1);
        assert_eq!(cache.accesses, 1);

        // Subsequent hit
        let (hit, _) = cache.access(addr, None);
        assert!(hit, "Subsequent access to {addr:#x} should be a hit");
        assert_eq!(cache.misses, 1);
        assert_eq!(cache.accesses, 2);
    }

    #[test]
    fn test_cache_clear_resets_state() {
        let mut cache: Cache<LruPolicy> = Cache::new(64, 8, 16384);
        cache.access(0x1000, None);
        
        assert_eq!(cache.accesses, 1);
        assert_eq!(cache.misses, 1);

        cache.clear();

        // Stats (accesses/misses) are currently preserved by clear() based on implementation,
        // but the cache content should be empty.
        let (hit, _) = cache.access(0x1000, None);
        assert!(!hit, "Access after clear should be a miss");
    }

    #[test]
    fn test_tag_and_set_extraction() {
        let cache: Cache<LruPolicy> = Cache::new(64, 2, 256);
        // 64 byte blocks -> 6 bits for offset
        // 256 bytes total, 2-way assoc -> 2 sets -> 1 bit for set
        // tag is everything else
        
        let addr = 0x1000; // ...0001 0000 0000_0000
        let set = cache.extract_set(addr);
        let tag = cache.extract_tag(addr);

        assert_eq!(set, 0, "Addr {addr:#x} should be in set 0");
        assert!(tag > 0, "Tag should be non-zero for {addr:#x}");
        
        let addr_set1 = 0x1000 + 64;
        assert_eq!(cache.extract_set(addr_set1), 1, "Addr {addr_set1:#x} should be in set 1");
    }

    #[test]
    fn test_lru_policy_internal() {
        let mut cache: Cache<LruPolicy> = Cache::new(64, 2, 128);
        // Set 0 has 2 blocks.
        
        cache.access(0x1000, None); // Miss, fill block 0
        cache.access(0x2000, None); // Miss, fill block 1
        
        // Both blocks full. LRU is block 0.
        // Access block 0 to make it MRU.
        cache.access(0x1000, None); // Hit, block 0 is now MRU
        
        // Access block 2 (addr 0x3000). Should evict block 1 (addr 0x2000).
        cache.access(0x3000, None); 
        
        let (hit_0, _) = cache.access(0x1000, None);
        let (hit_1, _) = cache.access(0x2000, None);
        
        assert!(hit_0, "Address 0x1000 should still be in cache");
        assert!(!hit_1, "Address 0x2000 should have been evicted by LRU");
    }
}
