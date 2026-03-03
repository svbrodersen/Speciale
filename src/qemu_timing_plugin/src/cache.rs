#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use queues::{queue, IsQueue, Queue};
use rand::{
    rngs::{StdRng, SysRng},
    RngExt, SeedableRng,
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
    pub new: usize,
    pub block_idx: usize,
    pub set_idx: usize,
    pub level: CacheLevel,
}

pub struct CacheBlock {
    tag: usize,
    valid: bool,
    priority: usize,
    cur_domain: Option<usize>,
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
    domain_option: Option<usize>,
    replace_idx: usize,
    block: &mut CacheBlock,
    was_valid: bool,
) -> Option<DomainViolation> {
    // Only update domain if available
    let prev_domain = block.cur_domain;
    block.cur_domain = domain_option;
    match (domain_option, prev_domain) {
        (Some(domain_id), Some(prev_domain)) => {
            // Only trigger a violation if the block was previously valid and the domain changed
            if was_valid && (prev_domain != domain_id) {
                return Some(DomainViolation {
                    orig: prev_domain,
                    new: domain_id,
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

    fn access(&mut self, tag: usize, domain_id: Option<usize>) -> (bool, Option<DomainViolation>) {
        if let Some(idx) = self.blocks.iter().position(|b| b.valid && b.tag == tag) {
            self.policy.on_access(idx, false);

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

        self.policy.on_access(replace_idx, true);

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
            // Find minimum priority
            .min_by_key(|&(_, &p)| p)
            // Get index
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
    fn new(assoc: usize) -> Self {
        let mut q = queue![];
        for i in 0..assoc {
            let _ = q.add(i);
        }
        Self { queue: q }
    }
    fn on_access(&mut self, idx: usize, is_hit: bool) {
        if !is_hit {
            let _ = self.queue.add(idx);
        }
    }
    fn choose_victim(&mut self, _blocks: &[CacheBlock]) -> usize {
        self.queue.remove().unwrap_or(0)
    }

    fn reset(&mut self, assoc: usize) {
        let mut q = queue![];
        for i in 0..assoc {
            let _ = q.add(i);
        }
        self.queue = q;
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
        domain_option: Option<usize>,
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
