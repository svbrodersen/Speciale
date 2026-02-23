#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]


use queues::{IsQueue, Queue, queue};
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};

pub struct CacheBlock {
    tag: usize,
    valid: bool,
    priority: usize,
}

impl CacheBlock {
    pub fn new(tag: usize, valid: bool) -> Self {
        Self {
            tag,
            valid,
            priority: 0,
        }
    }
}

pub struct LRUCacheSet {
    blocks: Vec<CacheBlock>,
    gen_counter: usize,
}

pub struct FIFOCacheSet {
    blocks: Vec<CacheBlock>,
    queue: Queue<usize>,
}

pub struct RandCacheSet {
    blocks: Vec<CacheBlock>,
    rng: StdRng,
}

impl CacheSet for LRUCacheSet {
    fn new(assoc: usize) -> Self {
        let mut blocks = Vec::with_capacity(assoc);
        for _ in 0..assoc {
            blocks.push(CacheBlock::new(0, false));
        }
        Self {
            blocks,
            gen_counter: 0,
        }
    }

    fn access(&mut self, tag: usize, domain_id: Option<usize>) -> bool {
        if let Some(block) = self.blocks.iter_mut().find(|b| b.valid && b.tag == tag) {
            block.priority = self.gen_counter;
            self.gen_counter += 1;
            return true;
        }

        let mut replace_idx = 0;
        let mut min_priority = usize::MAX;

        for (i, block) in self.blocks.iter().enumerate() {
            if !block.valid {
                replace_idx = i;
                break;
            }
            if block.priority < min_priority {
                min_priority = block.priority;
                replace_idx = i;
            }
        }

        let block = &mut self.blocks[replace_idx];
        block.tag = tag;
        block.valid = true;
        block.priority = self.gen_counter;
        self.gen_counter += 1;

        false
    }
}

impl CacheSet for FIFOCacheSet {
    fn new(assoc: usize) -> Self {
        let mut blocks = Vec::with_capacity(assoc);
        for _ in 0..assoc {
            blocks.push(CacheBlock::new(0, false));
        }
        Self {
            blocks,
            queue: queue![],
        }
    }

    fn access(&mut self, tag: usize, domain_id: Option<usize>) -> bool {
        if self.blocks.iter().any(|b| b.valid && b.tag == tag) {
            return true;
        }

        let replace_idx: usize;

        let invalid_pos = self.blocks.iter().position(|b| !b.valid);
        if let Some(pos) = invalid_pos {
            replace_idx = pos;
        } else {
            replace_idx = self.queue.remove().unwrap_or(0);
        }

        let block = &mut self.blocks[replace_idx];
        block.tag = tag;
        block.valid = true;

        let _ = self.queue.add(replace_idx);

        false
    }
}

impl CacheSet for RandCacheSet {
    fn new(assoc: usize) -> Self {
        let mut blocks = Vec::with_capacity(assoc);
        for _ in 0..assoc {
            blocks.push(CacheBlock::new(0, false));
        }
        Self {
            blocks,
            rng: StdRng::try_from_rng(&mut SysRng).unwrap(),
        }
    }

    fn access(&mut self, tag: usize, domain_id: Option<usize>) -> bool {
        if self.blocks.iter().any(|b| b.valid && b.tag == tag) {
            return true;
        }

        let replace_idx: usize;

        let invalid_pos = self.blocks.iter().position(|b| !b.valid);
        if let Some(pos) = invalid_pos {
            replace_idx = pos;
        } else {
            replace_idx = self.rng.random_range(0..self.blocks.len());
        }

        let block = &mut self.blocks[replace_idx];
        block.tag = tag;
        block.valid = true;

        false
    }
}

pub trait CacheSet: Send {
    fn new(assoc: usize) -> Self;
    fn access(&mut self, tag: usize, domain_id: Option<usize>) -> bool;
}

pub struct Cache<T: CacheSet> {
    pub sets: Vec<T>,
    pub block_shift: u64,
    pub set_mask: usize,
    pub tag_mask: usize,
    pub accesses: usize,
    pub misses: usize,
}

impl<T: CacheSet> Cache<T> {
    fn check_params(blk_size: usize, assoc: usize, cache_size: usize) -> Result<(), String> {
        if !cache_size.is_multiple_of(blk_size) || !cache_size.is_multiple_of(blk_size * assoc) {
            Err("Bad cache parameters".to_string())
        } else {
            Ok(())
        }
    }

    pub fn new(blk_size: usize, assoc: usize, cache_size: usize) -> Cache<T> {
        Cache::<T>::check_params(blk_size, assoc, cache_size).expect("Bad cache params on creation");
        let num_sets = cache_size / (blk_size * assoc);
        let block_shift = (blk_size as f64).log2() as u64;
        let blk_mask = blk_size - 1;
        let set_mask = (num_sets - 1) << block_shift;
        let tag_mask = !(set_mask | blk_mask);

        let mut sets = Vec::with_capacity(num_sets);
        for _ in 0..num_sets {
            sets.push(T::new(assoc));
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

    pub fn access(&mut self, addr: usize, domain_id: Option<usize>) -> bool {
        let tag = self.extract_tag(addr);
        let set = self.extract_set(addr);
        self.accesses += 1;

        let hit = self.sets[set].access(tag, domain_id);

        if !hit {
            self.misses += 1;
        }

        hit
    }
}

