#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::similar_names)]
#![allow(clippy::upper_case_acronyms)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::ffi::CStr;

use queues::{IsQueue, Queue, queue};
use rand::RngExt;

struct CacheBlock {
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

struct LRUCacheSet {
    blocks: Vec<CacheBlock>,
    gen_counter: usize,
    assoc: usize,
}

struct FIFOCacheSet {
    blocks: Vec<CacheBlock>,
    queue: Queue<usize>,
    assoc: usize,
}

struct RandCacheSet {
    blocks: Vec<CacheBlock>,
    assoc: usize,
    rng: rand::rngs::ThreadRng,
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
            assoc,
        }
    }
    fn access(&mut self, tag: usize) -> bool {
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
            assoc,
        }
    }

    fn access(&mut self, tag: usize) -> bool {
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
        for _ in 0..blocks.len() {
            blocks.push(CacheBlock::new(0, false));
        }
        Self {
            blocks,
            assoc,
            rng: rand::rng(),
        }
    }

    fn access(&mut self, tag: usize) -> bool {
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

trait CacheSet {
    fn new(assoc: usize) -> Self;
    fn access(&mut self, tag: usize) -> bool;
}

struct Cache<T: CacheSet> {
    sets: Vec<T>,
    size: usize,
    assoc: usize,
    block_shift: u64,
    set_mask: usize,
    tag_mask: usize,
    accesses: u64,
    misses: u64,
}

impl<T: CacheSet> Cache<T> {
    fn checkParams(blk_size: usize, assoc: usize, cache_size: usize) -> Result<(), String> {
        if !cache_size.is_multiple_of(blk_size) || !cache_size.is_multiple_of(blk_size * assoc) {
            Err("Bad cache parameters".to_string())
        } else {
            Ok(())
        }
    }

    pub fn new(blk_size: usize, assoc: usize, cache_size: usize) -> Cache<T> {
        Cache::<T>::checkParams(blk_size, assoc, cache_size);
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
            size: cache_size,
            assoc,
            block_shift,
            set_mask,
            tag_mask,
            accesses: 0,
            misses: 0,
        }
    }

    fn extractTag(&self, addr: usize) -> usize {
        addr & self.tag_mask
    }
    fn extractSet(&self, addr: usize) -> usize {
        (addr & self.set_mask) >> self.block_shift
    }

    fn accessCache(&mut self, addr: usize) -> bool {
        let tag = self.extractTag(addr);
        let set = self.extractSet(addr);
        self.accesses += 1;

        let hit = self.sets[set].access(tag);

        if !hit {
            self.misses += 1;
        }

        hit
    }
}

#[unsafe(no_mangle)]
pub static qemu_plugin_version: u32 = QEMU_PLUGIN_VERSION;

#[unsafe(no_mangle)]
extern "C" fn vcpu_init_callback(_id: qemu_plugin_id_t, vcpu_index: u32) {
    println!("Rust Plugin: vCPU {vcpu_index} initialized!");
}

#[unsafe(no_mangle)]
pub extern "C" fn qemu_plugin_install(
    id: qemu_plugin_id_t,
    _info: *const qemu_info_t,
    argc: i32,
    argv: *mut *mut i8,
) -> i32 {
    println!("Rust Plugin: Loaded successfully!");

    if argc > 0
        && let Some(first) = unsafe { argv.as_ref() }
        && !first.is_null()
    {
        let first_arg = unsafe { CStr::from_ptr(*first) }.to_string_lossy();
        println!("Rust Plugin: Received argument: {first_arg}");
    }

    unsafe {
        qemu_plugin_register_vcpu_init_cb(id, Some(vcpu_init_callback));
    }

    0
}
