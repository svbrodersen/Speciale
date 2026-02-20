#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::similar_names)]
#![allow(clippy::upper_case_acronyms)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::{
    ffi::CStr,
    sync::{OnceLock, atomic::AtomicUsize},
};

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

trait CacheSet: Send {
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

    fn access(&mut self, addr: usize) -> bool {
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

trait CacheDyn: Send {
    fn access(&mut self, addr: usize) -> bool;
}

impl<T: CacheSet + 'static> CacheDyn for Cache<T> {
    fn access(&mut self, addr: usize) -> bool {
        Cache::access(self, addr)
    }
}

struct InsnData {
    addr: usize,
    disas: String,
    symbol: String,
    l1_imisses: AtomicUsize,
    l1_dmisses: AtomicUsize,
    l2_misses: AtomicUsize,
}

struct PluginState {
    sys: Mutex<bool>,
    cores: Mutex<usize>,

    l1_d_caches: Mutex<Vec<Box<dyn CacheDyn>>>,
    l1_i_caches: Mutex<Vec<Box<dyn CacheDyn>>>,

    l2_u_caches: Mutex<Vec<Box<dyn CacheDyn>>>,
    insn_map: Mutex<HashMap<usize, InsnData>>,
}

// Allow only one initialization of PluginState
static STATE: OnceLock<PluginState> = OnceLock::new();

#[unsafe(no_mangle)]
pub static qemu_plugin_version: u32 = QEMU_PLUGIN_VERSION;

#[unsafe(no_mangle)]
extern "C" fn vcpu_tb_trans(_id: qemu_plugin_id_t, tb: *mut qemu_plugin_tb) {
    let state = match STATE.get() {
        Some(st) => st,
        Err(err) => {
            let msg = sprintf!("No initialized state, err: %s", err);
            panic!(msg);
        }
    };

    let n_insns = unsafe { qemu_plugin_tb_n_insns(tb) };
    for i in 0..n_insns {
        let insn = unsafe { qemu_plugin_tb_get_insn(tb, i) };
        let eff_addr = unsafe {
            if state.sys {
                qemu_plugin_insn_haddr(insn);
            } else {
                qemu_plugin_insn_vaddr(insn);
            };
        };

        {
            let mut map = state.insn_map.lock();

            let entry = map.entry(insn).or_insert_with(|| {
                let disas = unsafe { qemu_plugin_insn_disas(insn) };
                let symbol = unsafe { qemu_plugin_insn_symbol(insn) };
                InsnData {
                    addr: eff_addr,
                    disas: disas,
                    symbol: symbol,
                    l1_imisses: AtomicUsize::new(0),
                    l1_dmisses: AtomicUsize::new(0),
                    l2_misses: AtomicUsize::new(0),
                }
            });
        }
        let data_ptr = entry.as_mut() as *mut _ as *mut std::ffi::c_void;

        unsafe {
            qemu_plugin_register_vcpu_mem_cb(
                insn,
                Some(vcpu_mem_access),
                qemu_plugin_cb_flags_QEMU_PLUGIN_CB_NO_REGS,
                qemu_plugin_mem_rw_QEMU_PLUGIN_MEM_RW,
                data_ptr,
            );

            qemu_plugin_register_vcpu_insn_exec_cb(
                insn,
                Some(vcpu_insn_exec),
                qemu_plugin_cb_flags_QEMU_PLUGIN_CB_NO_REGS,
                data_ptr,
            );
        };
    }
}

#[unsafe(no_mangle)]
extern "C" fn vcpu_mem_access(
    vcpu_index: u32,
    info: qemu_plugin_meminfo_t,
    vaddr: u64,
    user_data: *mut std::ffi::c_void,
) {
    let state = match STATE.get() {
        Some(st) => st,
        Err(err) => {
            let msg = sprintf!("No initialized state, err: %s", err);
            panic!(msg);
        }
    };

    let hwaddr = unsafe { qemu_plugin_get_hwaddr(info, vaddr) };
    if (hwaddr && unsafe { qemu_plugin_hwaddr_is_io(haddr) }) {
        return;
    }

    let eff_addr = unsafe {
        if hwaddr {
            qemu_plugin_hwaddr_phys_addr(insn);
        } else {
            vaddr;
        };
    };

    let cache_idx = (vcpu_index as usize) % state.cores;

    let insn_data = unsafe { &*(userdata as *mut InsnData) };
    let mut hit;

    {
        let mut l1_dcaches = state.l1_d_caches.lock();
        hit = l1_dcaches[cache_idx].access(eff_addr);
        if (!hit) {
            insn_data
                .l1_dmisses
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    if (hit) {
        return;
    }

    {
        let mut l2_ucaches = state.l2_u_caches.lock();
        hit = l2_ucaches[cache_idx].access(eff_addr);
        if (!hit) {
            insn_data
                .l2_misses
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
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
