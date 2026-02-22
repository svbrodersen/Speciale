#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::similar_names)]
#![allow(clippy::upper_case_acronyms)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::{
    collections::HashMap,
    ffi::CStr,
    sync::{Mutex, OnceLock, atomic::AtomicUsize},
};

use queues::{IsQueue, Queue, queue};
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};

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
}

struct FIFOCacheSet {
    blocks: Vec<CacheBlock>,
    queue: Queue<usize>,
}

struct RandCacheSet {
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
        for _ in 0..assoc {
            blocks.push(CacheBlock::new(0, false));
        }
        Self {
            blocks,
            rng: StdRng::try_from_rng(&mut SysRng).unwrap(),
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
    block_shift: u64,
    set_mask: usize,
    tag_mask: usize,
    accesses: usize,
    misses: usize,
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
        Cache::<T>::checkParams(blk_size, assoc, cache_size).expect("Bad cache params on creation");
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
    fn getStats(&self) -> (usize, usize);
}

impl<T: CacheSet + 'static> CacheDyn for Cache<T> {
    fn access(&mut self, addr: usize) -> bool {
        Cache::access(self, addr)
    }

    fn getStats(&self) -> (usize, usize) {
        (self.accesses, self.misses)
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
    sys: bool,
    cores: usize,
    limit_insn: usize,

    l1_d_caches: Vec<Mutex<Box<dyn CacheDyn>>>,
    l1_i_caches: Vec<Mutex<Box<dyn CacheDyn>>>,

    l2_u_caches: Vec<Mutex<Box<dyn CacheDyn>>>,
    insn_map: Mutex<HashMap<usize, Box<InsnData>>>,
}

fn build_caches(
    policy: &str,
    cores: usize,
    blk: usize,
    assoc: usize,
    size: usize,
) -> Vec<Mutex<Box<dyn CacheDyn>>> {
    (0..cores)
        .map(|_| {
            let cache: Box<dyn CacheDyn> = match policy {
                "lru" => Box::new(Cache::<LRUCacheSet>::new(blk, assoc, size)),
                "fifo" => Box::new(Cache::<FIFOCacheSet>::new(blk, assoc, size)),
                "rand" => Box::new(Cache::<RandCacheSet>::new(blk, assoc, size)),
                _ => panic!("Unknown policy: {policy}"),
            };
            Mutex::new(cache)
        })
        .collect()
}

// Allow only one initialization of PluginState
static STATE: OnceLock<PluginState> = OnceLock::new();

fn getState() -> &'static PluginState {
    STATE.get().expect("QEMU plugin state not initialized")
}

fn qemu_print(msg: &str) {
    if let Ok(c_str) = std::ffi::CString::new(msg) {
        unsafe { qemu_plugin_outs(c_str.as_ptr()) };
    }
}

#[unsafe(no_mangle)]
pub static qemu_plugin_version: u32 = QEMU_PLUGIN_VERSION;

#[unsafe(no_mangle)]
extern "C" fn vcpu_mem_access(
    vcpu_index: u32,
    info: qemu_plugin_meminfo_t,
    vaddr: u64,
    user_data: *mut std::ffi::c_void,
) {
    let state = getState();

    let hwaddr = unsafe { qemu_plugin_get_hwaddr(info, vaddr) };
    if !hwaddr.is_null() && unsafe { qemu_plugin_hwaddr_is_io(hwaddr) } {
        return;
    }

    let eff_addr = unsafe {
        if hwaddr.is_null() {
            usize::try_from(vaddr).expect("vaddr exceeds usize range")
        } else {
            usize::try_from(qemu_plugin_hwaddr_phys_addr(hwaddr))
                .expect("hwaddr exceeds usize range")
        }
    };

    let cache_idx = (vcpu_index as usize) % state.cores;

    let insn_data =
        unsafe { user_data.cast::<InsnData>().as_ref() }.expect("InsnData pointer was null");
    let hit = state.l1_d_caches[cache_idx]
        .lock()
        .unwrap()
        .access(eff_addr);

    if !hit {
        insn_data
            .l1_dmisses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let l2_hit = state.l2_u_caches[cache_idx]
            .lock()
            .unwrap()
            .access(eff_addr);
        if !l2_hit {
            insn_data
                .l2_misses
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn vcpu_insn_exec(vcpu_index: u32, user_data: *mut std::ffi::c_void) {
    let state = getState();

    let insn_data =
        unsafe { user_data.cast::<InsnData>().as_ref() }.expect("InsnData pointer was null");
    let cache_idx = (vcpu_index as usize) % state.cores;

    let hit = state.l1_i_caches[cache_idx]
        .lock()
        .unwrap()
        .access(insn_data.addr);

    if !hit {
        insn_data
            .l1_imisses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let l2_hit = state.l2_u_caches[cache_idx]
            .lock()
            .unwrap()
            .access(insn_data.addr);
        if !l2_hit {
            insn_data
                .l2_misses
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn vcpu_tb_trans(_id: qemu_plugin_id_t, tb: *mut qemu_plugin_tb) {
    let state = getState();
    let n_insns = unsafe { qemu_plugin_tb_n_insns(tb) };

    for i in 0..n_insns {
        let insn = unsafe { qemu_plugin_tb_get_insn(tb, i) };
        let eff_addr = if state.sys {
            unsafe { qemu_plugin_insn_haddr(insn) as usize }
        } else {
            unsafe {
                usize::try_from(qemu_plugin_insn_vaddr(insn)).expect("vaddr exceeds range of usize")
            }
        };

        let mut map = state.insn_map.lock().unwrap();

        // Use Box to ensure the struct doesn't move in memory when the map resizes.
        let entry = map.entry(insn as usize).or_insert_with(|| {
            let disas_ptr = unsafe { qemu_plugin_insn_disas(insn) };
            let symbol_ptr = unsafe { qemu_plugin_insn_symbol(insn) };

            let disas = if disas_ptr.is_null() {
                String::from("unknown")
            } else {
                unsafe { CStr::from_ptr(disas_ptr).to_string_lossy().into_owned() }
            };

            let symbol = if symbol_ptr.is_null() {
                String::from("unknown")
            } else {
                unsafe { CStr::from_ptr(symbol_ptr).to_string_lossy().into_owned() }
            };

            Box::new(InsnData {
                addr: eff_addr,
                disas,
                symbol,
                l1_imisses: AtomicUsize::new(0),
                l1_dmisses: AtomicUsize::new(0),
                l2_misses: AtomicUsize::new(0),
            })
        });

        let data_ptr = std::ptr::from_ref(entry.as_ref()) as *mut std::ffi::c_void;

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

fn cache_config_error(blksize: usize, assoc: usize, cachesize: usize) -> Result<(), &'static str> {
    if !cachesize.is_multiple_of(blksize) {
        Err("cache size must be divisible by block size")
    } else if !cachesize.is_multiple_of(blksize * assoc) {
        Err("cache size must be divisible by set size (assoc * block size)")
    } else {
        Ok(())
    }
}

/// Install plugin
///
/// # Panics
///
/// Panics if qemu fails to install.
///
/// # Arguments
///
/// * `id` - qemu id
/// * `info` - qemu info
/// * `argc` - qemu num cli arguments
/// * `argv` - qemu cli arguments
///
#[unsafe(no_mangle)]
pub extern "C" fn qemu_plugin_install(
    id: qemu_plugin_id_t,
    info: *const qemu_info_t,
    argc: i32,
    argv: *mut *mut i8,
) -> i32 {
    let info_ref = unsafe { info.as_ref().expect("QEMU passed a null info pointer") };

    let sys = info_ref.system_emulation;
    let mut cores: usize = if sys {
        unsafe {
            usize::try_from(info_ref.__bindgen_anon_1.system.smp_vcpus)
                .expect("smp_vcpus exceeds range of usize")
        }
    } else {
        1
    };

    let mut limit_insn: usize = 32;

    let mut l1_dassoc: usize = 8;
    let mut l1_dblksize: usize = 64;
    let mut l1_dcachesize: usize = l1_dblksize * l1_dassoc * 32;

    let mut l1_iassoc: usize = 8;
    let mut l1_iblksize: usize = 64;
    let mut l1_icachesize: usize = l1_iblksize * l1_iassoc * 32;

    let mut l2_assoc: usize = 16;
    let mut l2_blksize: usize = 64;
    let mut l2_cachesize: usize = l2_assoc * l2_blksize * 2048;

    let mut policy = String::from("lru");

    let args = unsafe { std::slice::from_raw_parts(argv, argc as usize) };
    for &arg_ptr in args {
        let arg_str = unsafe { CStr::from_ptr(arg_ptr) }.to_string_lossy();
        let tokens: Vec<&str> = arg_str.splitn(2, '=').collect();
        let key = tokens[0];
        let val = tokens.get(1).copied().unwrap_or("");

        match key {
            "iblksize" => l1_iblksize = val.parse().unwrap_or(l1_iblksize),
            "iassoc" => l1_iassoc = val.parse().unwrap_or(l1_iassoc),
            "icachesize" => l1_icachesize = val.parse().unwrap_or(l1_icachesize),
            "dblksize" => l1_dblksize = val.parse().unwrap_or(l1_dblksize),
            "dassoc" => l1_dassoc = val.parse().unwrap_or(l1_dassoc),
            "dcachesize" => l1_dcachesize = val.parse().unwrap_or(l1_dcachesize),
            "limit" => limit_insn = val.parse().unwrap_or(limit_insn),
            "cores" => cores = val.parse().unwrap_or(cores),
            "l2cachesize" => {
                l2_cachesize = val.parse().unwrap_or(l2_cachesize);
            }
            "l2blksize" => {
                l2_blksize = val.parse().unwrap_or(l2_blksize);
            }
            "l2assoc" => {
                l2_assoc = val.parse().unwrap_or(l2_assoc);
            }
            "evict" => match val {
                "rand" | "lru" | "fifo" => policy = val.to_string(),
                _ => {
                    eprintln!("invalid eviction policy: {arg_str}");
                    return -1;
                }
            },
            _ => {
                eprintln!("option parsing failed: {arg_str}");
                return -1;
            }
        }
    }

    if let Err(err) = cache_config_error(l1_dblksize, l1_dassoc, l1_dcachesize) {
        eprintln!("dcache cannot be constructed from given parameters");
        eprintln!("{err}");
        return -1;
    }

    if let Err(err) = cache_config_error(l1_iblksize, l1_iassoc, l1_icachesize) {
        eprintln!("icache cannot be constructed from given parameters");
        eprintln!("{err}");
        return -1;
    }

    if let Err(err) = cache_config_error(l2_blksize, l2_assoc, l2_cachesize) {
        eprintln!("L2 cache cannot be constructed from given parameters");
        eprintln!("{err}");
        return -1;
    }

    let state = PluginState {
        sys,
        cores,
        limit_insn,
        l1_d_caches: build_caches(&policy, cores, l1_dblksize, l1_dassoc, l1_dcachesize),
        l1_i_caches: build_caches(&policy, cores, l1_iblksize, l1_iassoc, l1_icachesize),
        l2_u_caches: build_caches(&policy, cores, l2_blksize, l2_assoc, l2_cachesize),
        insn_map: Mutex::new(HashMap::new()),
    };

    STATE
        .set(state)
        .map_err(|_| "State already initialized")
        .unwrap();

    unsafe {
        qemu_plugin_register_vcpu_tb_trans_cb(id, Some(vcpu_tb_trans));
        qemu_plugin_register_atexit_cb(id, Some(plugin_exit), std::ptr::null_mut());
    }

    0
}

use std::fmt::Write;
use std::sync::atomic::Ordering::Relaxed;

#[unsafe(no_mangle)]
extern "C" fn plugin_exit(_id: qemu_plugin_id_t, _user_data: *mut std::ffi::c_void) {
    let state = getState();
    let mut out = String::new();

    writeln!(
        &mut out,
        "core #,  data accesses, data misses, dmiss rate, insn accesses, insn misses, imiss rate, l2 accesses, l2 misses, l2 miss rate"
    ).unwrap();

    let calc_rate = |misses: usize, acc: usize| -> f64 {
        if acc > 0 {
            (misses as f64 / acc as f64) * 100.0
        } else {
            0.0
        }
    };

    let mut format_row = |label: &str, d_acc, d_miss, i_acc, i_miss, l2_acc, l2_miss| {
        let d_rate = calc_rate(d_miss, d_acc);
        let i_rate = calc_rate(i_miss, i_acc);
        let l2_rate = calc_rate(l2_miss, l2_acc);

        writeln!(
            &mut out,
            "{label:<8} {d_acc:<14} {d_miss:<12} {d_rate:>9.4}%  {i_acc:<14} {i_miss:<12} {i_rate:>9.4}%  {l2_acc:<12} {l2_miss:<11} {l2_rate:>10.4}%"
        ).unwrap();
    };

    let (mut t_da, mut t_dm, mut t_ia, mut t_im, mut t_la, mut t_lm) = (0, 0, 0, 0, 0, 0);

    for i in 0..state.cores {
        let (da, dm) = state.l1_d_caches[i].lock().unwrap().getStats();
        let (ia, im) = state.l1_i_caches[i].lock().unwrap().getStats();
        let (la, lm) = state.l2_u_caches[i].lock().unwrap().getStats();

        t_da += da;
        t_dm += dm;
        t_ia += ia;
        t_im += im;
        t_la += la;
        t_lm += lm;

        format_row(&i.to_string(), da, dm, ia, im, la, lm);
    }

    if state.cores > 1 {
        format_row("sum", t_da, t_dm, t_ia, t_im, t_la, t_lm);
    }
    out.push('\n');

    let map = state.insn_map.lock().unwrap();

    let mut insns: Vec<&InsnData> = map.values().map(std::convert::AsRef::as_ref).collect();

    print_insn_table(&mut out, "data misses", &mut insns, state.limit_insn, |i| {
        i.l1_dmisses.load(Relaxed)
    });
    print_insn_table(
        &mut out,
        "fetch misses",
        &mut insns,
        state.limit_insn,
        |i| i.l1_imisses.load(Relaxed),
    );
    print_insn_table(&mut out, "L2 misses", &mut insns, state.limit_insn, |i| {
        i.l2_misses.load(Relaxed)
    });

    qemu_print(&out);
}

fn print_insn_table(
    out: &mut String,
    label: &str,
    insns: &mut [&InsnData],
    limit: usize,
    count_fn: impl Fn(&InsnData) -> usize,
) {
    // Sort the references in place
    insns.sort_by_key(|&b| std::cmp::Reverse(count_fn(b)));
    writeln!(out, "\naddress, {label}, instruction").unwrap();

    for &insn in insns.iter().take(limit).filter(|&&i| count_fn(i) > 0) {
        let sym = if insn.symbol.is_empty() {
            String::new()
        } else {
            format!(" ({})", insn.symbol)
        };

        let misses = count_fn(insn);

        writeln!(out, "{:#x}{sym}, {}, {}", insn.addr, misses, insn.disas).unwrap();
    }
}
