#![allow(unused_imports)]

use std::fmt::Write;

include!(concat!(env!("OUT_DIR"), "/bindings_s3k.rs"));
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use crate::{
    GByteArray, g_byte_array_new, g_byte_array_set_size,
    qemu_plugin_hwaddr_operation_result_QEMU_PLUGIN_HWADDR_OPERATION_OK,
    qemu_plugin_read_memory_hwaddr, qemu_plugin_read_memory_vaddr, qemu_plugin_read_register,
    qemu_plugin_register, utils::plugin_find_register,
};

use super::{DomainRetriever, SendPtr};

struct VcpuState {
    buf: SendPtr<GByteArray>,
    last_tp: u64,
    last_domain_id: Option<usize>,
}

pub struct S3KDomainRetriever {
    reg_tp: OnceLock<SendPtr<qemu_plugin_register>>,
    reg_mscratch: OnceLock<SendPtr<qemu_plugin_register>>,
    vcpu_states: Vec<Mutex<VcpuState>>,
    tp_to_domain: Mutex<HashMap<u64, Option<usize>>>,
    proc_buf: Mutex<SendPtr<GByteArray>>,
}

impl DomainRetriever for S3KDomainRetriever {
    fn new(cores: usize, _: &str) -> Self {
        let mut vcpu_states = Vec::with_capacity(cores);

        for _ in 0..cores {
            let buf = unsafe { g_byte_array_new() };
            vcpu_states.push(Mutex::new(VcpuState {
                buf: SendPtr(buf),
                last_tp: u64::MAX,
                last_domain_id: None,
            }));
        }

        Self {
            reg_tp: OnceLock::new(),
            reg_mscratch: OnceLock::new(),
            vcpu_states,
            tp_to_domain: Mutex::new(HashMap::new()),
            proc_buf: Mutex::new(SendPtr(unsafe { g_byte_array_new() })),
        }
    }

    fn vcpu_init(&self) {
        self.reg_tp
            .get_or_init(|| SendPtr(plugin_find_register("tp")));
        self.reg_mscratch
            .get_or_init(|| SendPtr(plugin_find_register("mscratch")));
    }

    fn on_exit(&self, _out: &mut String) {}

    fn get_domain_info(&self, vcpu_index: u32, addr: usize) -> Option<(usize, bool)> {
        let cache_idx = (vcpu_index as usize) % self.vcpu_states.len();
        let mut guard = self.vcpu_states[cache_idx].lock().unwrap();
        let buf_ptr = guard.buf.0;

        let is_kernel = self.is_spm_address(addr);

        let read_reg = |handle: *mut qemu_plugin_register| -> Option<u64> {
            if handle.is_null() {
                return None;
            }
            unsafe {
                g_byte_array_set_size(buf_ptr, 0);
                if !qemu_plugin_read_register(handle, buf_ptr) {
                    return None;
                }
                let len = (*buf_ptr).len as usize;
                match len {
                    4 => Some(u64::from(u32::from_le_bytes(
                        *((*buf_ptr).data as *const [u8; 4]),
                    ))),
                    8 => Some(u64::from_le_bytes(*((*buf_ptr).data as *const [u8; 8]))),
                    _ => None,
                }
            }
        };

        let tp_handle = self.reg_tp.get()?.0;
        let mscratch_handle = self.reg_mscratch.get()?.0;

        let mut possible_tps = Vec::new();
        if let Some(val) = read_reg(tp_handle) {
            possible_tps.push(val);
        }
        if let Some(val) = read_reg(mscratch_handle) {
            possible_tps.push(val);
        }

        for tp_val in possible_tps {
            if tp_val == 0 {
                continue;
            }

            if tp_val == guard.last_tp {
                return guard.last_domain_id.map(|id| (id, is_kernel));
            }

            // Check global cache
            if let Some(&domain_id) = self.tp_to_domain.lock().unwrap().get(&tp_val) {
                if domain_id.is_some() {
                    guard.last_tp = tp_val;
                    guard.last_domain_id = domain_id;
                    return domain_id.map(|id| (id, is_kernel));
                }
            }

            // Slow path: read memory
            let domain_id = unsafe {
                let proc_size = std::mem::size_of::<proc_t>();

                let mutex_guard = self.proc_buf.lock().unwrap();
                let proc_buf = mutex_guard.0;
                g_byte_array_set_size(proc_buf, proc_size as u32);

                let succ = qemu_plugin_read_memory_vaddr(tp_val, proc_buf, proc_size);

                if succ {
                    let proc_ptr = (*proc_buf).data as *const proc_t;
                    let pid = std::ptr::read_unaligned(std::ptr::addr_of!((*proc_ptr).pid));
                    usize::try_from(pid).ok()
                } else {
                    g_byte_array_set_size(proc_buf, proc_size as u32);
                    let succ_hw = qemu_plugin_read_memory_hwaddr(tp_val, proc_buf, proc_size);

                    if succ_hw
                        == qemu_plugin_hwaddr_operation_result_QEMU_PLUGIN_HWADDR_OPERATION_OK
                    {
                        let proc_ptr = (*proc_buf).data as *const proc_t;
                        let pid = std::ptr::read_unaligned(std::ptr::addr_of!((*proc_ptr).pid));
                        usize::try_from(pid).ok()
                    } else {
                        None
                    }
                }
            };

            if domain_id.is_some() {
                self.tp_to_domain.lock().unwrap().insert(tp_val, domain_id);
                guard.last_tp = tp_val;
                guard.last_domain_id = domain_id;
                return domain_id.map(|id| (id, is_kernel));
            } 
            // We tried to read from this pointer and it wasn't a valid proc_t (memory access failed or pid invalid)
            // Cache the failure so we don't repeatedly fail on user TP
            self.tp_to_domain.lock().unwrap().insert(tp_val, None);
        }

        // If neither `tp` nor `mscratch` points to a valid proc_t, we just fall back to the last known domain
        guard.last_domain_id.map(|id| (id, is_kernel))
    }

    /// Check if an address is in a scratchpad memory (SPM) region.
    /// For S3K, the kernel resides in SPM which bypasses L2 cache.
    /// QEMU: Kernel at 0x90000000-0x90010000 (64KB)
    fn is_spm_address(&self, addr: usize) -> bool {
        // QEMU virt platform kernel region
        const QEMU_KERNEL_START: usize = 0x9000_0000;
        const QEMU_KERNEL_END: usize = 0x9001_0000;

        (QEMU_KERNEL_START..QEMU_KERNEL_END).contains(&addr)
    }
}

// Check for temporal_fence instruction (magic NOP)
// RISC-V: addi x0, x0, 11 = 0x00b00013
// This is a NOP (x0 hardwired to 0) but we use it as a fence marker
pub fn is_temporal_fence(insn_opcode: u64) -> bool {
    insn_opcode == 0x00b0_0013
}
