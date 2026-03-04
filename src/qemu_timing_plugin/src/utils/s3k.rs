#![allow(unused_imports)]

use std::fmt::Write;

include!(concat!(env!("OUT_DIR"), "/bindings_s3k.rs"));
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use crate::{
    g_byte_array_new, g_byte_array_set_size,
    qemu_plugin_hwaddr_operation_result_QEMU_PLUGIN_HWADDR_OPERATION_OK,
    qemu_plugin_read_memory_hwaddr, qemu_plugin_read_memory_vaddr, qemu_plugin_read_register,
    qemu_plugin_register, utils::plugin_find_register, GByteArray,
};

use super::{DomainRetriever, SendPtr};

struct VcpuState {
    buf: SendPtr<GByteArray>,
    last_tp: u64,
    last_domain_id: Option<usize>,
}

pub struct S3KDomainRetriever {
    reg_tp: OnceLock<SendPtr<qemu_plugin_register>>,
    vcpu_states: Vec<Mutex<VcpuState>>,
    tp_to_domain: Mutex<HashMap<u64, Option<usize>>>,
    proc_buf: Mutex<SendPtr<GByteArray>>,
}

impl DomainRetriever for S3KDomainRetriever {
    fn new(cores: usize) -> Self {
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
            vcpu_states,
            tp_to_domain: Mutex::new(HashMap::new()),
            proc_buf: Mutex::new(SendPtr(unsafe { g_byte_array_new() })),
        }
    }

    fn vcpu_init(&self) {
        self.reg_tp
            .get_or_init(|| SendPtr(plugin_find_register("tp")));
    }

    fn on_exit(&self, _out: &mut String) {}

    fn get_domain_id(&self, vcpu_index: u32) -> Option<usize> {
        let tp_handle = self.reg_tp.get()?.0;
        if tp_handle.is_null() {
            return None;
        }

        let cache_idx = (vcpu_index as usize) % self.vcpu_states.len();
        let mut guard = self.vcpu_states[cache_idx].lock().unwrap();
        let buf_ptr = guard.buf.0;

        let tp_val = unsafe {
            g_byte_array_set_size(buf_ptr, 0);
            if !qemu_plugin_read_register(tp_handle, buf_ptr) {
                return None;
            }

            let len = (*buf_ptr).len as usize;
            match len {
                4 => u64::from(u32::from_le_bytes(*((*buf_ptr).data as *const [u8; 4]))),
                8 => u64::from_le_bytes(*((*buf_ptr).data as *const [u8; 8])),
                _ => return None,
            }
        };

        if tp_val == 0 {
            return None;
        }

        if tp_val == guard.last_tp {
            return guard.last_domain_id;
        }

        // Check global cache, in case we have already seen
        if let Some(&domain_id) = self.tp_to_domain.lock().unwrap().get(&tp_val) {
            guard.last_tp = tp_val;
            guard.last_domain_id = domain_id;
            return domain_id;
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

                if succ_hw != qemu_plugin_hwaddr_operation_result_QEMU_PLUGIN_HWADDR_OPERATION_OK {
                    None
                } else {
                    let proc_ptr = (*proc_buf).data as *const proc_t;
                    let pid = std::ptr::read_unaligned(std::ptr::addr_of!((*proc_ptr).pid));
                    usize::try_from(pid).ok()
                }
            }
        };

        self.tp_to_domain.lock().unwrap().insert(tp_val, domain_id);
        guard.last_tp = tp_val;
        guard.last_domain_id = domain_id;
        domain_id
    }
}
