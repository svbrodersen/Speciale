#![allow(unused_imports)]

use std::fmt::Write;

include!(concat!(env!("OUT_DIR"), "/bindings_s3k.rs"));
use std::{
    collections::HashSet,
    sync::{Mutex, OnceLock},
};

use crate::{
    GByteArray, g_byte_array_new, g_byte_array_set_size,
    qemu_plugin_hwaddr_operation_result_QEMU_PLUGIN_HWADDR_OPERATION_OK,
    qemu_plugin_read_memory_hwaddr, qemu_plugin_read_memory_vaddr, qemu_plugin_read_register,
    qemu_plugin_register, utils::plugin_find_register,
};

use super::{DomainRetriever, SendPtr};

pub struct S3KDomainRetriever {
    reg_tp: OnceLock<SendPtr<qemu_plugin_register>>,
    cpu_buffers: Vec<Mutex<SendPtr<GByteArray>>>,
    proc_buf: Mutex<SendPtr<GByteArray>>,
    unique_domain_tp: Mutex<HashSet<(usize, u64)>>,
}

impl DomainRetriever for S3KDomainRetriever {
    fn new(cores: usize) -> Self {
        let mut cpu_buffers = Vec::with_capacity(cores);

        for _ in 0..cores {
            let buf = unsafe { g_byte_array_new() };
            cpu_buffers.push(Mutex::new(SendPtr(buf)));
        }

        Self {
            reg_tp: OnceLock::new(),
            cpu_buffers,
            proc_buf: Mutex::new(SendPtr(unsafe { g_byte_array_new() })),
            unique_domain_tp: Mutex::new(HashSet::new()),
        }
    }

    fn vcpu_init(&self) {
        self.reg_tp
            .get_or_init(|| SendPtr(plugin_find_register("tp")));
    }

    fn on_exit(&self, out: &mut String) {
        writeln!(
            out,
            "Unique_domain_tp: {:?}",
            self.unique_domain_tp.lock().unwrap()
        ).unwrap();
    }

    fn get_domain_id(&self, vcpu_index: u32) -> Option<usize> {
        let tp_handle = self.reg_tp.get()?.0;
        if tp_handle.is_null() {
            return None;
        }

        let cache_idx = (vcpu_index as usize) % self.cpu_buffers.len();
        let guard = self.cpu_buffers[cache_idx].lock().unwrap();
        let buf_ptr = guard.0;

        unsafe {
            // Read tp
            g_byte_array_set_size(buf_ptr, 0);
            if !qemu_plugin_read_register(tp_handle, buf_ptr) {
                return None;
            }

            let len = (*buf_ptr).len as usize;
            let tp_val = match len {
                4 => u64::from(u32::from_le_bytes(*((*buf_ptr).data as *const [u8; 4]))),
                8 => u64::from_le_bytes(*((*buf_ptr).data as *const [u8; 8])),
                _ => return None,
            };

            if tp_val == 0 {
                return None;
            }

            let proc_size = std::mem::size_of::<proc_t>();

            let mutex_guard = self.proc_buf.lock().unwrap();
            let proc_buf = mutex_guard.0;
            g_byte_array_set_size(proc_buf, proc_size as u32);

            let succ = qemu_plugin_read_memory_vaddr(tp_val, proc_buf, proc_size);

            if !succ {
                g_byte_array_set_size(proc_buf, proc_size as u32);
                let succ_hw = qemu_plugin_read_memory_hwaddr(tp_val, proc_buf, proc_size);

                if succ_hw != qemu_plugin_hwaddr_operation_result_QEMU_PLUGIN_HWADDR_OPERATION_OK {
                    return None;
                }
            }

            let proc_ptr = (*buf_ptr).data as *const proc_t;
            let pid = std::ptr::read_unaligned(std::ptr::addr_of!((*proc_ptr).pid));

            if let Ok(domain_id) = usize::try_from(pid) {
                let mut set = self.unique_domain_tp.lock().unwrap();
                set.insert((domain_id, tp_val));
                Some(domain_id)
            } else {
                None
            }
        }
    }
}
