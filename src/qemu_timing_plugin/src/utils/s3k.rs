use std::sync::{Mutex, OnceLock};

use crate::{
    GByteArray, g_byte_array_new, g_byte_array_set_size, 
    qemu_plugin_read_register, qemu_plugin_register, utils::plugin_find_register,
};

use super::{DomainRetriever, SendPtr};

pub struct S3KDomainRetriever {
    reg_tp: OnceLock<SendPtr<qemu_plugin_register>>,
    cpu_buffers: Vec<Mutex<SendPtr<GByteArray>>>,
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
        }
    }

    fn vcpu_init(&self) {
        self.reg_tp
            .get_or_init(|| SendPtr(plugin_find_register("tp")));
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
            if len == 0 {
                return None;
            }

            let tp_data = std::slice::from_raw_parts((*buf_ptr).data, len);
            let tp_val = if len == 4 {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(tp_data);
                u64::from(u32::from_le_bytes(arr))
            } else if len == 8 {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(tp_data);
                u64::from_le_bytes(arr)
            } else {
                return None;
            };

            // Have to read from memory of this location to proc_t type and then get PID
            if tp_val != 0 {
                println!("tp_val: {tp_val}");
            }

            None
        }
    }
}
