use std::sync::Mutex;

use crate::{GByteArray, g_byte_array_new, g_byte_array_set_size, qemu_plugin_read_register, qemu_plugin_register, utils::plugin_find_register};

use super::{DomainRetriever, SendPtr};

pub struct S3KDomainRetriever {
    reg_tp: SendPtr<qemu_plugin_register>,
    cpu_buffers: Vec<Mutex<SendPtr<GByteArray>>>,
}

impl DomainRetriever for S3KDomainRetriever {
    fn new(cores: usize) -> Self {
        let reg = plugin_find_register("tp");
        let mut cpu_buffers = Vec::with_capacity(cores);

        for _ in 0..cores {
            let buf = unsafe { g_byte_array_new() };
            cpu_buffers.push(Mutex::new(SendPtr(buf)));
        }

        Self {
            reg_tp: SendPtr(reg),
            cpu_buffers,
        }
    }

    fn get_domain_id(&self, vcpu_index: u32) -> Option<usize> {
        if self.reg_tp.0.is_null() {
            return None;
        }

        let cache_idx = (vcpu_index as usize) % self.cpu_buffers.len();
        let guard = self.cpu_buffers[cache_idx].lock().unwrap();
        let buf_ptr = guard.0;

        unsafe {
            g_byte_array_set_size(buf_ptr, 0);
            let success = qemu_plugin_read_register(self.reg_tp.0, buf_ptr);

            if success {
                // Cast the data pointer of GByteArray to u64
                let data_ptr = (*buf_ptr).data as *const u64;
                if !data_ptr.is_null() {
                    return Some(usize::try_from(*data_ptr).expect("Failed to cast u64 to usize"));
                }
            }
        }
        None
    }
}
