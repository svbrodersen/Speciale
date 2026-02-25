use std::sync::{Mutex, OnceLock};

use crate::{
    GByteArray, g_byte_array_new, g_byte_array_set_size, qemu_plugin_read_register,
    qemu_plugin_register, utils::plugin_find_register,
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
        let reg = self.reg_tp.get()?;
        if reg.0.is_null() {
            return None;
        }

        let cache_idx = (vcpu_index as usize) % self.cpu_buffers.len();
        let guard = self.cpu_buffers[cache_idx].lock().unwrap();
        let buf_ptr = guard.0;

        unsafe {
            g_byte_array_set_size(buf_ptr, 0);

            let success = qemu_plugin_read_register(reg.0, buf_ptr);
            if !success {
                return None;
            }

            let len = (*buf_ptr).len as usize;
            if len == 0 {
                return None;
            }

            let data = std::slice::from_raw_parts((*buf_ptr).data, len);

            if data.iter().any(|&b| b != 0) {
                eprintln!("tp register size: {len}");
                eprintln!("raw bytes: {data:x?}");
            }

            // Read based on actual register width
            let value = match len {
                4 => {
                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(data);
                    u32::from_le_bytes(arr) as usize
                }
                8 => {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(data);
                    u64::from_le_bytes(arr) as usize
                }
                _ => {
                    // Unexpected register size
                    return None;
                }
            };
            Some(value)
        }
    }
}
