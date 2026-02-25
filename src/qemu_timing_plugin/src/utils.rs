mod s3k;

use crate::{
    GByteArray, g_byte_array_new, g_byte_array_set_size, qemu_plugin_get_registers,
    qemu_plugin_read_register, qemu_plugin_reg_descriptor, qemu_plugin_register,
};
use std::{ffi::CStr, ptr, sync::Mutex};

#[cfg(feature = "s3k")]
pub type ActiveRetriever = S3KDomainRetriever;

#[cfg(feature = "noop")]
pub type ActiveRetriever = NoOpRetriever;

pub trait DomainRetriever: Send + Sync + 'static {
    fn new(cores: usize) -> Self;
    fn get_domain_id(&self, vcpu_index: u32) -> Option<usize>;
}

fn plugin_find_register(name: &str) -> *mut qemu_plugin_register {
    let regs_ref = unsafe {
        qemu_plugin_get_registers()
            .as_ref()
            .expect("QEMU passed a null registers pointer")
    };
    let data = regs_ref.data.cast::<qemu_plugin_reg_descriptor>();

    for i in 0..regs_ref.len {
        let reg = unsafe { data.add(i as usize) };
        let reg_ref = unsafe { reg.as_ref().expect("QEMU reg is null pointer") };
        let reg_name = unsafe { CStr::from_ptr(reg_ref.name).to_str() }.unwrap_or("");
        if reg_name == name {
            return reg_ref.handle;
        }
    }
    ptr::null_mut()
}
struct SendPtr<T>(*mut T);
unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

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

pub struct NoOpRetriever;

impl DomainRetriever for NoOpRetriever {
    fn new(_cores: usize) -> Self {
        Self
    }
    fn get_domain_id(&self, _vcpu_index: u32) -> Option<usize> {
        None
    }
}
