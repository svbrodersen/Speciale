use crate::{
    qemu_plugin_get_registers, qemu_plugin_reg_descriptor, qemu_plugin_register,
};
use std::{ffi::CStr, ptr};

#[cfg(feature = "s3k")]
mod s3k;
#[cfg(feature = "s3k")]
pub use self::s3k::S3KDomainRetriever as ActiveRetriever;

#[cfg(not(feature = "retriever"))]
mod noop;
#[cfg(not(feature = "retriever"))]
pub type ActiveRetriever = noop::NoOpRetriever;

pub trait DomainRetriever: Send + Sync + 'static {
    fn new(cores: usize) -> Self;
    fn vcpu_init(&self);
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


