#![allow(unused_imports, non_snake_case)]

use std::{
    collections::HashMap,
    fs,
    sync::{Mutex, OnceLock},
};

include!(concat!(env!("OUT_DIR"), "/bindings_FreeRTOS.rs"));

use object::{Object, ObjectSymbol};

use crate::{
    GByteArray, g_byte_array_new, g_byte_array_set_size,
    qemu_plugin_hwaddr_operation_result_QEMU_PLUGIN_HWADDR_OPERATION_OK,
    qemu_plugin_read_memory_hwaddr, qemu_plugin_read_memory_vaddr, qemu_plugin_read_register,
    qemu_plugin_register, utils::plugin_find_register,
};

use super::{DomainRetriever, SendPtr};

pub struct FreeRTOSDomainRetriever {
    proc_buf: Mutex<SendPtr<GByteArray>>,
    var_current_tcb_addr: u64,
    cores: usize,
}

impl DomainRetriever for FreeRTOSDomainRetriever {
    fn new(cores: usize, elf_path: &str) -> Self {
        let bin_data = fs::read(elf_path).unwrap();

        let elf_file = object::File::parse(&*bin_data).unwrap();

        let symbol = elf_file
            .symbols()
            .find(|sym| sym.name() == Ok("pxCurrentTCB"));

        match symbol {
            Some(sym) => Self {
                cores,
                proc_buf: Mutex::new(SendPtr(unsafe { g_byte_array_new() })),
                var_current_tcb_addr: sym.address(),
            },
            None => panic!("Unable to find pxCurrentTCB in elf file"),
        }
    }

    fn vcpu_init(&self) {}

    fn on_exit(&self, _out: &mut String) {}

    // Currently only handle single CPU, so no cpu index
    fn get_domain_info(&self, _vcpu_index: u32, _addr: usize) -> Option<(usize, bool)> {
        static TCB_PRINT_ONCE: OnceLock<()> = OnceLock::new();
        static TCB_STRUCT_PRINT_ONCE: OnceLock<()> = OnceLock::new();
        static TCB: OnceLock<()> = OnceLock::new();
        let mutex_guard = self.proc_buf.lock().unwrap();
        let proc_buf = mutex_guard.0;

        if TCB.set(()).is_ok() {
            println!("pxCurrentTCB: {:x?}", self.var_current_tcb_addr);
        }

        let read_to_buf = |guest_addr: u64, size: usize| -> bool {
            unsafe {
                if proc_buf.is_null() {
                    return false;
                }
                g_byte_array_set_size(proc_buf, size as u32);
                qemu_plugin_read_memory_vaddr(guest_addr, proc_buf, size)
            }
        };

        // 2. Read the pointer to the TCB (Assuming it's a 32-bit pointer based on your '4' arg)
        if read_to_buf(self.var_current_tcb_addr, 4) {
            let tcb_guest_addr =
                unsafe { u32::from_le_bytes(*((*proc_buf).data as *const [u8; 4])) as u64 };

            if tcb_guest_addr == 0 {
                return None;
            }

            if TCB_PRINT_ONCE.set(()).is_ok() {
                println!("tcb_guest_addr: {tcb_guest_addr:x}");
            }

            // 3. Now read the actual TCB struct from the guest
            let tcb_size = std::mem::size_of::<TCB_t>();
            if read_to_buf(tcb_guest_addr, tcb_size) {
                if TCB_STRUCT_PRINT_ONCE.set(()).is_ok() {
                    unsafe { println!("TCB_Struct: {:?}", (*proc_buf).data) };
                }
                let tcb_struct = unsafe { &*((*proc_buf).data as *const TCB_t) };

                return Some((tcb_struct.uxTCBNumber as usize, false));
            }
        }
        None
    }

    /// Check if an address is in a scratchpad memory (SPM) region.
    /// For FreeRTOS, there is no distinction
    fn is_spm_address(&self, _addr: usize) -> bool {
        return false;
    }
}

// Check for temporal_fence instruction (magic NOP)
// RISC-V: addi x0, x0, 11 = 0x00b00013
// This is a NOP (x0 hardwired to 0) but we use it as a fence marker
pub fn is_temporal_fence(insn_opcode: u64) -> bool {
    insn_opcode == 0x00b0_0013
}
