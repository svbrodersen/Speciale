#![allow(unused_imports, non_snake_case)]

use std::{
    collections::HashMap,
    fs,
    sync::{Mutex, OnceLock},
};

use std::borrow::Cow;

use object::{Object, ObjectSection, ObjectSymbol};

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
    ux_tcb_number_offset: u64,
}

impl FreeRTOSDomainRetriever {
    fn get_struct_field_offset(
        _elf_data: &[u8],
        _struct_name: &str,
        _field_name: &str,
    ) -> Option<u64> {
        Some(64)
    }
}

impl DomainRetriever for FreeRTOSDomainRetriever {
    fn new(cores: usize, elf_path: &str) -> Self {
        let bin_data = fs::read(elf_path).unwrap();

        let elf_file = object::File::parse(&*bin_data).unwrap();

        let symbol = elf_file
            .symbols()
            .find(|sym| sym.name() == Ok("pxCurrentTCB"));

        let offset = Self::get_struct_field_offset(&bin_data, "tskTaskControlBlock", "uxTCBNumber")
            .or_else(|| Self::get_struct_field_offset(&bin_data, "TCB_t", "uxTCBNumber"))
            .expect("Could not find uxTCBNumber offset in DWARF info");

        match symbol {
            Some(sym) => Self {
                cores,
                proc_buf: Mutex::new(SendPtr(unsafe { g_byte_array_new() })),
                var_current_tcb_addr: sym.address(),
                ux_tcb_number_offset: offset,
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

        let read_to_buf = |guest_addr: u64, size: usize| -> bool {
            unsafe {
                if proc_buf.is_null() {
                    return false;
                }
                g_byte_array_set_size(proc_buf, size as u32);
                qemu_plugin_read_memory_vaddr(guest_addr, proc_buf, size)
            }
        };

        // Read pointer to TCB
        if read_to_buf(self.var_current_tcb_addr, 4) {
            let tcb_pointer =
                unsafe { u32::from_le_bytes(*((*proc_buf).data as *const [u8; 4])) as u64 };

            if tcb_pointer == 0 {
                return None;
            }

            if read_to_buf(tcb_pointer + self.ux_tcb_number_offset, 4) {
                let tcb_number =
                    unsafe { u32::from_le_bytes(*((*proc_buf).data as *const [u8; 4])) as u64 };

                if tcb_number == 0 {
                    return None;
                }

                return Some((tcb_number as usize, false));
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

/// Check for mret instruction (RISC-V machine mode return)
/// mret opcode: 0x30200073
pub fn is_mret(insn_opcode: u64) -> bool {
    insn_opcode == 0x3020_0073
}
