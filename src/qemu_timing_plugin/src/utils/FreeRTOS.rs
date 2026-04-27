#![allow(unused_imports, non_snake_case)]

use std::{
    collections::HashMap,
    fs,
    sync::{Mutex, OnceLock},
};

use std::borrow::Cow;

use object::{Object, ObjectSection, ObjectSymbol};

use crate::{
    GByteArray, g_byte_array_free, g_byte_array_new, g_byte_array_set_size,
    qemu_plugin_hwaddr_operation_result_QEMU_PLUGIN_HWADDR_OPERATION_OK,
    qemu_plugin_read_memory_hwaddr, qemu_plugin_read_memory_vaddr, qemu_plugin_read_register,
    qemu_plugin_register, utils::plugin_find_register,
};

use super::{DomainRetriever, SendPtr};

/// Size of `DomainBlock_t` on RV32: UBaseType_t uxDomainID (4 bytes) + size_t uxLength (4 bytes)
const DOMAIN_BLOCK_SIZE: u64 = 8;
/// Offset of `uxDomainID` inside `DomainBlock_t`
const DOMAIN_ID_OFFSET: u64 = 0;

pub struct FreeRTOSDomainRetriever {
    proc_buf: Mutex<SendPtr<GByteArray>>,
    var_px_current_domain_index_addr: u64,
    var_x_domains_addr: u64,
    cores: usize,
}

impl DomainRetriever for FreeRTOSDomainRetriever {
    fn new(cores: usize, elf_path: &str) -> Self {
        let bin_data = fs::read(elf_path).unwrap();

        let elf_file = object::File::parse(&*bin_data).unwrap();

        let sym_px_current_domain_index = elf_file
            .symbols()
            .find(|sym| sym.name() == Ok("pxCurrentDomainIndex"));

        let sym_x_domains = elf_file.symbols().find(|sym| sym.name() == Ok("xDomains"));

        match (sym_px_current_domain_index, sym_x_domains) {
            (Some(idx_sym), Some(dom_sym)) => Self {
                cores,
                proc_buf: Mutex::new(SendPtr(unsafe { g_byte_array_new() })),
                var_px_current_domain_index_addr: idx_sym.address(),
                var_x_domains_addr: dom_sym.address(),
            },
            (None, _) => panic!("Unable to find pxCurrentDomainIndex in elf file"),
            (_, None) => panic!("Unable to find xDomains in elf file"),
        }
    }

    fn vcpu_init(&self) {}

    fn on_exit(&self, _out: &mut String) {}

    // Currently only handle single CPU, so no cpu index
    fn get_domain_info(&self, _vcpu_index: u32, _addr: usize) -> Option<(usize, bool)> {
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

        // Read pxCurrentDomainIndex (size_t on RV32 -> 4 bytes)
        if read_to_buf(self.var_px_current_domain_index_addr, 4) {
            let domain_index =
                unsafe { u32::from_le_bytes(*((*proc_buf).data as *const [u8; 4])) as u64 };

            let block_addr =
                self.var_x_domains_addr + (domain_index * DOMAIN_BLOCK_SIZE) + DOMAIN_ID_OFFSET;

            if read_to_buf(block_addr, 4) {
                let domain_id =
                    unsafe { u32::from_le_bytes(*((*proc_buf).data as *const [u8; 4])) as u64 };

                return Some((domain_id as usize, false));
            }
        }
        None
    }

    /// Check if an address is in a scratchpad memory (SPM) region.
    /// For FreeRTOS, there is no distinction
    fn is_spm_address(&self, _addr: usize) -> bool {
        return false;
    }

    /// Read the 64-bit machine time (`mtime`) from the QEMU `virt` CLINT.
    /// Reads low and high 32-bit halves separately (RV32 style).
    /// Uses `qemu_plugin_read_memory_vaddr` because the MPU port runs
    /// without address translation (vaddr == paddr) and the vaddr API
    /// is known to work in this plugin context.
    /// Returns `None` if either read fails.
    fn read_mtime(&self) -> Option<u64> {
        let guard = self.proc_buf.lock().unwrap();
        let buf_ptr = guard.0;
        if buf_ptr.is_null() {
            return None;
        }
        unsafe {
            // Read low 32 bits at CLINT_MTIME_LOW_ADDR (0x0200bff8)
            g_byte_array_set_size(buf_ptr, 4);
            if !qemu_plugin_read_memory_vaddr(0x0200_bff8, buf_ptr, 4) {
                return None;
            }
            let low = u32::from_le_bytes(*((*buf_ptr).data as *const [u8; 4])) as u64;

            // Read high 32 bits at CLINT_MTIME_HIGH_ADDR (0x0200bffc)
            g_byte_array_set_size(buf_ptr, 4);
            if !qemu_plugin_read_memory_vaddr(0x0200_bffc, buf_ptr, 4) {
                return None;
            }
            let high = u32::from_le_bytes(*((*buf_ptr).data as *const [u8; 4])) as u64;

            Some((high << 32) | low)
        }
    }
}

// Check for temporal_fence instruction (magic NOP)
// RISC-V: addi x0, x0, 11 = 0x00b00013
// This is a NOP (x0 hardwired to 0) but we use it as a fence marker
pub fn is_temporal_fence(insn_opcode: u64) -> bool {
    insn_opcode == 0x00b0_0013
}

// Check for is_timing start instruction (magic NOP)
// RISC-V: addi x0, x0, 12 = 0x00c00013
pub fn is_timing_start(insn_opcode: u64) -> bool {
    insn_opcode == 0x00c0_0013
}

// Check for is_timing end instruction (magic NOP)
// RISC-V: addi x0, x0, 13 = 0x00d00013
pub fn is_timing_end(insn_opcode: u64) -> bool {
    insn_opcode == 0x00d0_0013
}

// Check for domain round-trip marker instruction (magic NOP)
// RISC-V: addi x0, x0, 14 = 0x00e00013
pub fn is_round_trip_marker(insn_opcode: u64) -> bool {
    insn_opcode == 0x00e0_0013
}
