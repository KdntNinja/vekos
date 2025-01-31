/*
* Copyright 2023-2024 Juan Miguel Giraldo
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

use core::mem::size_of;
use alloc::vec::Vec;
use x86_64::structures::paging::Size4KiB;
use crate::serial_println;
use x86_64::VirtAddr;
use x86_64::structures::paging::{Page, PageTableFlags};
use crate::memory::MemoryError;
use crate::memory::MemoryManager;
use x86_64::structures::paging::FrameAllocator;

#[repr(C)]
pub struct ElfHeader {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
pub struct ProgramHeader {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

pub fn load_elf(data: &[u8], memory_manager: &mut MemoryManager) -> Result<VirtAddr, MemoryError> {
    serial_println!("Starting ELF loading");
    serial_println!("File size: {} bytes", data.len());
    
    if data.len() < size_of::<ElfHeader>() {
        return Err(MemoryError::InvalidExecutable);
    }

    let header = unsafe { &*(data.as_ptr() as *const ElfHeader) };
    
    if &header.e_ident[0..4] != b"\x7FELF" {
        return Err(MemoryError::InvalidExecutable);
    }

    serial_println!("Entry point: {:#x}", header.e_entry);
    serial_println!("Program headers: {} at offset {:#x}", 
        header.e_phnum, 
        header.e_phoff);

    let ph_offset = header.e_phoff as usize;
    let ph_count = header.e_phnum as usize;

    for i in 0..ph_count {

        serial_println!("let ph_pos = ph_offset + i * size_of::<ProgramHeader>() coming.");

        let ph_pos = ph_offset + i * size_of::<ProgramHeader>();
        if ph_pos + size_of::<ProgramHeader>() > data.len() {
            return Err(MemoryError::InvalidExecutable);
        }

        serial_println!("let ph = &*(data[ph_pos..].as_ptr() as *const ProgramHeader) coming.");

        let ph = unsafe { &*(data[ph_pos..].as_ptr() as *const ProgramHeader) };

        serial_println!("if ph.p_type == 1 coming.");

        if ph.p_type == 1 {
            let start_page = Page::containing_address(VirtAddr::new(ph.p_vaddr));
            let end_page = Page::containing_address(VirtAddr::new(ph.p_vaddr + ph.p_memsz - 1));

            let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;

            flags |= PageTableFlags::WRITABLE;

            if ph.p_flags & 0x1 != 0 {
            } else {
                flags |= PageTableFlags::NO_EXECUTE;
            }

            for page in Page::range_inclusive(start_page, end_page) {
                let frame = memory_manager.frame_allocator
                    .allocate_frame()
                    .ok_or(MemoryError::FrameAllocationFailed)?;

                unsafe {
                    memory_manager.map_page(page, frame, flags)?;

                    let dest_ptr = page.start_address().as_mut_ptr::<u8>();

                    core::ptr::write_bytes(dest_ptr, 0, Page::<Size4KiB>::SIZE as usize);

                    let page_offset = page.start_address().as_u64() - ph.p_vaddr;
                    if page_offset < ph.p_filesz {
                        let file_offset = ph.p_offset + page_offset;
                        let copy_size = core::cmp::min(
                            Page::<Size4KiB>::SIZE as u64,
                            ph.p_filesz - page_offset
                        ) as usize;

                        if file_offset as usize + copy_size <= data.len() {
                            core::ptr::copy_nonoverlapping(
                                data.as_ptr().add(file_offset as usize),
                                dest_ptr,
                                copy_size
                            );
                        }
                    }

                    if ph.p_flags & 0x2 == 0 {
                        let new_flags = flags & !PageTableFlags::WRITABLE;
                        memory_manager.update_page_flags(page, new_flags)?;
                    }
                }
            }
        }
    }

    Ok(VirtAddr::new(header.e_entry))
}