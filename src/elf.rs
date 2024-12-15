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

use crate::memory::{MemoryManager, MemoryError, UserSpaceRegion, USER_SPACE_END};
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;
use x86_64::structures::paging::Page;
use x86_64::structures::paging::FrameAllocator;
use x86_64::structures::paging::Size4KiB;
use crate::serial_println;
use x86_64::structures::paging::Mapper;
use x86_64::structures::paging::FrameDeallocator;
use alloc::vec::Vec;

#[derive(Debug)]
pub enum ElfError {
    InvalidMagic,
    InvalidClass,
    InvalidFormat,
    UnsupportedArchitecture,
    MemoryError(MemoryError),
    LoadError,
    InvalidSegment,
    SecurityViolation,
    UnsupportedFeature,
    InvalidAlignment,
    DynamicLinkingUnsupported,
}

impl From<MemoryError> for ElfError {
    fn from(error: MemoryError) -> Self {
        match error {
            MemoryError::FrameAllocationFailed => ElfError::LoadError,
            MemoryError::PageMappingFailed => ElfError::LoadError,
            MemoryError::InvalidAddress => ElfError::SecurityViolation,
            MemoryError::InvalidPermissions => ElfError::SecurityViolation,
            MemoryError::RegionOverlap => ElfError::SecurityViolation,
            MemoryError::ZoneNotFound => ElfError::LoadError,
            MemoryError::ZoneExhausted => ElfError::LoadError,
            MemoryError::InvalidZoneAccess => ElfError::SecurityViolation,
            MemoryError::InsufficientContiguousMemory => ElfError::LoadError,
            MemoryError::ZoneValidationFailed => ElfError::LoadError,
            MemoryError::MemoryLimitExceeded => ElfError::LoadError,
            MemoryError::VerificationFailed => ElfError::SecurityViolation,
            MemoryError::SwapFileError => ElfError::LoadError,
            MemoryError::NoSwapSpace => ElfError::LoadError,
            MemoryError::InvalidSwapSlot => ElfError::LoadError,
            MemoryError::VramAllocationFailed => ElfError::LoadError,
            MemoryError::VramVerificationFailed => ElfError::SecurityViolation,
            MemoryError::VramInvalidBlock => ElfError::LoadError,
            MemoryError::InvalidAlignment => ElfError::InvalidAlignment,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProgramHeaderTable<'a> {
    pub headers: &'a [ProgramHeader],
    pub count: usize,
}

impl<'a> ProgramHeaderTable<'a> {
    pub fn iter(&self) -> impl Iterator<Item = &ProgramHeader> {
        self.headers.iter()
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SegmentType {
    Null = 0,
    Load = 1,
    Dynamic = 2,
    Interp = 3,
    Note = 4,
    SharedLib = 5,
    PHdr = 6,
    TLS = 7,
}

impl TryFrom<u32> for SegmentType {
    type Error = ElfError;
    
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SegmentType::Null),
            1 => Ok(SegmentType::Load),
            2 => Ok(SegmentType::Dynamic),
            3 => Ok(SegmentType::Interp),
            4 => Ok(SegmentType::Note),
            5 => Ok(SegmentType::SharedLib),
            6 => Ok(SegmentType::PHdr),
            7 => Ok(SegmentType::TLS),
            _ => Err(ElfError::InvalidSegment),
        }
    }
}

#[repr(C)]
pub struct ElfHeader {
    magic: [u8; 4],
    class: u8,
    data: u8,
    version: u8,
    os_abi: u8,
    abi_version: u8,
    padding: [u8; 7],
    type_: u16,
    machine: u16,
    version2: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

#[repr(C)]
#[derive(Debug)]
pub struct ProgramHeader {
    pub(crate) type_: u32,
    pub(crate) flags: u32,
    pub(crate) offset: u64,
    pub(crate) vaddr: u64,
    pub(crate) paddr: u64,
    pub(crate) filesz: u64,
    pub(crate) memsz: u64,
    pub(crate) align: u64,
}

impl ProgramHeader {
    pub fn vaddr(&self) -> u64 {
        self.vaddr
    }

    pub fn memsz(&self) -> u64 {
        self.memsz
    }

    pub fn get_type(&self) -> u32 {
        self.type_
    }
}

pub struct ElfLoader {
    header: &'static ElfHeader,
    program_headers: &'static [ProgramHeader],
    binary: &'static [u8],
}

impl ElfLoader {
    pub fn new(binary: &'static [u8]) -> Result<Self, ElfError> {
        if binary.len() < core::mem::size_of::<ElfHeader>() {
            return Err(ElfError::InvalidFormat);
        }

        let header = unsafe { &*(binary.as_ptr() as *const ElfHeader) };
        
        
        if header.magic != [0x7f, 0x45, 0x4c, 0x46] {
            return Err(ElfError::InvalidMagic);
        }

        
        if header.class != 2 {
            return Err(ElfError::InvalidClass);
        }

        
        if header.machine != 0x3e {
            return Err(ElfError::UnsupportedArchitecture);
        }

        let ph_offset = header.phoff as usize;
        let ph_size = header.phentsize as usize;
        let ph_count = header.phnum as usize;

        if binary.len() < ph_offset + ph_size * ph_count {
            return Err(ElfError::InvalidFormat);
        }

        let program_headers = unsafe {
            core::slice::from_raw_parts(
                (binary.as_ptr().add(ph_offset)) as *const ProgramHeader,
                ph_count
            )
        };

        Ok(ElfLoader {
            header,
            program_headers,
            binary,
        })
    }

    pub fn program_headers(&self) -> Result<ProgramHeaderTable, ElfError> {
        Ok(ProgramHeaderTable {
            headers: self.program_headers,
            count: self.header.phnum as usize
        })
    }

    pub fn load(&self, memory_manager: &mut MemoryManager) -> Result<VirtAddr, ElfError> {
        
        self.validate_segments()?;

        let mut entry_point = None;

        for ph in self.program_headers {
            match SegmentType::try_from(ph.type_)? {
                SegmentType::Load => {
                    self.load_segment(memory_manager, ph)?;
                }
                SegmentType::Dynamic => {
                    return Err(ElfError::DynamicLinkingUnsupported);
                }
                SegmentType::TLS => {
                    return Err(ElfError::UnsupportedFeature);
                }
                _ => continue,
            }
        }

        
        entry_point = Some(VirtAddr::new(self.header.entry));

        
        if let Some(entry) = entry_point {
            if entry.as_u64() >= 0xffff_8000_0000_0000 {
                return Err(ElfError::SecurityViolation);
            }
        }

        entry_point.ok_or(ElfError::LoadError)
    }

    fn load_segment(&self, memory_manager: &mut MemoryManager, ph: &ProgramHeader) 
    -> Result<(), MemoryError> 
    {
        let mem_size = ph.memsz as usize;
        let file_size = ph.filesz as usize;
        let file_offset = ph.offset as usize;

        if ph.vaddr + ph.memsz > USER_SPACE_END {
            return Err(MemoryError::InvalidAddress);
        }

        // Add size validation
        if mem_size > 16 * 1024 * 1024 { // 16MB max segment size
            return Err(MemoryError::MemoryLimitExceeded);
        }

        // Calculate actual number of pages needed
        let start_page = Page::containing_address(VirtAddr::new(ph.vaddr));
        let end_page = Page::containing_address(VirtAddr::new(ph.vaddr + mem_size as u64 - 1));
        let page_range = Page::range_inclusive(start_page, end_page);

        // Create proper flags based on ELF segment permissions
        let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if ph.flags & 0x2 != 0 {
            flags |= PageTableFlags::WRITABLE;
        }
        if ph.flags & 0x1 == 0 {
            flags |= PageTableFlags::NO_EXECUTE;
        }

        // Validate page alignment 
        if ph.align > 0 && (ph.vaddr % ph.align != 0 || ph.offset % ph.align != 0) {
            return Err(MemoryError::InvalidAlignment);
        }

        // Verify addresses are in valid user space
        if ph.vaddr >= 0xffff_8000_0000_0000 {
            return Err(MemoryError::InvalidPermissions);
        }

        for page in page_range {
            // Add validation that the page address is valid
            if page.start_address().as_u64() >= 0xffff_8000_0000_0000 {
                serial_println!("Invalid page address: {:#x}", page.start_address().as_u64());
                return Err(MemoryError::InvalidAddress);
            }

            serial_println!("Allocating frame for page at {:#x}", page.start_address().as_u64());
            let frame = memory_manager.frame_allocator
                .allocate_frame()
                .ok_or(MemoryError::FrameAllocationFailed)?;

            serial_println!("Mapping page {:#x} to frame {:#x} with flags {:?}", 
                page.start_address().as_u64(),
                frame.start_address().as_u64(),
                flags);

            unsafe {
                // First map the page
                match memory_manager.map_page(page, frame, flags) {
                    Ok(_) => serial_println!("Successfully mapped page {:#x}", page.start_address().as_u64()),
                    Err(e) => {
                        serial_println!("Failed to map page {:#x}: {:?}", page.start_address().as_u64(), e);
                        memory_manager.frame_allocator.deallocate_frame(frame);
                        return Err(e);
                    }
                }

                // Calculate offset into this page
                let page_base = page.start_address().as_u64() as usize;
                let page_offset = page_base - ph.vaddr as usize;
                
                // Only copy data if we're in the initialized part
                if page_offset < file_size {
                    let start = file_offset + page_offset;
                    let count = core::cmp::min(
                        Page::<Size4KiB>::SIZE as usize,
                        file_size - page_offset
                    );
        
                    // Add this validation right before the copy
                    if start + count > self.binary.len() {
                        return Err(MemoryError::InvalidAddress);
                    }
        
                    // Replace this copy block
                    core::ptr::copy_nonoverlapping(
                        self.binary.as_ptr().add(start),
                        page_base as *mut u8,
                        count
                    );
                    // With this corrected version
                    let dest_addr = memory_manager.phys_to_virt(frame.start_address()).as_mut_ptr::<u8>();
                    core::ptr::copy_nonoverlapping(
                        self.binary.as_ptr().add(start),
                        dest_addr,
                        count
                    );
                }

                // Zero remaining page memory if needed
                if page_offset < mem_size {
                    let zero_start = if page_offset < file_size {
                        page_base + core::cmp::min(
                            Page::<Size4KiB>::SIZE as usize,
                            file_size - page_offset
                        )
                    } else {
                        page_base
                    };

                    let zero_count = core::cmp::min(
                        Page::<Size4KiB>::SIZE as usize - (zero_start - page_base),
                        mem_size - page_offset
                    );

                    core::ptr::write_bytes(
                        zero_start as *mut u8,
                        0,
                        zero_count
                    );
                }
            }
        }

        let num_pages = (ph.memsz as usize + 4095) / 4096;
    
        serial_println!("Checking page mappings after setup...");
        for i in 0..num_pages {
            let page = start_page + i as u64;
            match memory_manager.page_table.translate_page(page) {
                Ok(_) => serial_println!("Page {:#x} mapped successfully", page.start_address().as_u64()),
                Err(e) => serial_println!("Page {:#x} mapping verification failed: {:?}", 
                                        page.start_address().as_u64(), e),
            }
        }

        Ok(())
    }

    pub fn validate_segments(&self) -> Result<(), ElfError> {
        
        let mut sorted_segments: Vec<_> = self.program_headers.iter()
            .filter(|ph| SegmentType::try_from(ph.type_).unwrap_or(SegmentType::Null) == SegmentType::Load)
            .collect();
        sorted_segments.sort_by_key(|ph| ph.vaddr);

        for i in 1..sorted_segments.len() {
            let prev = sorted_segments[i - 1];
            let curr = sorted_segments[i];
            if prev.vaddr + prev.memsz > curr.vaddr {
                return Err(ElfError::SecurityViolation);
            }
        }

        for ph in self.program_headers {
            if ph.type_ == 1 {
                if ph.align > 0 && (ph.vaddr % ph.align != 0 || ph.offset % ph.align != 0) {
                    return Err(ElfError::InvalidAlignment);
                }

                if ph.vaddr + ph.memsz < ph.vaddr {
                    return Err(ElfError::SecurityViolation);
                }

                if ph.offset + ph.filesz > self.binary.len() as u64 {
                    return Err(ElfError::InvalidSegment);
                }

                if ph.filesz > ph.memsz {
                    return Err(ElfError::InvalidSegment);
                }
            }
        }

        Ok(())
    }

    pub fn entry_point(&self) -> VirtAddr {
        VirtAddr::new(self.header.entry)
    }
}