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

use alloc::vec::Vec;
use alloc::vec;
use x86_64::structures::paging::FrameAllocator;
use x86_64::structures::paging::FrameDeallocator;
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::{
    structures::paging::{Page, PageTableFlags},
};
use crate::{
    memory::{MemoryError, MemoryManager},
    fs::{FILESYSTEM, FileSystem, FilePermissions},
    hash,
};

const SWAP_FILE: &str = "swap";
const PAGE_SIZE: usize = 4096;
const MAX_SWAP_PAGES: usize = 1024;

#[derive(Clone)]
pub struct SwapEntry {
    pub offset: usize,
    pub page: Page,
    pub flags: PageTableFlags,
    pub hash: [u8; 32],
}

pub struct SwapManager {
    free_slots: Vec<usize>,
    pub used_slots: Vec<Option<SwapEntry>>,
    total_slots: usize,
    swap_file_size: usize,
}

impl SwapManager {
    pub fn new() -> Self {
        let mut free_slots = Vec::with_capacity(MAX_SWAP_PAGES);
        for i in 0..MAX_SWAP_PAGES {
            free_slots.push(i);
        }

        Self {
            free_slots,
            used_slots: vec![None; MAX_SWAP_PAGES],
            total_slots: MAX_SWAP_PAGES,
            swap_file_size: PAGE_SIZE * MAX_SWAP_PAGES,
        }
    }

    pub fn init(&self) -> Result<(), MemoryError> {
        let mut fs = FILESYSTEM.lock();

        if fs.stat(SWAP_FILE).is_err() {
            fs.create_file(
                SWAP_FILE,
                FilePermissions {
                    read: true,
                    write: true,
                    execute: false,
                }
            ).map_err(|_| MemoryError::SwapFileError)?;

            let zeros = vec![0u8; self.swap_file_size];
            fs.write_file(SWAP_FILE, &zeros)
                .map_err(|_| MemoryError::SwapFileError)?;
        }
        
        Ok(())
    }

    pub fn get_entry(&self, slot: usize) -> Option<&SwapEntry> {
        self.used_slots.get(slot)?.as_ref()
    }

    pub fn iter_slots(&self) -> impl Iterator<Item = (usize, &Option<SwapEntry>)> {
        self.used_slots.iter().enumerate()
    }

    pub fn swap_out(
        &mut self,
        page: Page,
        flags: PageTableFlags,
        memory_manager: &mut MemoryManager,
    ) -> Result<usize, MemoryError> {
        let slot = self.free_slots.pop()
            .ok_or(MemoryError::NoSwapSpace)?;
        
        let offset = slot * PAGE_SIZE;

        let virt_addr = page.start_address();
        let page_data = unsafe {
            core::slice::from_raw_parts(
                virt_addr.as_ptr::<u8>(),
                PAGE_SIZE
            )
        };

        let page_hash = hash::hash_memory(
            virt_addr,
            PAGE_SIZE
        );

        let mut fs = FILESYSTEM.lock();
        fs.write_file(SWAP_FILE, page_data)
            .map_err(|_| MemoryError::SwapFileError)?;

        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..8].copy_from_slice(&page_hash.0.to_ne_bytes());
        
        self.used_slots[slot] = Some(SwapEntry {
            offset,
            page,
            flags,
            hash: hash_bytes,
        });

        unsafe {
            memory_manager.unmap_page(page)?;
        }

        Ok(slot)
    }

    pub fn swap_in(
        &mut self,
        slot: usize,
        memory_manager: &mut MemoryManager,
    ) -> Result<(), MemoryError> {
        let entry = self.used_slots[slot].take()
            .ok_or(MemoryError::InvalidSwapSlot)?;

        let mut fs = FILESYSTEM.lock();
        let mut page_data = vec![0u8; PAGE_SIZE];

        let mut file_data = fs.read_file(SWAP_FILE)
            .map_err(|_| MemoryError::SwapFileError)?;
        page_data.copy_from_slice(&file_data[entry.offset..entry.offset + PAGE_SIZE]);

        let frame = memory_manager.frame_allocator
            .allocate_frame()
            .ok_or(MemoryError::FrameAllocationFailed)?;

        unsafe {
            memory_manager.map_page(entry.page, frame, entry.flags)?;

            core::ptr::copy_nonoverlapping(
                page_data.as_ptr(),
                entry.page.start_address().as_mut_ptr::<u8>(),
                PAGE_SIZE
            );

            let new_hash = hash::hash_memory(
                entry.page.start_address(),
                PAGE_SIZE
            );
            let mut verify_bytes = [0u8; 32];
            verify_bytes[0..8].copy_from_slice(&new_hash.0.to_ne_bytes());
            
            if verify_bytes != entry.hash {
                memory_manager.unmap_page(entry.page)?;
                memory_manager.frame_allocator.deallocate_frame(frame);
                return Err(MemoryError::SwapFileError);
            }
        }

        self.free_slots.push(slot);
        
        Ok(())
    }
}

lazy_static! {
    pub static ref SWAP_MANAGER: Mutex<SwapManager> = Mutex::new(SwapManager::new());
}