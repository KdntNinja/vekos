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

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::VirtAddr;
use alloc::vec::Vec;
use x86_64::structures::paging::PageTableFlags;
use crate::memory::{MemoryError, MemoryManager};
use alloc::vec;
use crate::{
    verification::{Hash, OperationProof, Verifiable, VerificationError},
    hash,
};
 
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FramebufferInfo {
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u8,
    pub memory_model: u8,
    pub red_mask_size: u8,
    pub red_mask_pos: u8,
    pub green_mask_size: u8,
    pub green_mask_pos: u8,
    pub blue_mask_size: u8,
    pub blue_mask_pos: u8,
}

pub struct Framebuffer {
    info: FramebufferInfo,
    buffer: VirtAddr,
    size: usize,
    state_hash: AtomicU64,
    double_buffer: Option<Vec<u8>>,
}

impl Framebuffer {
    pub fn new(
        info: FramebufferInfo,
        physical_buffer: u64,
        memory_manager: &mut MemoryManager
    ) -> Result<Self, MemoryError> {
        let size = (info.pitch as usize * info.height as usize) as usize;
        
        let flags = PageTableFlags::PRESENT 
            | PageTableFlags::WRITABLE 
            | PageTableFlags::NO_CACHE
            | PageTableFlags::WRITE_THROUGH;
            
        let pages = (size + 4095) / 4096;

        let buffer = VirtAddr::new(0xfd000000);

        const CHUNK_SIZE: usize = 64;
        for chunk_start in (0..pages).step_by(CHUNK_SIZE) {
            let chunk_pages = core::cmp::min(CHUNK_SIZE, pages - chunk_start);
            
            for i in 0..chunk_pages {
                let page_idx = chunk_start + i;
                let phys_addr = physical_buffer + (page_idx * 4096) as u64;
                let page = x86_64::structures::paging::Page::containing_address(
                    buffer + (page_idx * 4096) as u64
                );
                let frame = x86_64::structures::paging::PhysFrame::containing_address(
                    x86_64::PhysAddr::new(phys_addr)
                );
                
                unsafe {
                    memory_manager.map_page(page, frame, flags)?;
                }
            }
        }
    
        Ok(Self {
            info,
            buffer,
            size,
            state_hash: AtomicU64::new(0),
            double_buffer: None,
        })
    }
    
    pub fn write_pixel(&mut self, x: u32, y: u32, color: u32) -> Result<(), &'static str> {
        if x >= self.info.width || y >= self.info.height {
            return Err("Pixel coordinates out of bounds");
        }
    
        let offset = (y * self.info.pitch + x * (self.info.bpp as u32 / 8)) as usize;

        if offset + 3 < self.size {
            unsafe {
                let ptr = (self.buffer + offset).as_mut_ptr();
                *ptr = (color >> 16) as u8;
                *ptr.add(1) = (color >> 8) as u8;
                *ptr.add(2) = color as u8;
                *ptr.add(3) = (color >> 24) as u8;
            }
            Ok(())
        } else {
            Err("Buffer overflow")
        }
    }

    fn generate_flush_proof(&self, new_buffer: &[u8]) -> Result<OperationProof, VerificationError> {
        let prev_state = self.state_hash();

        let buffer_hash = hash::hash_memory(
            VirtAddr::new(new_buffer.as_ptr() as u64),
            new_buffer.len()
        );

        let new_state = Hash(prev_state.0 ^ buffer_hash.0);
        
        Ok(OperationProof {
            op_id: crate::tsc::read_tsc(),
            prev_state,
            new_state,
            data: crate::verification::ProofData::Memory(
                crate::verification::MemoryProof {
                    operation: crate::verification::MemoryOpType::Modify,
                    address: self.buffer,
                    size: self.size,
                    frame_hash: buffer_hash,
                }
            ),
            signature: [0; 64],
        })
    }
    
    pub fn draw_pixel_verified(&mut self, x: u32, y: u32, color: u32) -> Result<Hash, VerificationError> {
        if let Err(e) = self.write_pixel(x, y, color) {
            return Err(VerificationError::OperationFailed);
        }

        let offset = (y * self.info.pitch + x * (self.info.bpp as u32 / 8)) as usize;
        let pixel_data = unsafe {
            core::slice::from_raw_parts(
                (self.buffer + offset).as_ptr(),
                4
            )
        };

        let pixel_hash = unsafe {
            hash::hash_memory(
                VirtAddr::new(pixel_data.as_ptr() as *const () as u64),
                pixel_data.len()
            )
        };

        Ok(pixel_hash)
    }

    pub fn fill_rect_verified(&mut self, x: u32, y: u32, width: u32, height: u32, color: u32) 
        -> Result<Hash, VerificationError> 
    {
        let mut hashes = Vec::new();
        
        for cy in y..y.saturating_add(height) {
            for cx in x..x.saturating_add(width) {
                if let Ok(hash) = self.draw_pixel_verified(cx, cy, color) {
                    hashes.push(hash);
                }
            }
        }

        Ok(hash::combine_hashes(&hashes))
    }

    pub fn clear(&mut self, color: u32) -> Result<(), &'static str> {
        if let Some(ref mut double_buffer) = self.double_buffer {
            for y in 0..self.info.height {
                for x in 0..self.info.width {
                    self.write_pixel(x, y, color)?;
                }
            }
            Ok(())
        } else {
            Err("Double buffer not initialized")
        }
    }
}

impl Verifiable for Framebuffer {
    fn generate_proof(&self, operation: crate::verification::Operation) -> Result<OperationProof, VerificationError> {
        match operation {
            crate::verification::Operation::Memory { address, size, .. } => {
                let prev_state = self.state_hash();
                
                let buffer_hash = if let Some(ref double_buffer) = self.double_buffer {
                    hash::hash_memory(
                        VirtAddr::new(double_buffer.as_ptr() as u64),
                        double_buffer.len()
                    )
                } else {
                    return Err(VerificationError::InvalidState);
                };
                
                let new_state = Hash(prev_state.0 ^ buffer_hash.0);
                
                Ok(OperationProof {
                    op_id: crate::tsc::read_tsc(),
                    prev_state,
                    new_state,
                    data: crate::verification::ProofData::Memory(
                        crate::verification::MemoryProof {
                            operation: crate::verification::MemoryOpType::Modify,
                            address,
                            size,
                            frame_hash: buffer_hash,
                        }
                    ),
                    signature: [0; 64],
                })
            },
            _ => Err(VerificationError::InvalidOperation),
        }
    }

    fn verify_proof(&self, proof: &OperationProof) -> Result<bool, VerificationError> {
        let current_state = self.state_hash();
        Ok(current_state == proof.new_state)
    }

    fn state_hash(&self) -> Hash {
        Hash(self.state_hash.load(Ordering::SeqCst))
    }
}