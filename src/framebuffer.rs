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
use crate::serial_println;
use x86_64::structures::paging::PageTableFlags;
use x86_64::instructions::port::Port;
use crate::memory::{MemoryError, MemoryManager};
use alloc::vec;
use spin::Mutex;
use core::sync::atomic::AtomicBool;
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
    pub page_flip_supported: bool,
    pub current_page: u8,
}

pub struct Framebuffer {
    info: FramebufferInfo,
    buffer: VirtAddr,
    size: usize,
    state_hash: AtomicU64,
    double_buffer: Option<Vec<u8>>,
    swap_in_progress: AtomicBool,
    front_buffer_hash: AtomicU64,
    back_buffer_hash: AtomicU64,
    vsync_enabled: AtomicBool,
    vga_status_port: Mutex<Port<u8>>,
    vga_crt_port: Mutex<Port<u16>>,
    page1_buffer: VirtAddr,
    page2_buffer: VirtAddr,
    active_buffer: AtomicU64,
    flip_in_progress: AtomicBool,
    sync_pending: AtomicBool,
    vsync_occurred: AtomicBool,
}

impl Framebuffer {
    pub fn new(
        mut info: FramebufferInfo,
        physical_buffer: u64,
        memory_manager: &mut MemoryManager
    ) -> Result<Self, MemoryError> {
        let size = (info.pitch as usize * info.height as usize) as usize;
        let pages = (size + 4095) / 4096; 
        let buffer = VirtAddr::new(0xfd000000);

        let flags = PageTableFlags::PRESENT 
            | PageTableFlags::WRITABLE 
            | PageTableFlags::NO_CACHE
            | PageTableFlags::WRITE_THROUGH;

        let result_buffer = if info.page_flip_supported {
            let buffer2_addr = VirtAddr::new(0xfd000000 + size as u64);
            let mut mapping_succeeded = true;

            let memory_required = size * 2;
            if !memory_manager.verify_memory_requirements(memory_required) {
                serial_println!("Warning: Insufficient memory for double buffered framebuffer");
                info.page_flip_supported = false;
                Ok(Framebuffer {
                    info,
                    buffer,
                    size,
                    state_hash: AtomicU64::new(0),
                    double_buffer: None, 
                    swap_in_progress: AtomicBool::new(false),
                    front_buffer_hash: AtomicU64::new(0),
                    back_buffer_hash: AtomicU64::new(0),
                    vsync_enabled: AtomicBool::new(true),
                    vga_status_port: Mutex::new(Port::new(0x3DA)),
                    vga_crt_port: Mutex::new(Port::new(0x3D4)),
                    page1_buffer: buffer,
                    page2_buffer: buffer,
                    active_buffer: AtomicU64::new(buffer.as_u64()),
                    flip_in_progress: AtomicBool::new(false),
                    sync_pending: AtomicBool::new(false),
                    vsync_occurred: AtomicBool::new(false),
                })
            } else {

                const CHUNK_SIZE: usize = 64;
                for chunk_start in (0..pages).step_by(CHUNK_SIZE) {
                    let chunk_pages = core::cmp::min(CHUNK_SIZE, pages - chunk_start);
                    
                    for i in 0..chunk_pages {
                        let page_idx = chunk_start + i;
                        let phys_addr = physical_buffer + ((pages + page_idx) * 4096) as u64;
                        let page = x86_64::structures::paging::Page::containing_address(
                            buffer2_addr + (page_idx * 4096) as u64
                        );
                        let frame = x86_64::structures::paging::PhysFrame::containing_address(
                            x86_64::PhysAddr::new(phys_addr)
                        );
                        
                        unsafe {
                            match memory_manager.map_page(page, frame, flags) {
                                Ok(_) => continue,
                                Err(e) => {
                                    serial_println!("Failed to map page at index {}: {:?}", page_idx, e);
                                    mapping_succeeded = false;

                                    for j in 0..page_idx {
                                        let cleanup_page = x86_64::structures::paging::Page::containing_address(
                                            buffer2_addr + (j * 4096) as u64
                                        );
                                        if let Err(e) = memory_manager.unmap_page(cleanup_page) {
                                            serial_println!("Warning: Failed to unmap page during cleanup: {:?}", e);
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    
                    if !mapping_succeeded {
                        break;
                    }
                }
    
                if mapping_succeeded {
                    unsafe {
                        x86_64::instructions::tlb::flush_all();
                    }
                    Ok(Framebuffer {
                        info,
                        buffer,
                        size,
                        state_hash: AtomicU64::new(0),
                        double_buffer: None,
                        swap_in_progress: AtomicBool::new(false),
                        front_buffer_hash: AtomicU64::new(0),
                        back_buffer_hash: AtomicU64::new(0),
                        vsync_enabled: AtomicBool::new(true),
                        vga_status_port: Mutex::new(Port::new(0x3DA)),
                        vga_crt_port: Mutex::new(Port::new(0x3D4)),
                        page1_buffer: buffer,
                        page2_buffer: buffer2_addr,
                        active_buffer: AtomicU64::new(buffer.as_u64()),
                        flip_in_progress: AtomicBool::new(false),
                        sync_pending: AtomicBool::new(false),
                        vsync_occurred: AtomicBool::new(false),
                    })
                } else {
                    serial_println!("Warning: Failed to map second framebuffer, falling back to single buffer");
                    info.page_flip_supported = false;
                    Ok(Framebuffer {
                        info,
                        buffer,
                        size,
                        state_hash: AtomicU64::new(0),
                        double_buffer: None,
                        swap_in_progress: AtomicBool::new(false),
                        front_buffer_hash: AtomicU64::new(0),
                        back_buffer_hash: AtomicU64::new(0),
                        vsync_enabled: AtomicBool::new(true),
                        vga_status_port: Mutex::new(Port::new(0x3DA)),
                        vga_crt_port: Mutex::new(Port::new(0x3D4)),
                        page1_buffer: buffer,
                        page2_buffer: buffer,
                        active_buffer: AtomicU64::new(buffer.as_u64()),
                        flip_in_progress: AtomicBool::new(false),
                        sync_pending: AtomicBool::new(false),
                        vsync_occurred: AtomicBool::new(false),
                    })
                }
            }
        } else {
            Ok(Framebuffer {
                info,
                buffer,
                size,
                state_hash: AtomicU64::new(0),
                double_buffer: None,
                swap_in_progress: AtomicBool::new(false),
                front_buffer_hash: AtomicU64::new(0),
                back_buffer_hash: AtomicU64::new(0),
                vsync_enabled: AtomicBool::new(true),
                vga_status_port: Mutex::new(Port::new(0x3DA)),
                vga_crt_port: Mutex::new(Port::new(0x3D4)),
                page1_buffer: buffer,
                page2_buffer: buffer,
                active_buffer: AtomicU64::new(buffer.as_u64()),
                flip_in_progress: AtomicBool::new(false),
                sync_pending: AtomicBool::new(false),
                vsync_occurred: AtomicBool::new(false),
            })
        };
    
        result_buffer
    }

    pub fn init_double_buffering(&mut self) -> Result<(), &'static str> {
        let buffer_size = (self.info.pitch as usize * self.info.height as usize) as usize;

        if !self.check_buffer_alignment(VirtAddr::new(self.buffer.as_u64()), buffer_size) {
            return Err("Buffer alignment check failed");
        }
        
        self.double_buffer = Some(vec![0; buffer_size]);
        Ok(())
    }

    fn check_buffer_alignment(&self, addr: VirtAddr, size: usize) -> bool {
        if !addr.is_aligned(4096u64) {
            serial_println!("Error: Buffer address not page aligned");
            return false;
        }

        if size % 4096 != 0 {
            serial_println!("Error: Buffer size not page aligned");
            return false;
        }

        if addr.as_u64().checked_add(size as u64).is_none() {
            serial_println!("Error: Buffer address range overflow");
            return false;
        }
    
        true
    }
    
    pub fn handle_vsync(&mut self) {
        self.vsync_occurred.store(true, Ordering::SeqCst);
        if self.sync_pending.load(Ordering::SeqCst) {
            self.sync_pending.store(false, Ordering::SeqCst);
        }
    }
    
    pub fn wait_for_vsync(&self) -> Result<(), VerificationError> {
        if !self.vsync_enabled.load(Ordering::SeqCst) {
            return Ok(());
        }
    
        self.vsync_occurred.store(false, Ordering::SeqCst);

        while !self.vsync_occurred.load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }
        
        Ok(())
    }

    pub fn write_pixel(&mut self, x: u32, y: u32, color: u32) -> Result<(), &'static str> {
        if x >= self.info.width || y >= self.info.height {
            return Err("Pixel coordinates out of bounds");
        }
    
        let offset = (y * self.info.pitch + x * (self.info.bpp as u32 / 8)) as usize;
        let current_buffer = self.get_active_buffer();
        let draw_buffer = if current_buffer == self.page1_buffer {
            self.page2_buffer
        } else {
            self.page1_buffer
        };
    
        if offset + 3 < self.size {
            unsafe {
                let ptr = (draw_buffer + offset).as_mut_ptr();
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

    pub fn swap_buffers(&mut self) -> Result<Hash, VerificationError> {
        if self.swap_in_progress.load(Ordering::SeqCst) {
            return Err(VerificationError::InvalidState);
        }
    
        let double_buffer = self.double_buffer.as_ref()
            .ok_or(VerificationError::InvalidState)?;

        self.swap_in_progress.store(true, Ordering::SeqCst);

        let back_buffer_hash = hash::hash_memory(
            VirtAddr::new(double_buffer.as_ptr() as u64),
            double_buffer.len()
        );

        let front_buffer_hash = hash::hash_memory(
            self.buffer,
            self.size
        );

        self.back_buffer_hash.store(back_buffer_hash.0, Ordering::SeqCst);
        self.front_buffer_hash.store(front_buffer_hash.0, Ordering::SeqCst);

        unsafe {
            core::ptr::copy_nonoverlapping(
                double_buffer.as_ptr(),
                self.buffer.as_mut_ptr(),
                double_buffer.len()
            );
        }

        let new_front_hash = hash::hash_memory(
            self.buffer,
            self.size
        );
    
        if new_front_hash.0 != back_buffer_hash.0 {
            unsafe {
                let mut prev_buffer = vec![0u8; self.size];
                core::ptr::copy_nonoverlapping(
                    self.buffer.as_ptr(),
                    prev_buffer.as_mut_ptr(),
                    self.size
                );

                core::ptr::copy_nonoverlapping(
                    prev_buffer.as_ptr(),
                    self.buffer.as_mut_ptr(),
                    self.size
                );
            }
            self.swap_in_progress.store(false, Ordering::SeqCst);
            return Err(VerificationError::OperationFailed);
        }

        let new_state = Hash(front_buffer_hash.0 ^ back_buffer_hash.0);
        self.state_hash.store(new_state.0, Ordering::SeqCst);

        self.swap_in_progress.store(false, Ordering::SeqCst);
    
        Ok(new_state)
    }

    pub fn flip_page(&mut self) -> Result<Hash, VerificationError> {
        if !self.info.page_flip_supported {
            return Err(VerificationError::InvalidOperation);
        }
    
        if self.flip_in_progress.load(Ordering::SeqCst) {
            return Err(VerificationError::InvalidState);
        }
    
        self.flip_in_progress.store(true, Ordering::SeqCst);
    
        self.wait_for_vsync()?;

        let current_buffer = VirtAddr::new(self.active_buffer.load(Ordering::SeqCst));
        let next_buffer = if current_buffer == self.page1_buffer {
            self.page2_buffer
        } else {
            self.page1_buffer
        };

        let next_hash = hash::hash_memory(next_buffer, self.size);

        unsafe {
            let mut crt_port = self.vga_crt_port.lock();
            let offset = (next_buffer.as_u64() >> 12) as u16;

            crt_port.write(0x0Cu16);
            Port::new(0x3D5).write((offset >> 8) as u8);

            crt_port.write(0x0Du16);
            Port::new(0x3D5).write(offset as u8);
        }

        self.active_buffer.store(next_buffer.as_u64(), Ordering::SeqCst);
        self.state_hash.store(next_hash.0, Ordering::SeqCst);
        self.flip_in_progress.store(false, Ordering::SeqCst);
    
        Ok(next_hash)
    }

    pub fn get_active_buffer(&self) -> VirtAddr {
        VirtAddr::new(self.active_buffer.load(Ordering::SeqCst))
    }

    pub fn get_front_buffer_hash(&self) -> Hash {
        Hash(self.front_buffer_hash.load(Ordering::SeqCst))
    }
    
    pub fn get_back_buffer_hash(&self) -> Hash {
        Hash(self.back_buffer_hash.load(Ordering::SeqCst))
    }
    
    pub fn is_swap_in_progress(&self) -> bool {
        self.swap_in_progress.load(Ordering::SeqCst)
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