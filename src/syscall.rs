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

use x86_64::{
    VirtAddr,
};

use x86_64::instructions::interrupts;
use crate::serial_println;
use x86_64::registers::model_specific::Msr;
use core::arch::naked_asm;
use core::arch::asm;
use crate::MEMORY_MANAGER;
use x86_64::structures::paging::PageTableFlags;
use x86_64::structures::paging::Page;
use x86_64::structures::paging::PhysFrame;
use x86_64::registers::model_specific::Efer;
use core::sync::atomic::AtomicU64;
use x86_64::registers::model_specific::SFMask;
use x86_64::registers::rflags::RFlags;
use x86_64::registers::model_specific::Star;
use x86_64::PhysAddr;
use x86_64::structures::gdt::SegmentSelector;
use x86_64::registers::model_specific::LStar;
use x86_64::structures::paging::FrameAllocator;
use crate::gdt::GDT;
use spin::Mutex;
use lazy_static::lazy_static;
use alloc::vec::Vec;

static TOP_OF_KERNEL_STACK: AtomicU64 = AtomicU64::new(0);
static USER_STACK_SCRATCH: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct MemoryAllocation {
    pub size: usize,
    pub address: VirtAddr,
}

#[derive(Clone)]
pub struct ProcessMemory {
    pub heap_size: usize,
    pub allocations: Vec<MemoryAllocation>,
    pub total_allocated: usize,
}

#[naked]
unsafe extern "x86-interrupt" fn syscall_handler() {
    naked_asm!(
        "swapgs",
        "mov gs:[0x0], rsp",
        "mov rsp, gs:[0x1000]",

        "cmp rax, 1",
        "je 3f",

        "2:",
        "mov rsp, gs:[0x0]",
        "swapgs",
        "sysretq",

        "3:",
        "mov rdi, 0",
        "jmp 2b",
    );
}

pub fn init() {
    serial_println!("Starting syscall initialization...");

    unsafe {
        serial_println!("Setting up kernel stack variables...");
        let mut current_kernel_stack: u64;
        asm!("mov {}, rsp", out(reg) current_kernel_stack);

        const REGION_SIZE: usize = 16 * 4096;
        let kernel_region_start = VirtAddr::new(0xFFFF_8000_0000_0000);
        let scratch_region_start = VirtAddr::new(0xFFFF_8000_0001_0000);

        TOP_OF_KERNEL_STACK.store(kernel_region_start.as_u64(), core::sync::atomic::Ordering::SeqCst);
        USER_STACK_SCRATCH.store(scratch_region_start.as_u64(), core::sync::atomic::Ordering::SeqCst);

        let mut mm_lock = MEMORY_MANAGER.lock();
        if let Some(mm) = mm_lock.as_mut() {
            let flags = PageTableFlags::PRESENT 
                | PageTableFlags::WRITABLE 
                | PageTableFlags::NO_EXECUTE;

            for i in 0..16 {
                let kernel_frame = mm.frame_allocator
                    .allocate_frame()
                    .expect("Failed to allocate kernel frame");
            
                let page_addr = kernel_region_start + (i as u64 * 4096);
                let kernel_page = Page::containing_address(page_addr);
                mm.map_page(kernel_page, kernel_frame, flags)
                    .expect("Failed to map kernel region");

                page_addr.as_mut_ptr::<u8>()
                    .write_bytes(0, 4096);
            }

            for i in 0..16 {
                let scratch_frame = mm.frame_allocator
                    .allocate_frame()
                    .expect("Failed to allocate scratch frame");
            
                let page_addr = scratch_region_start + (i as u64 * 4096);
                let scratch_page = Page::containing_address(page_addr);
                mm.map_page(scratch_page, scratch_frame, flags)
                    .expect("Failed to map scratch region");

                page_addr.as_mut_ptr::<u8>()
                    .write_bytes(0, 4096);
            }
        }
        drop(mm_lock);

        serial_println!("Initializing GS bases...");
        x86_64::registers::model_specific::KernelGsBase::write(kernel_region_start);
        x86_64::registers::model_specific::GsBase::write(scratch_region_start);

        serial_println!("Checking GS base setup...");
        let gs_base = x86_64::registers::model_specific::GsBase::read();
        serial_println!("Current GS base: {:#x}", gs_base);
        let kernel_gs_base = x86_64::registers::model_specific::KernelGsBase::read();
        serial_println!("Current Kernel GS base: {:#x}", kernel_gs_base);

        serial_println!("Enabling SCE...");
        x86_64::registers::model_specific::Efer::update(|efer| {
            *efer |= x86_64::registers::model_specific::EferFlags::SYSTEM_CALL_EXTENSIONS;
        });
        serial_println!("SCE enabled successfully");

        serial_println!("Setting up SFMASK...");
        x86_64::registers::model_specific::SFMask::write(x86_64::registers::rflags::RFlags::INTERRUPT_FLAG);
        serial_println!("SFMASK set successfully");

        serial_println!("Setting up syscall handler...");
        let handler_addr = VirtAddr::new(syscall_handler as usize as u64);
        x86_64::registers::model_specific::LStar::write(handler_addr);
        serial_println!("Syscall handler set to {:#x}", handler_addr.as_u64());

        serial_println!("Setting up STAR register...");
        match x86_64::registers::model_specific::Star::write(
            SegmentSelector::new(2, x86_64::PrivilegeLevel::Ring3),
            SegmentSelector::new(1, x86_64::PrivilegeLevel::Ring3),
            SegmentSelector::new(1, x86_64::PrivilegeLevel::Ring0),
            SegmentSelector::new(2, x86_64::PrivilegeLevel::Ring0),
        ) {
            Ok(_) => serial_println!("STAR register set successfully"),
            Err(e) => serial_println!("Failed to set STAR register: {:?}", e),
        }
    }

    serial_println!("Syscall initialization complete");
}

impl ProcessMemory {
    pub fn new() -> Self {
        Self {
            heap_size: 0,
            allocations: Vec::new(),
            total_allocated: 0,
        }
    }
}

lazy_static! {
    pub static ref KEYBOARD_BUFFER: Mutex<Vec<u8>> = Mutex::new(Vec::with_capacity(1024));
}

pub fn push_to_keyboard_buffer(c: u8) {
    interrupts::without_interrupts(|| {
        let mut buffer = KEYBOARD_BUFFER.lock();
        if buffer.len() < 1024 {
            buffer.push(c);
            serial_println!("Added to keyboard buffer: {} ({})", c as char, c);
        } else {
            serial_println!("Keyboard buffer full!");
        }
    });
}