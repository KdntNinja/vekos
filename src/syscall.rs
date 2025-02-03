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
use core::slice;
use x86_64::registers::model_specific::Msr;
use core::arch::naked_asm;
use core::arch::asm;
use crate::vga_buffer::WRITER;
use crate::vga_buffer::ColorCode;
use crate::MEMORY_MANAGER;
use crate::vga_buffer::Color;
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

pub static TOP_OF_KERNEL_STACK: AtomicU64 = AtomicU64::new(0);
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

#[no_mangle]
pub extern "C" fn test_syscall_function() {
    serial_println!("=========================================================");
    serial_println!("============= TEST SYSCALL FUNCTION REACHED =============");
    serial_println!("=============  ASSEMBLY TO RUST IS WORKING  =============");
    serial_println!("=========================================================");
}

#[naked]
unsafe extern "x86-interrupt" fn syscall_handler() {
    naked_asm!(
        "swapgs",
        "mov gs:[0x0], rsp",
        "mov rsp, gs:[0x1000]",

        "cmp rax, 1",    
        "je 3f",
        
        "cmp rax, 2",    
        "je 5f",         

        "2:",
        "mov rsp, gs:[0x0]",
        "swapgs",
        "sysretq",

        "3:",
        "mov rdi, 0",
        "jmp 2b",

        "5:",

        "push rax",
        "push rcx",
        "push rdx",
        "push rbx",
        "push rbp",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        "mov rbp, rsp",
        "and rsp, -16",
        "sub rsp, 32",

        "call gs:[0x1008]",

        "mov rsp, rbp",

        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rbp",
        "pop rbx",
        "pop rdx",
        "pop rcx",
        "pop rax",
        
        "jmp 2b",
    );
}

pub fn init() {
    serial_println!("Starting syscall initialization...");

    unsafe {
        let kernel_region_start = VirtAddr::new(0xFFFF_8000_0000_0000);
        let scratch_region_start = VirtAddr::new(0xFFFF_8000_0001_0000);
        let handler_region = VirtAddr::new(0xFFFF_8000_0002_0000);

        let regions = [
            (kernel_region_start, 16 * 4096),
            (scratch_region_start, 16 * 4096),
            (handler_region, 4096),
        ];

        let mut mm_lock = MEMORY_MANAGER.lock();
        if let Some(mm) = mm_lock.as_mut() {
            for (addr, size) in regions.iter() {
                serial_println!("Verifying region at {:#x} size {:#x}", addr.as_u64(), size);
                if !mm.verify_memory_requirements(*size) {
                    panic!("Not enough memory for region at {:#x}", addr.as_u64());
                }
            }

            let stack_flags = PageTableFlags::PRESENT 
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::GLOBAL;

            let handler_flags = PageTableFlags::PRESENT 
                | PageTableFlags::WRITABLE 
                | PageTableFlags::USER_ACCESSIBLE
                | PageTableFlags::GLOBAL;

            for i in 0..16 {
                let frame = mm.frame_allocator
                    .allocate_frame()
                    .expect("Failed to allocate kernel frame");
                
                let page = Page::containing_address(kernel_region_start + (i * 4096) as u64);
                mm.map_page(page, frame, stack_flags)
                    .expect("Failed to map kernel region");

                let frame = mm.frame_allocator
                    .allocate_frame()
                    .expect("Failed to allocate scratch frame");
                
                let page = Page::containing_address(scratch_region_start + (i * 4096) as u64);
                mm.map_page(page, frame, stack_flags)
                    .expect("Failed to map scratch region");
            }

            let handler_frame = mm.frame_allocator
                .allocate_frame()
                .expect("Failed to allocate handler frame");
            
            let handler_page = Page::containing_address(handler_region);

            serial_println!("test_syscall_function address: {:#x}", test_syscall_function as *const () as u64);

            mm.map_page(handler_page, handler_frame, handler_flags)
                .expect("Failed to map handler page");

            let handler_src = syscall_handler as *const u8;
            let handler_dst = handler_region.as_mut_ptr::<u8>();
            core::ptr::copy_nonoverlapping(
                handler_src,
                handler_dst,
                4096
            );

            serial_println!("Mapped handler to virtual {:#x} physical {:#x}", 
                handler_region.as_u64(),
                handler_frame.start_address().as_u64());
        }
        drop(mm_lock);

        serial_println!("Setting up CPU state...");
        serial_println!("KernelGsBase setting to: {:#x}", kernel_region_start.as_u64());
        serial_println!("GsBase setting to: {:#x}", scratch_region_start.as_u64());
        x86_64::registers::model_specific::KernelGsBase::write(kernel_region_start);
        x86_64::registers::model_specific::GsBase::write(scratch_region_start);

        let scratch_ptr = scratch_region_start.as_u64() as *mut u64;
        unsafe {
            core::ptr::write(scratch_ptr.add(0x1000 / 8), kernel_region_start.as_u64() + (16 * 4096));
            core::ptr::write(scratch_ptr.add(0x1008 / 8), test_syscall_function as *const () as u64);
        }

        x86_64::registers::model_specific::Efer::update(|efer| {
            *efer |= x86_64::registers::model_specific::EferFlags::SYSTEM_CALL_EXTENSIONS;
        });
        
        x86_64::registers::model_specific::SFMask::write(x86_64::registers::rflags::RFlags::INTERRUPT_FLAG);
        serial_println!("Handler region for syscalls: {:#x}", handler_region.as_u64());
        x86_64::registers::model_specific::LStar::write(handler_region);

        x86_64::registers::model_specific::Star::write(
            SegmentSelector::new(2, x86_64::PrivilegeLevel::Ring3),
            SegmentSelector::new(1, x86_64::PrivilegeLevel::Ring3),
            SegmentSelector::new(1, x86_64::PrivilegeLevel::Ring0),
            SegmentSelector::new(2, x86_64::PrivilegeLevel::Ring0),
        ).expect("Failed to set STAR register");
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