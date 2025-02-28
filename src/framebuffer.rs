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

use crate::serial_println;
use core::ptr::read_volatile;
use core::ptr::write_volatile;
use lazy_static::lazy_static;
use micromath::F32Ext;
use spin::Mutex;
use x86_64::instructions::port::Port;

const VGA_WIDTH: usize = 320;
const VGA_HEIGHT: usize = 200;
const VGA_BUFFER_ADDRESS: usize = 0xA0000;
const VGA_BUFFER_SIZE: usize = VGA_WIDTH * VGA_HEIGHT;

const VGA_MISC_WRITE: u16 = 0x3C2;
const VGA_CRTC_INDEX: u16 = 0x3D4;
const VGA_CRTC_DATA: u16 = 0x3D5;
const VGA_SEQ_INDEX: u16 = 0x3C4;
const VGA_SEQ_DATA: u16 = 0x3C5;
const VGA_GC_INDEX: u16 = 0x3CE;
const VGA_GC_DATA: u16 = 0x3CF;
const VGA_AC_INDEX: u16 = 0x3C0;
const VGA_AC_WRITE: u16 = 0x3C0;
const VGA_AC_READ: u16 = 0x3C1;
const VGA_INSTAT_READ: u16 = 0x3DA;

static mut BACK_BUFFER: [u8; VGA_BUFFER_SIZE] = [0; VGA_BUFFER_SIZE];

/// Represents a single pixel with an index.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Pixel {
    pub index: u8,
}

/// Represents a framebuffer for VGA graphics.
pub struct Framebuffer {
    front_buffer: *mut u8,
    back_buffer: *mut u8,
    double_buffering: bool,
}

unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

impl Framebuffer {
    /// Creates a new framebuffer instance.
    pub fn new() -> Self {
        unsafe {
            Self {
                front_buffer: VGA_BUFFER_ADDRESS as *mut u8,
                back_buffer: BACK_BUFFER.as_mut_ptr(),
                double_buffering: false,
            }
        }
    }

    /// Enables double buffering for the framebuffer.
    pub fn enable_double_buffering(&mut self) {
        self.double_buffering = true;
    }

    /// Plots a pixel at the specified (x, y) coordinates.
    ///
    /// # Arguments
    ///
    /// * `x` - The x-coordinate of the pixel.
    /// * `y` - The y-coordinate of the pixel.
    /// * `pixel` - The pixel to plot.
    pub fn plot_pixel(&mut self, x: usize, y: usize, pixel: Pixel) {
        if x >= VGA_WIDTH || y >= VGA_HEIGHT {
            return;
        }

        let offset = y * VGA_WIDTH + x;

        if x < 4 {
            serial_println!(
                "Writing pixel: x={}, y={}, offset={:#x}, value={:#x}",
                x,
                y,
                offset,
                pixel.index
            );
        }

        unsafe {
            write_volatile(
                if self.double_buffering {
                    self.back_buffer.add(offset)
                } else {
                    self.front_buffer.add(offset)
                },
                pixel.index,
            );
        }
    }

    /// Draws a circle with the specified center and radius.
    ///
    /// # Arguments
    ///
    /// * `center_x` - The x-coordinate of the circle's center.
    /// * `center_y` - The y-coordinate of the circle's center.
    /// * `radius` - The radius of the circle.
    /// * `pixel` - The pixel to use for drawing the circle.
    pub fn draw_circle(&mut self, center_x: usize, center_y: usize, radius: usize, pixel: Pixel) {
        for y in 0..self.height() {
            for x in 0..self.width() {
                let dx = (x as isize - center_x as isize).abs();
                let dy = (y as isize - center_y as isize).abs();
                let distance = ((dx * dx + dy * dy) as f32).sqrt();

                if distance <= radius as f32 {
                    self.plot_pixel(x, y, pixel);
                }
            }
        }
    }

    /// Draws a character at the specified (x, y) coordinates.
    ///
    /// # Arguments
    ///
    /// * `x` - The x-coordinate of the character's top-left corner.
    /// * `y` - The y-coordinate of the character's top-left corner.
    /// * `c` - The character to draw.
    /// * `pixel` - The pixel to use for drawing the character.
    pub fn draw_char(&mut self, x: usize, y: usize, c: char, pixel: Pixel) {
        let font = crate::font::FONT.lock();
        let glyph = font.get_glyph(c);

        for (row, glyph_row) in glyph.iter().enumerate() {
            for col in 0..8 {
                if (glyph_row & (0x80 >> col)) != 0 {
                    self.plot_pixel(x + col, y + row, pixel);
                }
            }
        }
    }

    /// Prints a string at the specified (x, y) coordinates.
    ///
    /// # Arguments
    ///
    /// * `x` - The x-coordinate of the string's starting position.
    /// * `y` - The y-coordinate of the string's starting position.
    /// * `text` - The string to print.
    /// * `pixel` - The pixel to use for drawing the string.
    pub fn print_string(&mut self, x: usize, y: usize, text: &str, pixel: Pixel) {
        let mut current_x = x;
        for c in text.chars() {
            if current_x + 8 >= self.width() {
                break;
            }
            self.draw_char(current_x, y, c, pixel);
            current_x += 8;
        }
    }

    /// Clears the framebuffer with the specified pixel.
    ///
    /// # Arguments
    ///
    /// * `pixel` - The pixel to use for clearing the framebuffer.
    pub fn clear(&mut self, pixel: Pixel) {
        serial_println!("Starting clear with color index {:#x}", pixel.index);

        for i in 0..VGA_BUFFER_SIZE {
            if i % VGA_WIDTH == 0 {
                serial_println!("Writing scanline {}, offset={:#x}", i / VGA_WIDTH, i);
            }

            unsafe {
                write_volatile(
                    if self.double_buffering {
                        self.back_buffer.add(i)
                    } else {
                        self.front_buffer.add(i)
                    },
                    pixel.index,
                );
            }
        }
        serial_println!("Clear operation completed");
    }

    /// Draws a rectangle at the specified (x, y) coordinates with the given width and height.
    ///
    /// # Arguments
    ///
    /// * `x` - The x-coordinate of the rectangle's top-left corner.
    /// * `y` - The y-coordinate of the rectangle's top-left corner.
    /// * `width` - The width of the rectangle.
    /// * `height` - The height of the rectangle.
    /// * `pixel` - The pixel to use for drawing the rectangle.
    pub fn draw_rect(&mut self, x: usize, y: usize, width: usize, height: usize, pixel: Pixel) {
        for cy in y..core::cmp::min(y + height, VGA_HEIGHT) {
            for cx in x..core::cmp::min(x + width, VGA_WIDTH) {
                self.plot_pixel(cx, cy, pixel);
            }
        }
    }

    /// Swaps the front and back buffers if double buffering is enabled.
    pub fn swap_buffers(&mut self) {
        if !self.double_buffering {
            return;
        }

        for i in 0..VGA_BUFFER_SIZE {
            unsafe {
                let pixel = read_volatile(self.back_buffer.add(i));
                write_volatile(self.front_buffer.add(i), pixel);
            }
        }
    }

    /// Returns the width of the framebuffer.
    pub fn width(&self) -> usize {
        VGA_WIDTH
    }

    /// Returns the height of the framebuffer.
    pub fn height(&self) -> usize {
        VGA_HEIGHT
    }
}

lazy_static! {
    /// Global framebuffer instance protected by a mutex.
    pub static ref FRAMEBUFFER: Mutex<Option<Framebuffer>> = Mutex::new(None);
}

pub const BLACK: Pixel = Pixel { index: 0 };
pub const BLUE: Pixel = Pixel { index: 1 };
pub const GREEN: Pixel = Pixel { index: 2 };
pub const CYAN: Pixel = Pixel { index: 3 };
pub const RED: Pixel = Pixel { index: 4 };
pub const MAGENTA: Pixel = Pixel { index: 5 };
pub const BROWN: Pixel = Pixel { index: 6 };
pub const LIGHT_GRAY: Pixel = Pixel { index: 7 };
pub const DARK_GRAY: Pixel = Pixel { index: 8 };
pub const LIGHT_BLUE: Pixel = Pixel { index: 9 };
pub const LIGHT_GREEN: Pixel = Pixel { index: 10 };
pub const LIGHT_CYAN: Pixel = Pixel { index: 11 };
pub const LIGHT_RED: Pixel = Pixel { index: 12 };
pub const LIGHT_MAGENTA: Pixel = Pixel { index: 13 };
pub const YELLOW: Pixel = Pixel { index: 14 };
pub const WHITE: Pixel = Pixel { index: 15 };

const VGA_DAC_WRITE_INDEX: u16 = 0x3C8;
const VGA_DAC_DATA: u16 = 0x3C9;
const VGA_DAC_READ_INDEX: u16 = 0x3C7;
const VGA_DAC_STATE: u16 = 0x3C7;

/// Prints the current state of various VGA registers for debugging purposes.
fn debug_vga_state() {
    unsafe {
        let mut crtc_index = Port::<u8>::new(VGA_CRTC_INDEX);
        let mut crtc_data = Port::<u8>::new(VGA_CRTC_DATA);

        serial_println!("=== CRTC Register State ===");
        for i in 0..25 {
            crtc_index.write(i as u8);
            let value = crtc_data.read();
            serial_println!("CRTC {:#04x}: {:#04x}", i, value);
        }

        let mut seq_index = Port::<u8>::new(VGA_SEQ_INDEX);
        let mut seq_data = Port::<u8>::new(VGA_SEQ_DATA);

        serial_println!("=== Sequencer Register State ===");
        for i in 0..5 {
            seq_index.write(i as u8);
            let value = seq_data.read();
            serial_println!("SEQ {:#04x}: {:#04x}", i, value);
        }

        let mut gc_index = Port::<u8>::new(VGA_GC_INDEX);
        let mut gc_data = Port::<u8>::new(VGA_GC_DATA);

        serial_println!("=== Graphics Controller Register State ===");
        for i in 0..9 {
            gc_index.write(i as u8);
            let value = gc_data.read();
            serial_println!("GC {:#04x}: {:#04x}", i, value);
        }
    }
}

/// Initializes the VGA DAC with a predefined palette.
fn init_vga_dac() {
    unsafe {
        serial_println!("Initializing VGA DAC...");
        let mut write_index = Port::<u8>::new(VGA_DAC_WRITE_INDEX);
        let mut dac_data = Port::<u8>::new(VGA_DAC_DATA);

        write_index.write(0);

        let palette: [(u8, u8, u8); 16] = [
            (0, 0, 0),
            (0, 0, 63),
            (0, 63, 0),
            (0, 63, 63),
            (63, 0, 0),
            (63, 0, 63),
            (63, 32, 0),
            (63, 63, 63),
            (32, 32, 32),
            (32, 32, 63),
            (32, 63, 32),
            (32, 63, 63),
            (63, 32, 32),
            (63, 32, 63),
            (63, 63, 32),
            (63, 63, 63),
        ];

        for (r, g, b) in palette.iter() {
            dac_data.write(*r);
            dac_data.write(*g);
            dac_data.write(*b);
        }

        serial_println!("DAC initialization completed");
    }
}

/// Verifies the current VGA mode settings.
fn verify_mode_13h() {
    unsafe {
        let mut seq_index = Port::<u8>::new(VGA_SEQ_INDEX);
        let mut seq_data = Port::<u8>::new(VGA_SEQ_DATA);
        let mut gc_index = Port::<u8>::new(VGA_GC_INDEX);
        let mut gc_data = Port::<u8>::new(VGA_GC_DATA);

        seq_index.write(0x04_u8);
        let chain4 = seq_data.read();
        serial_println!("Chain-4 mode: {:#02x} (should be 0x08)", chain4);

        gc_index.write(0x06_u8);
        let memory_mode = gc_data.read();
        serial_println!("Memory mapping: {:#02x} (should be 0x05)", memory_mode);
    }
}

/// Checks the current status of various VGA registers.
fn check_vga_status() {
    unsafe {
        let _misc_port = Port::<u8>::new(VGA_MISC_WRITE);
        let misc_value = Port::<u8>::new(0x3CC).read();
        serial_println!("Misc Output Register: {:#02x}", misc_value);

        let mut seq_index = Port::<u8>::new(VGA_SEQ_INDEX);
        let mut seq_data = Port::<u8>::new(VGA_SEQ_DATA);

        seq_index.write(0x00_u8);
        let seq_reset = seq_data.read();
        serial_println!("Sequencer Reset: {:#02x}", seq_reset);

        seq_index.write(0x04_u8);
        let seq_memory_mode = seq_data.read();
        serial_println!("Memory Mode: {:#02x}", seq_memory_mode);

        let mut gc_index = Port::<u8>::new(VGA_GC_INDEX);
        let mut gc_data = Port::<u8>::new(VGA_GC_DATA);

        gc_index.write(0x06_u8);
        let graphics_mode = gc_data.read();
        serial_println!("Graphics Mode: {:#02x}", graphics_mode);

        gc_index.write(0x05_u8);
        let graphics_mode_reg = gc_data.read();
        serial_println!("Graphics Mode Register: {:#02x}", graphics_mode_reg);
    }
}

/// Resets the VGA to a known state.
fn reset_vga() {
    unsafe {
        serial_println!("Starting VGA reset sequence...");

        let mut seq_index = Port::<u8>::new(VGA_SEQ_INDEX);
        let mut seq_data = Port::<u8>::new(VGA_SEQ_DATA);

        seq_index.write(0x00_u8);
        seq_data.write(0x00_u8);

        for i in 0..5 {
            seq_index.write(i);
            seq_data.write(0x00_u8);
        }

        let mut gc_index = Port::<u8>::new(VGA_GC_INDEX);
        let mut gc_data = Port::<u8>::new(VGA_GC_DATA);

        for i in 0..9 {
            gc_index.write(i);
            gc_data.write(0x00_u8);
        }

        let mut instat_port = Port::<u8>::new(VGA_INSTAT_READ);
        let mut ac_port = Port::<u8>::new(VGA_AC_INDEX);

        let _ = instat_port.read();

        for i in 0..0x15 {
            ac_port.write(i);
            ac_port.write(0x00_u8);
        }

        let mut crtc_index = Port::<u8>::new(VGA_CRTC_INDEX);
        let mut crtc_data = Port::<u8>::new(VGA_CRTC_DATA);

        for i in 0..0x19 {
            crtc_index.write(i);
            crtc_data.write(0x00_u8);
        }

        let _ = instat_port.read();
        ac_port.write(0x20_u8);

        seq_index.write(0x00_u8);
        seq_data.write(0x03_u8);

        serial_println!("VGA reset sequence completed");
    }
}

/// Verifies the CRTC offset register.
fn verify_crtc_offset() {
    unsafe {
        let mut crtc_index = Port::<u8>::new(VGA_CRTC_INDEX);
        let mut crtc_data = Port::<u8>::new(VGA_CRTC_DATA);

        crtc_index.write(0x13);
        let offset = crtc_data.read();
        serial_println!("CRTC Offset Register (0x13) = {:#x}", offset);

        let bytes_per_line = (offset as u16) * 2;
        serial_println!("CRTC configured bytes per line: {}", bytes_per_line);
    }
}

/// Verifies the memory layout of the VGA.
fn verify_memory_layout() {
    unsafe {
        let mut crtc_index = Port::<u8>::new(VGA_CRTC_INDEX);
        let mut crtc_data = Port::<u8>::new(VGA_CRTC_DATA);

        crtc_index.write(0x13);
        let hardware_offset = crtc_data.read();
        let hardware_stride = (hardware_offset as usize) * 4 * 2;
        let our_stride = VGA_WIDTH;

        serial_println!("Memory layout verification:");
        serial_println!("  Hardware offset register: {:#x}", hardware_offset);
        serial_println!("  Hardware stride: {} bytes", hardware_stride);
        serial_println!("  Our stride: {} bytes", our_stride);
        serial_println!(
            "  Mismatch: {} bytes",
            if hardware_stride > our_stride {
                hardware_stride - our_stride
            } else {
                our_stride - hardware_stride
            }
        );
    }
}

// fn test_solid_color() {
//     if let Some(fb) = &mut *FRAMEBUFFER.lock() {
//         serial_println!("Starting circle test for {}x{} framebuffer...", fb.width(), fb.height());
//         verify_crtc_offset();
//         verify_memory_layout();
//         unsafe {
//             let mut port = Port::<u8>::new(VGA_INSTAT_READ);
//             port.read();
//             while port.read() & 0x08 == 0 {}
//         }
//
//         fb.double_buffering = true;
//
//         fb.clear(WHITE);
//         let center_x = fb.width() / 2;
//         let center_y = fb.height() / 2;
//         let radius = 50;
//         fb.draw_circle(center_x, center_y, radius, RED);
//
//         fb.swap_buffers();
//         fb.double_buffering = false;
//         serial_println!("Circle test completed");
//     }
// }

/// VGA mode 13h miscellaneous output register value.
const MODE_13H_MISC: u8 = 0x63;

/// VGA mode 13h sequencer register values.
const MODE_13H_SEQ: &[u8] = &[0x03, 0x01, 0x0F, 0x00, 0x0E];

/// VGA mode 13h CRTC register values.
const MODE_13H_CRTC: &[u8] = &[
    0x5F, 0x4F, 0x50, 0x82, 0x54, 0x80, 0xBF, 0x1F, 0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9C, 0x8E, 0x8F, 0x28, 0x40, 0x96, 0xB9, 0xA3, 0xFF,
];

/// VGA mode 13h graphics controller register values.
const MODE_13H_GC: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x05, 0x0F, 0xFF];

/// Writes the VGA registers with the mode 13h values.
fn write_registers() {
    unsafe {
        let mut misc_port = Port::<u8>::new(VGA_MISC_WRITE);
        misc_port.write(0x00);

        let mut instat_port = Port::<u8>::new(VGA_INSTAT_READ);
        let _ = instat_port.read();

        misc_port.write(MODE_13H_MISC);

        let mut seq_index = Port::<u8>::new(VGA_SEQ_INDEX);
        let mut seq_data = Port::<u8>::new(VGA_SEQ_DATA);

        seq_index.write(0x00);
        seq_data.write(0x01);

        for (i, &value) in MODE_13H_SEQ.iter().enumerate() {
            seq_index.write(i as u8);
            seq_data.write(value);
            serial_println!("Writing SEQ {:#04x}: {:#04x}", i, value);
        }

        seq_index.write(0x00);
        seq_data.write(0x03);

        let mut crtc_index = Port::<u8>::new(VGA_CRTC_INDEX);
        let mut crtc_data = Port::<u8>::new(VGA_CRTC_DATA);

        crtc_index.write(0x11);
        let value = crtc_data.read() & 0x7F;
        crtc_data.write(value);

        for (i, &value) in MODE_13H_CRTC.iter().enumerate() {
            crtc_index.write(i as u8);
            let before = crtc_data.read();
            crtc_data.write(value);
            let after = crtc_data.read();
            serial_println!(
                "Writing CRTC {:#04x}: {:#04x} (before: {:#04x}, after: {:#04x})",
                i,
                value,
                before,
                after
            );
        }

        let mut gc_index = Port::<u8>::new(VGA_GC_INDEX);
        let mut gc_data = Port::<u8>::new(VGA_GC_DATA);

        for (i, &value) in MODE_13H_GC.iter().enumerate() {
            gc_index.write(i as u8);
            gc_data.write(value);
            serial_println!("Writing GC {:#04x}: {:#04x}", i, value);
        }

        misc_port.write(0x63);
    }
}

/// Sets up the CRTC timing for VGA mode 13h.
fn setup_crtc_timing() {
    unsafe {
        let mut crtc_index = Port::<u8>::new(VGA_CRTC_INDEX);
        let mut crtc_data = Port::<u8>::new(VGA_CRTC_DATA);

        crtc_index.write(0x11_u8);
        let current = crtc_data.read();
        crtc_data.write(current & 0x7F_u8);

        let timing_values: [(u8, u8); 10] = [
            (0x00, 0x5F),
            (0x01, 0x4F),
            (0x02, 0x50),
            (0x03, 0x82),
            (0x04, 0x54),
            (0x05, 0x80),
            (0x06, 0xBF),
            (0x07, 0x1F),
            (0x09, 0x40),
            (0x11, 0x0E),
        ];

        for (index, value) in timing_values.iter() {
            crtc_index.write(*index);
            crtc_data.write(*value);
        }

        crtc_index.write(0x15_u8);
        crtc_data.write(0x96_u8);

        crtc_index.write(0x16_u8);
        crtc_data.write(0xB9_u8);

        crtc_index.write(0x13_u8);
        crtc_data.write(0x28_u8);

        crtc_index.write(0x14_u8);
        crtc_data.write(0x00_u8);
    }
}

/// Sets the VGA to mode 13h.
fn set_mode_13h() {
    unsafe {
        serial_println!("Setting VGA Mode 13h...");

        let mut misc_port = Port::<u8>::new(VGA_MISC_WRITE);
        misc_port.write(0x63);

        let mut seq_index = Port::<u8>::new(VGA_SEQ_INDEX);
        let mut seq_data = Port::<u8>::new(VGA_SEQ_DATA);

        seq_index.write(0x00);
        seq_data.write(0x01);

        for i in 1..5 {
            seq_index.write(i);
            seq_data.write(0x00);
        }

        let seq_values: [(u8, u8); 4] = [(0x01, 0x01), (0x02, 0x0F), (0x03, 0x00), (0x04, 0x08)];

        for (index, value) in seq_values.iter() {
            seq_index.write(*index);
            seq_data.write(*value);

            seq_index.write(*index);
            let readback = seq_data.read();
            if readback != *value {
                serial_println!(
                    "SEQ register write verification failed: wrote {:#04x}, read {:#04x}",
                    value,
                    readback
                );
            }
        }

        seq_index.write(0x00);
        seq_data.write(0x03);

        let mut crtc_index = Port::<u8>::new(VGA_CRTC_INDEX);
        let mut crtc_data = Port::<u8>::new(VGA_CRTC_DATA);

        crtc_index.write(0x11);
        let value = crtc_data.read();
        crtc_data.write(value & 0x7F);

        let mut gc_index = Port::<u8>::new(VGA_GC_INDEX);
        let mut gc_data = Port::<u8>::new(VGA_GC_DATA);

        let gc_values: [(u8, u8); 9] = [
            (0x00, 0x00),
            (0x01, 0x00),
            (0x02, 0x00),
            (0x03, 0x00),
            (0x04, 0x00),
            (0x05, 0x40),
            (0x06, 0x05),
            (0x07, 0x0F),
            (0x08, 0xFF),
        ];

        for (index, value) in gc_values.iter() {
            gc_index.write(*index);
            gc_data.write(*value);

            gc_index.write(*index);
            let readback = gc_data.read();
            if readback != *value {
                serial_println!(
                    "GC register write verification failed: wrote {:#04x}, read {:#04x}",
                    value,
                    readback
                );
            }
        }

        serial_println!("Mode 13h base settings completed");
    }

    serial_println!("Mode 13h base settings completed");
    serial_println!("Checking CRTC offset after mode set:");
    verify_crtc_offset();
}

/// Initializes the VGA and sets it to mode 13h.
/// This function performs the following steps:
/// 1. Prints the initial VGA state.
/// 2. Resets the VGA.
/// 3. Prints the VGA state after reset.
/// 4. Sets the VGA to mode 13h.
/// 5. Prints the VGA state after setting mode 13h.
/// 6. Writes the VGA registers.
/// 7. Verifies the mode 13h settings.
/// 8. Prints the final VGA state.
/// 9. Initializes the VGA DAC.
/// 10. Creates a new framebuffer instance and stores it in the global framebuffer mutex.
// 11. Optionally, runs the `test_solid_color` function (currently commented out).
pub fn init() {
    serial_println!("Starting VGA initialization...");

    serial_println!("Initial VGA state:");
    debug_vga_state();

    reset_vga();

    serial_println!("Post-reset VGA state:");
    debug_vga_state();

    set_mode_13h();

    serial_println!("Post-Mode 13h VGA state:");
    debug_vga_state();

    write_registers();
    verify_mode_13h();

    serial_println!("Final VGA state:");
    debug_vga_state();

    init_vga_dac();

    let fb = Framebuffer::new();
    *FRAMEBUFFER.lock() = Some(fb);

    // test_solid_color();
}
