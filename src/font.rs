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

use lazy_static::lazy_static;
use spin::Mutex;

/// The font data loaded from a binary file.
const FONT_DATA: &[u8; 4096] = include_bytes!("../assets/font8x16.bin");

/// The height of each glyph in the font.
const GLYPH_HEIGHT: usize = 16;

/// The width of each glyph in the font.
const GLYPH_WIDTH: usize = 8;

/// Struct representing a font.
pub struct Font {
    data: &'static [u8; 4096],
}

impl Font {
    /// Creates a new `Font` instance.
    ///
    /// # Returns
    ///
    /// A new `Font` instance.
    pub fn new() -> Self {
        Self { data: FONT_DATA }
    }

    /// Retrieves the glyph data for a given character.
    ///
    /// # Arguments
    ///
    /// * `c` - The character to retrieve the glyph for.
    ///
    /// # Returns
    ///
    /// A slice of bytes representing the glyph data.
    pub fn get_glyph(&self, c: char) -> &[u8] {
        let idx = c as usize * GLYPH_HEIGHT;
        &self.data[idx..idx + GLYPH_HEIGHT]
    }
}

/// Global instance of `Font` protected by a `Mutex`.
lazy_static! {
    pub static ref FONT: Mutex<Font> = Mutex::new(Font::new());
}
