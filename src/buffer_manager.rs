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

use crate::hash;
use crate::serial_println;
use crate::verification::{Hash, OperationProof, Verifiable, VerificationError};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::VirtAddr;

const BUFFER_SIZE: usize = 4096;
const MAX_BUFFERS: usize = 256;

/// Struct representing a buffer.
#[derive(Debug)]
pub struct Buffer {
    pub(crate) data: [u8; BUFFER_SIZE],
    pub(crate) block_num: u64,
    pub(crate) dirty: bool,
    pub(crate) pinned: bool,
    pub(crate) last_access: u64,
    pub(crate) access_count: u64,
}

impl Clone for Buffer {
    fn clone(&self) -> Self {
        Self {
            data: self.data,
            block_num: self.block_num,
            dirty: self.dirty,
            pinned: self.pinned,
            last_access: self.last_access,
            access_count: self.access_count,
        }
    }
}

/// Struct representing the buffer manager.
#[derive(Debug)]
pub struct BufferManager {
    buffers: VecDeque<Buffer>,
    free_buffers: Vec<Buffer>,
    stats: BufferStats,
    state_hash: AtomicU64,
}

/// Struct representing buffer statistics.
#[derive(Debug, Default)]
pub struct BufferStats {
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    writes: AtomicU64,
}

impl Buffer {
    /// Creates a new buffer.
    ///
    /// # Arguments
    ///
    /// * `block_num` - The block number associated with the buffer.
    ///
    /// # Returns
    ///
    /// A new `Buffer` instance.
    pub fn new(block_num: u64) -> Self {
        Self {
            data: [0; BUFFER_SIZE],
            block_num,
            dirty: false,
            pinned: false,
            last_access: 0,
            access_count: 0,
        }
    }

    /// Pins the buffer.
    pub fn pin(&mut self) {
        self.pinned = true;
    }

    /// Unpins the buffer.
    pub fn unpin(&mut self) {
        self.pinned = false;
    }

    /// Marks the buffer as dirty.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Checks if the buffer is dirty.
    ///
    /// # Returns
    ///
    /// `true` if the buffer is dirty, `false` otherwise.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Gets the data from the buffer.
    ///
    /// # Returns
    ///
    /// A slice of the buffer data.
    pub fn get_data(&self) -> &[u8] {
        &self.data[..]
    }

    /// Sets the data in the buffer.
    ///
    /// # Arguments
    ///
    /// * `new_data` - The new data to set in the buffer.
    pub fn set_data(&mut self, new_data: &[u8]) {
        self.data.copy_from_slice(new_data);
    }

    /// Clears the buffer.
    pub fn clear(&mut self) {
        self.data.fill(0);
        self.dirty = false;
        self.pinned = false;
        self.last_access = 0;
        self.access_count = 0;
    }
}

impl BufferManager {
    /// Creates a new buffer manager.
    ///
    /// # Returns
    ///
    /// A new `BufferManager` instance.
    pub fn new() -> Self {
        serial_println!("BufferManager: Starting initialization");

        const INITIAL_CAPACITY: usize = 32;

        let mut free_buffers = Vec::with_capacity(INITIAL_CAPACITY);

        for _ in 0..INITIAL_CAPACITY {
            free_buffers.push(Buffer::new(0));
        }

        serial_println!(
            "BufferManager: Created initial {} buffers",
            INITIAL_CAPACITY
        );

        Self {
            buffers: VecDeque::with_capacity(INITIAL_CAPACITY),
            free_buffers,
            stats: BufferStats::default(),
            state_hash: AtomicU64::new(0),
        }
    }

    /// Grows the buffer pool.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure.
    fn grow_buffer_pool(&mut self) -> Result<(), &'static str> {
        if self.free_buffers.len() >= MAX_BUFFERS {
            return Err("Maximum buffer pool size reached");
        }

        const GROWTH_CHUNK: usize = 16;
        let new_size = core::cmp::min(self.free_buffers.len() + GROWTH_CHUNK, MAX_BUFFERS);

        for _ in self.free_buffers.len()..new_size {
            self.free_buffers.push(Buffer::new(0));
        }

        Ok(())
    }

    /// Gets a buffer for a specific block number.
    ///
    /// # Arguments
    ///
    /// * `block_num` - The block number to get the buffer for.
    ///
    /// # Returns
    ///
    /// An `Option` containing a mutable reference to the buffer if found, or `None` if not found.
    pub fn get_buffer(&mut self, block_num: u64) -> Option<&mut Buffer> {
        serial_println!("BufferManager: Attempting to get buffer {}", block_num);

        if let Some(index) = self.buffers.iter().position(|b| b.block_num == block_num) {
            let buffer = &mut self.buffers[index];
            buffer.last_access = crate::tsc::read_tsc();
            buffer.access_count += 1;
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            Some(buffer)
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);

            if self.buffers.len() >= self.free_buffers.len() {
                if let Err(_) = self.grow_buffer_pool() {
                    self.evict_one();
                }
            }

            let mut new_buffer = Buffer::new(block_num);

            let block_addr = VirtAddr::new(block_num * BUFFER_SIZE as u64);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    block_addr.as_ptr::<u8>(),
                    new_buffer.data.as_mut_ptr(),
                    BUFFER_SIZE,
                );
            }

            self.buffers.push_back(new_buffer);
            let last_index = self.buffers.len() - 1;
            Some(&mut self.buffers[last_index])
        }
    }

    /// Releases a buffer for a specific block number.
    ///
    /// # Arguments
    ///
    /// * `block_num` - The block number to release the buffer for.
    pub fn release_buffer(&mut self, block_num: u64) {
        if let Some(pos) = self.buffers.iter().position(|b| b.block_num == block_num) {
            let mut buffer = self.buffers.remove(pos).unwrap();
            if buffer.is_dirty() {
                self.flush_buffer(buffer.block_num, buffer.data);
            }
            buffer.clear();
            self.free_buffers.push(buffer);
        }
    }

    /// Flushes all dirty buffers.
    pub fn flush_all(&mut self) {
        let dirty_buffers: Vec<_> = self
            .buffers
            .iter()
            .filter(|b| b.is_dirty())
            .map(|b| (b.block_num, b.data.clone()))
            .collect();

        for (block_num, data) in dirty_buffers {
            self.flush_buffer(block_num, data);
        }
    }

    /// Flushes a specific buffer.
    ///
    /// # Arguments
    ///
    /// * `block_num` - The block number of the buffer to flush.
    /// * `data` - The data to flush.
    fn flush_buffer(&mut self, block_num: u64, data: [u8; BUFFER_SIZE]) {
        let block_addr = block_num * BUFFER_SIZE as u64;
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                VirtAddr::new(block_addr).as_mut_ptr(),
                BUFFER_SIZE,
            );
        }
        self.stats.writes.fetch_add(1, Ordering::Relaxed);
    }

    /// Gets the buffer manager statistics.
    ///
    /// # Returns
    ///
    /// A tuple containing the hit count, miss count, eviction count, and write count.
    pub fn get_stats(&self) -> (u64, u64, u64, u64) {
        (
            self.stats.hits.load(Ordering::Relaxed),
            self.stats.misses.load(Ordering::Relaxed),
            self.stats.evictions.load(Ordering::Relaxed),
            self.stats.writes.load(Ordering::Relaxed),
        )
    }

    /// Evicts one buffer.
    pub fn evict_one(&mut self) {
        if let Some(idx) = self
            .buffers
            .iter()
            .enumerate()
            .filter(|(_, buffer)| !buffer.pinned)
            .min_by_key(|(_, buffer)| (buffer.access_count, buffer.last_access))
            .map(|(idx, _)| idx)
        {
            let buffer = &self.buffers[idx];
            if buffer.dirty {
                let block_num = buffer.block_num;
                let data = buffer.data;
                self.flush_buffer(block_num, data);
            }

            self.buffers.remove(idx);
            self.stats.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Verifiable for BufferManager {
    /// Generates a proof for a given operation.
    ///
    /// # Arguments
    ///
    /// * `operation` - The operation to generate a proof for.
    ///
    /// # Returns
    ///
    /// A `Result` containing the generated `OperationProof` or a `VerificationError`.
    fn generate_proof(
        &self,
        _operation: crate::verification::Operation,
    ) -> Result<OperationProof, VerificationError> {
        let prev_state = self.state_hash();

        let mut buffer_hashes = Vec::new();
        for buffer in &self.buffers {
            let buffer_hash =
                hash::hash_memory(VirtAddr::new(buffer.data.as_ptr() as u64), BUFFER_SIZE);
            buffer_hashes.push(buffer_hash);
        }

        let combined_hash = hash::combine_hashes(&buffer_hashes);
        let new_state = Hash(prev_state.0 ^ combined_hash.0);

        Ok(OperationProof {
            op_id: crate::tsc::read_tsc(),
            prev_state,
            new_state,
            data: crate::verification::ProofData::Memory(crate::verification::MemoryProof {
                operation: crate::verification::MemoryOpType::Modify,
                address: VirtAddr::new(0),
                size: 0,
                frame_hash: combined_hash,
            }),
            signature: [0u8; 64],
        })
    }

    /// Verifies a given proof.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify.
    ///
    /// # Returns
    ///
    /// A `Result` indicating whether the proof is valid or a `VerificationError`.
    fn verify_proof(&self, proof: &OperationProof) -> Result<bool, VerificationError> {
        let current_state = self.state_hash();
        Ok(current_state == proof.new_state)
    }

    /// Retrieves the current state hash.
    ///
    /// # Returns
    ///
    /// The current state hash.
    fn state_hash(&self) -> Hash {
        Hash(self.state_hash.load(Ordering::SeqCst))
    }
}
