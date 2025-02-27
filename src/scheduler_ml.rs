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

use crate::process::{Process, ProcessId};
use crate::tsc;
use crate::verification::{Hash, OperationProof, Verifiable, VerificationError, Operation, ProofData};
use crate::hash;
use crate::serial_println;
use alloc::collections::BTreeMap;
use alloc::string::String;
use crate::alloc::string::ToString;
use alloc::format;
use spin::Mutex;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::VirtAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProcessType {
    CpuBound,
    IoBound,
    Interactive,
    Background,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    IncreasePriority,
    DecreasePriority,
    IncreaseTimeSlice,
    DecreaseTimeSlice,
    NoAction,
}

pub struct QEntry {
    value: i32,
    visits: u32,
}

pub struct SchedulerModel {
    q_table: BTreeMap<(ProcessType, Action), QEntry>,
    state_hash: AtomicU64,
    learning_rate: i32,
}

impl SchedulerModel {
    pub fn new() -> Self {
        serial_println!("Initializing scheduler ML model");
        
        let mut model = Self {
            q_table: BTreeMap::new(),
            state_hash: AtomicU64::new(0),
            learning_rate: 100,
        };
        
        model.initialize_q_table();

        let initial_hash = model.compute_model_hash();
        model.state_hash.store(initial_hash.0, Ordering::SeqCst);
        
        serial_println!("Scheduler ML model initialized successfully with hash {:x}", initial_hash.0);
        model
    }

    fn initialize_q_table(&mut self) {
        for process_type in [ProcessType::CpuBound, ProcessType::IoBound, 
                            ProcessType::Interactive, ProcessType::Background, 
                            ProcessType::Unknown].iter() {
            for action in [Action::IncreasePriority, Action::DecreasePriority,
                         Action::IncreaseTimeSlice, Action::DecreaseTimeSlice,
                         Action::NoAction].iter() {

                let initial_value = match (*process_type, *action) {
                    (ProcessType::CpuBound, Action::IncreaseTimeSlice) => 500,
                    (ProcessType::CpuBound, Action::DecreasePriority) => 300,

                    (ProcessType::IoBound, Action::IncreasePriority) => 500,
                    (ProcessType::IoBound, Action::DecreaseTimeSlice) => 300,

                    (ProcessType::Interactive, Action::IncreasePriority) => 700,

                    (ProcessType::Background, Action::DecreasePriority) => 400,

                    (_, Action::NoAction) => 200,

                    _ => 0,
                };
                
                self.q_table.insert((*process_type, *action), QEntry {
                    value: initial_value,
                    visits: 1,
                });
            }
        }
        
        serial_println!("Q-table initialized with {} entries", self.q_table.len());
    }

    pub fn classify_process(&self, process: &Process) -> ProcessType {
        let time_slice_used_percent = if process.remaining_time_slice > 90 {
            0
        } else if process.remaining_time_slice < 10 {
            100
        } else {
            100 - (process.remaining_time_slice * 100 / 100)
        };
        
        if time_slice_used_percent > 90 {
            ProcessType::CpuBound
        } else if time_slice_used_percent < 30 {
            ProcessType::IoBound
        } else if process.context_switches > 100 {
            ProcessType::Interactive
        } else if process.priority > 7 {
            ProcessType::Background
        } else {
            ProcessType::Unknown
        }
    }

    pub fn decide_action(&mut self, process: &Process) -> Action {
        let process_type = self.classify_process(process);
        
        serial_println!("Scheduler ML: Process {} classified as {:?}", process.id().0, process_type);

        if tsc::read_tsc() % 10 == 0 {
            let actions = [Action::IncreasePriority, Action::DecreasePriority,
                         Action::IncreaseTimeSlice, Action::DecreaseTimeSlice, 
                         Action::NoAction];
            let idx = (tsc::read_tsc() % 5) as usize;
            let random_action = actions[idx % actions.len()];
            
            serial_println!("Scheduler ML: Exploring random action: {:?} for process {}", 
                          random_action, process.id().0);
            return random_action;
        }
    
        let mut best_action = Action::NoAction;
        let mut best_value = i32::MIN;
        
        serial_println!("Scheduler ML: Evaluating Q-values for each action:");
        
        for action in [Action::IncreasePriority, Action::DecreasePriority,
                      Action::IncreaseTimeSlice, Action::DecreaseTimeSlice,
                      Action::NoAction].iter() {
            if let Some(entry) = self.q_table.get(&(process_type, *action)) {
                serial_println!("Scheduler ML:   Action {:?}: Q-value {:.3}", 
                              *action, entry.value as f32 / 1000.0);
                if entry.value > best_value {
                    best_value = entry.value;
                    best_action = *action;
                }
            } else {
                serial_println!("Scheduler ML:   Action {:?}: No Q-value yet", *action);
            }
        }
        
        serial_println!("Scheduler ML: Selected action {:?} with Q-value {:.3} for process {}", 
                      best_action, best_value as f32 / 1000.0, process.id().0);
        
        best_action
    }

    pub fn update_model(&mut self, process: &Process, action: Action, reward: i32) {
        let process_type = self.classify_process(process);
        let key = (process_type, action);
        
        serial_println!("Scheduler ML: Updating model for process {} (type: {:?}, action: {:?}, reward: {})", 
                      process.id().0, process_type, action, reward);

        if reward < -10000 || reward > 10000 {
            serial_println!("Scheduler ML: Warning - Ignoring extreme reward value: {}", reward);
            return;
        }
        
        if let Some(entry) = self.q_table.get_mut(&key) {
            let delta = ((reward.saturating_sub(entry.value)).saturating_mul(self.learning_rate)) / 1000;
            entry.value = entry.value.saturating_add(delta);
            entry.visits = entry.visits.saturating_add(1);
            
            serial_println!("Scheduler ML: Updated Q-value to {:.3} (delta: {:.3}, visits: {})", 
                          entry.value as f32 / 1000.0, 
                          delta as f32 / 1000.0, 
                          entry.visits);
    
            let new_hash = self.compute_model_hash();
            self.state_hash.store(new_hash.0, Ordering::SeqCst);
        } else {
            serial_println!("Scheduler ML: Creating new Q-table entry for ({:?}, {:?})", process_type, action);
            self.q_table.insert(key, QEntry {
                value: reward.clamp(-1000, 1000),
                visits: 1,
            });
        }
        
        serial_println!("Scheduler ML: Model update completed successfully");
    }

    pub fn get_statistics(&self) -> BTreeMap<String, f32> {
        let mut stats = BTreeMap::new();

        for process_type in [ProcessType::CpuBound, ProcessType::IoBound, 
                            ProcessType::Interactive, ProcessType::Background,
                            ProcessType::Unknown].iter() {
            let mut values_sum = 0;
            let mut count = 0;
            
            for ((pt, _), entry) in &self.q_table {
                if *pt == *process_type {
                    values_sum += entry.value;
                    count += 1;
                }
            }
            
            if count > 0 {
                stats.insert(format!("{:?}_avg", process_type), 
                            (values_sum as f32) / (count as f32 * 1000.0));
            }
        }

        stats.insert("learning_rate".to_string(), self.learning_rate as f32 / 1000.0);
        stats.insert("table_size".to_string(), self.q_table.len() as f32);
        
        stats
    }

    pub fn log_state(&self) {
        serial_println!("Scheduler ML model state:");
        serial_println!("  Q-table entries: {}", self.q_table.len());
        serial_println!("  Learning rate: {:.3}", self.learning_rate as f32 / 1000.0);
        
        let stats = self.get_statistics();
        for (key, value) in &stats {
            serial_println!("  {}: {:.3}", key, value);
        }
    }

    fn compute_model_hash(&self) -> Hash {
        let mut values = [0u64; 64];
        let mut i = 0;
        
        for ((pt, action), entry) in &self.q_table {
            if i < 60 {
                values[i] = (*pt as u64) << 56 | (*action as u64) << 48 | 
                           (entry.value.unsigned_abs() as u64 & 0xFFFFFFFF);
                i += 1;
            }
        }

        if i < values.len() {
            values[i] = self.learning_rate as u64;
        }
    
        hash::hash_memory(
            VirtAddr::new(values.as_ptr() as u64),
            core::mem::size_of_val(&values)
        )
    }
    
}

impl Verifiable for SchedulerModel {
    fn generate_proof(&self, operation: Operation) -> Result<OperationProof, VerificationError> {
        let prev_state = self.state_hash();
        
        match operation {
            Operation::Generic { name, data_hash } if name == "scheduler_ml" => {
                let model_hash = self.compute_model_hash();
                
                let proof_data = ProofData::Generic {
                    operation_type: "scheduler_ml".to_string(),
                    data_hash: model_hash,
                };
                
                let new_state = Hash(prev_state.0 ^ model_hash.0);
                let signature = [0u8; 64];
                
                Ok(OperationProof {
                    op_id: tsc::read_tsc(),
                    prev_state,
                    new_state,
                    data: proof_data,
                    signature,
                })
            },
            _ => Err(VerificationError::InvalidOperation),
        }
    }
    
    fn verify_proof(&self, proof: &OperationProof) -> Result<bool, VerificationError> {
        if proof.prev_state != self.state_hash() {
            return Ok(false);
        }
        
        match &proof.data {
            ProofData::Generic { operation_type, data_hash } if operation_type == "scheduler_ml" => {
                let current_hash = self.compute_model_hash();

                if *data_hash != current_hash {
                    return Ok(false);
                }

                let computed_state = Hash(proof.prev_state.0 ^ current_hash.0);
                if computed_state != proof.new_state {
                    return Ok(false);
                }
                
                Ok(true)
            },
            _ => Err(VerificationError::InvalidProof),
        }
    }
    
    fn state_hash(&self) -> Hash {
        Hash(self.state_hash.load(Ordering::SeqCst))
    }
}