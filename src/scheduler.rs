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

use crate::println;
use crate::process::{Process, ProcessId, ProcessState, PROCESS_LIST};
use x86_64::{registers::control::Cr3, VirtAddr};

use crate::priority::PriorityScheduler;
use crate::scheduler_ml::{Action, SchedulerModel};
use crate::serial_println;
use crate::signals::Signal;
use crate::MEMORY_MANAGER;
use crate::SYSTEM_TIME;
use alloc::vec::Vec;
use core::arch::asm;
use lazy_static::lazy_static;
use spin::Mutex;

pub struct Scheduler {
    current_process: Option<ProcessId>,
    priority_scheduler: PriorityScheduler,
    ticks: u64,
    ml_model: SchedulerModel,
    last_action: Option<Action>,
    last_reward: i32,
    ml_enabled: bool,
}

impl Scheduler {
    pub fn new() -> Self {
        serial_println!("Initializing scheduler with ML capabilities");

        let scheduler = Self {
            current_process: None,
            priority_scheduler: PriorityScheduler::new(),
            ticks: 0,
            ml_model: SchedulerModel::new(),
            last_action: None,
            last_reward: 0,
            ml_enabled: true,
        };

        serial_println!("Scheduler initialization complete");
        scheduler
    }

    fn calculate_reward(&self, process: &Process) -> i32 {
        serial_println!(
            "Scheduler ML: Calculating reward for process {}",
            process.id().0
        );

        let mut reward = 0;

        if process.remaining_time_slice > 0 {
            let time_slice = self.priority_scheduler.get_time_slice(process.id());

            if time_slice > 0 {
                let efficiency = (process.remaining_time_slice.saturating_mul(1000)) / time_slice;
                reward += efficiency as i32;
                serial_println!("Scheduler ML: Efficiency reward: {}", efficiency as i32);
            }
        }

        reward = reward.saturating_sub((process.context_switches % 100) as i32 * 5);
        serial_println!("Scheduler ML: After context switch penalty: {}", reward);

        if process.priority < 5 {
            reward = reward.saturating_add((5 - process.priority as i32) * 50);
            serial_println!("Scheduler ML: After priority bonus: {}", reward);
        }

        reward = reward.saturating_add(process.io_operations as i32 / 10);
        serial_println!("Scheduler ML: After I/O bonus: {}", reward);

        let clamped_reward = reward.clamp(-1000, 1000);
        serial_println!("Scheduler ML: Final clamped reward: {}", clamped_reward);

        clamped_reward
    }

    fn apply_ml_action(&mut self, process: &mut Process, action: Action) -> bool {
        let mut changed = false;

        match action {
            Action::IncreasePriority => {
                if process.priority > 1 {
                    process.priority -= 1;
                    changed = true;
                    serial_println!(
                        "ML: Increased priority for process {} to {}",
                        process.id().0,
                        process.priority
                    );
                }
            }
            Action::DecreasePriority => {
                if process.priority < 10 {
                    process.priority += 1;
                    changed = true;
                    serial_println!(
                        "ML: Decreased priority for process {} to {}",
                        process.id().0,
                        process.priority
                    );
                }
            }
            Action::IncreaseTimeSlice => {
                let original = process.remaining_time_slice;
                process.remaining_time_slice = (process.remaining_time_slice * 12 / 10).min(500);
                changed = process.remaining_time_slice != original;
                if changed {
                    serial_println!(
                        "ML: Increased time slice for process {} to {}",
                        process.id().0,
                        process.remaining_time_slice
                    );
                }
            }
            Action::DecreaseTimeSlice => {
                let original = process.remaining_time_slice;
                process.remaining_time_slice = (process.remaining_time_slice * 8 / 10).max(20);
                changed = process.remaining_time_slice != original;
                if changed {
                    serial_println!(
                        "ML: Decreased time slice for process {} to {}",
                        process.id().0,
                        process.remaining_time_slice
                    );
                }
            }
            Action::NoAction => {}
        }

        changed
    }

    fn record_decision(&mut self, process: &mut Process, action: Action) {
        for i in 0..15 {
            process.scheduler_decisions[i] = process.scheduler_decisions[i + 1];
        }

        process.scheduler_decisions[15] = match action {
            Action::IncreasePriority => 1,
            Action::DecreasePriority => 2,
            Action::IncreaseTimeSlice => 3,
            Action::DecreaseTimeSlice => 4,
            Action::NoAction => 0,
        };
    }

    fn update_process_metrics(&mut self, process: &mut Process) {
        serial_println!(
            "Scheduler ML: Updating process metrics for process {}",
            process.id().0
        );

        if process.cpu_usage_history.len() < 8 {
            serial_println!("Scheduler ML: Error - CPU usage history array is too small");
            return;
        }

        for i in 0..7 {
            process.cpu_usage_history[i] = process.cpu_usage_history[i + 1];
        }

        let time_slice = self.priority_scheduler.get_time_slice(process.id());
        let used = time_slice.saturating_sub(process.remaining_time_slice);
        let usage_percent = if time_slice > 0 {
            ((used * 100) / time_slice) as u32
        } else {
            0
        };

        process.cpu_usage_history[7] = usage_percent;

        process.context_switches = process.context_switches.saturating_add(1);

        process.memory_access_rate =
            (process.memory_access_rate.saturating_mul(3) + usage_percent) / 4;

        if process.ml_reward_history.len() < 4 {
            serial_println!("Scheduler ML: Error - Reward history array is too small");
            return;
        }

        for i in 0..3 {
            process.ml_reward_history[i] = process.ml_reward_history[i + 1];
        }
        process.ml_reward_history[3] = self.last_reward;

        serial_println!(
            "Scheduler ML: Successfully updated metrics for process {}",
            process.id().0
        );
    }

    pub fn toggle_ml(&mut self) -> bool {
        self.ml_enabled = !self.ml_enabled;
        serial_println!(
            "ML scheduling is now {}",
            if self.ml_enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        self.ml_enabled
    }

    pub fn get_ml_stats(&self) -> alloc::collections::BTreeMap<alloc::string::String, f32> {
        self.ml_model.get_statistics()
    }

    fn transition_process(&mut self, process: &mut Process, new_state: ProcessState) {
        let old_state = process.state();
        process.set_state(new_state);

        match (old_state, new_state) {
            (ProcessState::Running, ProcessState::Ready) => {
                self.priority_scheduler.requeue_process(process.id());
            }
            (_, ProcessState::Running) => {
                process.remaining_time_slice = self.priority_scheduler.get_time_slice(process.id());
            }
            (_, ProcessState::Zombie(_)) => {
                self.priority_scheduler.remove_process(process.id());
            }
            _ => {}
        }

        serial_println!(
            "Process {} transitioned from {:?} to {:?}",
            process.id().as_u64(),
            old_state,
            new_state
        );
    }

    pub fn add_process(&mut self, process: Process) {
        let pid = process.id();
        let priority = process.priority;
        self.priority_scheduler.add_process(pid, priority);

        let mut process_list = PROCESS_LIST.lock();
        if let Err(e) = process_list.add(process) {
            println!("Failed to add process: {:?}", e);
        }
    }

    fn cleanup_resources(&mut self) {
        let mut process_list = PROCESS_LIST.lock();
        let zombies: Vec<_> = process_list
            .iter_processes()
            .filter(|p| matches!(p.state(), ProcessState::Zombie(_)))
            .map(|p| p.id())
            .collect();

        for zombie_pid in zombies {
            if let Some(mut zombie) = process_list.remove(zombie_pid) {
                let mut mm_lock = MEMORY_MANAGER.lock();
                if let Some(ref mut mm) = *mm_lock {
                    if let Err(e) = zombie.cleanup(mm) {
                        serial_println!(
                            "Warning: Failed to clean up zombie process {}: {:?}",
                            zombie_pid.0,
                            e
                        );
                    }

                    mm.page_table_cache
                        .lock()
                        .release_page_table(zombie.page_table());
                }

                process_list.cleanup_process_relations(zombie_pid);
            }
        }
    }

    pub fn schedule(&mut self) {
        serial_println!("Scheduler: Beginning scheduling cycle");
        self.cleanup_resources();

        let current_system_ticks = SYSTEM_TIME.ticks();
        self.ticks = current_system_ticks;

        serial_println!(
            "Scheduler ML: Starting scheduling decision cycle (ticks={}, enabled={})",
            self.ticks,
            self.ml_enabled
        );

        serial_println!(
            "Scheduler ML: Tick modulo check: {} % 5 = {}",
            self.ticks,
            self.ticks % 5
        );

        if self.ml_enabled {
            serial_println!("Scheduler ML: ML is enabled");
            if self.ticks % 5 == 0 {
                serial_println!("Scheduler ML: Tick condition is true, will process ML");
            } else {
                serial_println!("Scheduler ML: Tick condition is false, skipping ML this cycle");
            }
        } else {
            serial_println!("Scheduler ML: ML is disabled");
        }

        let mut processes = PROCESS_LIST.lock();

        if self.ml_enabled && self.ticks % 5 == 0 {
            serial_println!("Scheduler ML: Analyzing processes for ML decisions");

            if self.current_process.is_none() {
                if let Some(current) = processes.current() {
                    self.current_process = Some(current.id());
                    serial_println!(
                        "Scheduler ML: Updated current_process to {}",
                        current.id().0
                    );
                }
            }

            serial_println!("Scheduler ML: current_process = {:?}", self.current_process);

            if let Some(current_pid) = self.current_process {
                serial_println!("Scheduler ML: Found current process ID {}", current_pid.0);
                if let Some(current) = processes.get_mut_by_id(current_pid) {
                    if current.state() == ProcessState::Running
                        || current.state() == ProcessState::Ready
                    {
                        serial_println!(
                            "Scheduler ML: Process {} is in {:?} state, applying ML",
                            current_pid.0,
                            current.state()
                        );

                        let reward = self.calculate_reward(current);
                        serial_println!(
                            "Scheduler ML: Calculated reward {} for process {}",
                            reward,
                            current.id().0
                        );

                        self.update_process_metrics(current);

                        if let Some(last_action) = self.last_action {
                            serial_println!(
                                "Scheduler ML: Updating model for last action {:?} with reward {}",
                                last_action,
                                reward
                            );

                            let clamped_reward = reward.clamp(-1000, 1000);
                            if clamped_reward != reward {
                                serial_println!("Scheduler ML: Warning - Clamped extreme reward value from {} to {}", 
                                              reward, clamped_reward);
                            }

                            self.ml_model
                                .update_model(current, last_action, clamped_reward);
                            self.last_reward = clamped_reward;
                        }

                        let action = self.ml_model.decide_action(current);
                        serial_println!(
                            "Scheduler ML: Model recommended action {:?} for process {}",
                            action,
                            current.id().0
                        );

                        let changed = self.apply_ml_action(current, action);
                        serial_println!(
                            "Scheduler ML: Applied action {:?}, changes applied: {}",
                            action,
                            changed
                        );

                        if changed {
                            self.record_decision(current, action);
                            self.last_action = Some(action);
                            serial_println!(
                                "Scheduler ML: Recorded decision for process {}",
                                current.id().0
                            );
                        }
                    } else {
                        serial_println!(
                            "Scheduler ML: Process {} in state {:?}, not applying ML",
                            current_pid.0,
                            current.state()
                        );
                    }
                } else {
                    serial_println!("Scheduler ML: Current process {} not found", current_pid.0);
                }
            } else {
                serial_println!("Scheduler ML: No current process selected for ML analysis");
            }
        }

        serial_println!(
            "Scheduler: Current process count: {}",
            processes.processes.len()
        );

        if processes.current().is_none() && self.current_process.is_none() {
            if let Some((next_pid, _)) = self.priority_scheduler.get_next_process() {
                if let Some(next) = processes.get_mut_by_id(next_pid) {
                    if !matches!(next.state(), ProcessState::Zombie(_)) {
                        self.transition_process(next, ProcessState::Running);
                        unsafe {
                            self.switch_to(next);
                        }
                        self.current_process = Some(next_pid);
                    }
                }
            }
            return;
        }

        if let Some(current_pid) = self.current_process {
            if let Some(current) = processes.get_mut_by_id(current_pid) {
                match current.state() {
                    ProcessState::Running => {
                        if current.remaining_time_slice > 0 {
                            return;
                        }
                        current.save_context();
                        self.transition_process(current, ProcessState::Ready);
                        self.current_process = None;
                    }
                    ProcessState::Zombie(_) => {
                        self.transition_process(current, current.state());
                        self.current_process = None;
                    }
                    _ => {}
                }
            }
        }

        if self.current_process.is_some() {
            return;
        }

        if let Some((next_pid, _)) = self.priority_scheduler.get_next_process() {
            if let Some(next) = processes.get_mut_by_id(next_pid) {
                if !matches!(next.state(), ProcessState::Zombie(_)) {
                    self.transition_process(next, ProcessState::Running);

                    if self.ml_enabled {
                        let action = self.ml_model.decide_action(next);

                        if self.apply_ml_action(next, action) {
                            self.record_decision(next, action);
                            self.last_action = Some(action);
                        }
                    }

                    unsafe {
                        self.switch_to(next);
                    }
                    self.current_process = Some(next_pid);
                }
            }
        }
    }

    unsafe fn switch_to(&self, next: &mut Process) {
        serial_println!("\nScheduler Process Switch Debug:");
        serial_println!(
            "Switching to process {} at instruction {:#x}",
            next.id().0,
            next.context.regs.rip
        );
        serial_println!("Stack pointer: {:#x}", next.context.regs.rsp);
        serial_println!(
            "Page table base: {:#x}",
            next.page_table().start_address().as_u64()
        );
        serial_println!(
            "CS: {:#x}, SS: {:#x}",
            next.context.regs.cs,
            next.context.regs.ss
        );

        if let Some(current_pid) = self.current_process {
            let mut processes = PROCESS_LIST.lock();
            if let Some(current) = processes.get_mut_by_id(current_pid) {
                current.context.save();
            }
        }

        let new_table = next.page_table();
        Cr3::write(new_table, Cr3::read().1);

        let new_stack = next.kernel_stack_top();
        Self::switch_stack(new_stack);

        next.context.restore();

        let pending_signals = next.signal_state.get_pending_signals();
        if !pending_signals.is_empty() && !next.signal_state.is_handling_signal() {
            self.handle_pending_signals(next, pending_signals);
        }
    }

    unsafe fn handle_pending_signals(&self, process: &mut Process, signals: Vec<Signal>) {
        if let Some(signal) = signals.first() {
            if let Some(handler) = process.signal_state.get_handler(*signal) {
                process.signal_state.set_handling_signal(true);
                process.signal_state.clear_signal(*signal);

                let current_rsp = process.context.regs.rsp;
                let current_rip = process.context.regs.rip;

                process.context.regs.rip = handler.handler.as_u64();

                if let Some(signal_stack) = &process.signal_stack {
                    process.context.regs.rsp = signal_stack.get_top().as_u64();
                }

                let stack_ptr = VirtAddr::new(process.context.regs.rsp);
                let rip_ptr = (stack_ptr - 16u64).as_mut_ptr::<u64>();
                let rsp_ptr = (stack_ptr - 8u64).as_mut_ptr::<u64>();

                *rip_ptr = current_rip;
                *rsp_ptr = current_rsp;
                process.context.regs.rsp -= 16;
            }
        }
    }

    unsafe fn switch_stack(new_stack: VirtAddr) {
        asm!(
        "mov rsp, {}",
        in(reg) new_stack.as_u64(),
        options(nomem, nostack)
        );
    }

    pub fn tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);
    }
}

lazy_static! {
    pub static ref SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
}
