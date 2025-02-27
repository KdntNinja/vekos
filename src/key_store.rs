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
use spin::Mutex;
use lazy_static::lazy_static;
use crate::serial_println;
use alloc::string::String;
use crate::fs::{FILESYSTEM, FileSystem, FilePermissions};

const KEY_STORE_PATH: &str = "/etc/vekos/keys";
const VERIFICATION_KEY_PATH: &str = "/etc/vekos/keys/verification.key";
const SIGNING_KEY_PATH: &str = "/etc/vekos/keys/signing.key";

const VERIFICATION_KEY_LENGTH: usize = 64;
const SIGNING_KEY_LENGTH: usize = 64;

pub struct KeyStore {
    verification_key: [u8; VERIFICATION_KEY_LENGTH],
    signing_key: [u8; SIGNING_KEY_LENGTH],
    initialized: bool,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            verification_key: [0u8; VERIFICATION_KEY_LENGTH],
            signing_key: [0u8; SIGNING_KEY_LENGTH],
            initialized: false,
        }
    }
    
    pub fn init_early_boot(&mut self) -> Result<(), &'static str> {
        serial_println!("Initializing KeyStore (early boot mode)");

        self.generate_keys()?;
        self.initialized = true;
        serial_println!("Generated temporary verification keys for early boot");
        
        Ok(())
    }

    pub fn init(&mut self) -> Result<(), &'static str> {
        serial_println!("Initializing key management subsystem");
        
        match self.ensure_key_directory() {
            Ok(_) => serial_println!("Key directories verified/created successfully"),
            Err(e) => serial_println!("Warning: Could not create key directories: {}", e),
        }
        
        if self.initialized {
            if let Err(e) = self.save_keys() {
                serial_println!("Note: Could not save existing keys: {}", e);
            } else {
                serial_println!("Existing keys saved to filesystem");
            }
            return Ok(());
        }

        match self.load_keys() {
            Ok(_) => {
                serial_println!("Successfully loaded existing keys");
                self.initialized = true;
                return Ok(());
            },
            Err(e) => {
                serial_println!("Could not load existing keys: {}", e);
                serial_println!("Generating new keypair");

                self.generate_keys()?;

                if let Err(e) = self.save_keys() {
                    serial_println!("Note: Could not save keys: {}", e);
                    serial_println!("Keys will remain in memory only");
                } else {
                    serial_println!("Keys saved to filesystem");
                }
                
                self.initialized = true;
                serial_println!("New keys generated successfully");
                Ok(())
            }
        }
    }

    fn ensure_key_directory(&self) -> Result<(), &'static str> {
        let mut fs = FILESYSTEM.lock();

        for dir in &["/etc", "/etc/vekos", "/etc/vekos/keys"] {
            let permissions = FilePermissions {
                read: true,
                write: true,
                execute: true,
            };
            
            match fs.stat(dir) {
                Ok(_) => {
                    serial_println!("Directory exists: {}", dir);
                },
                Err(_) => {
                    match fs.create_directory(dir, permissions) {
                        Ok(_) => serial_println!("Created directory: {}", dir),
                        Err(e) => {
                            serial_println!("Failed to create directory {}: {:?}", dir, e);
                            return Err("Failed to create key directory");
                        }
                    }
                }
            }
        }
        
        Ok(())
    }

    fn load_keys(&mut self) -> Result<(), &'static str> {
        let mut fs = FILESYSTEM.lock();

        match fs.read_file(VERIFICATION_KEY_PATH) {
            Ok(data) => {
                if data.len() != VERIFICATION_KEY_LENGTH {
                    return Err("Invalid verification key size");
                }
                self.verification_key.copy_from_slice(&data);
            },
            Err(_) => return Err("Failed to read verification key"),
        }

        match fs.read_file(SIGNING_KEY_PATH) {
            Ok(data) => {
                if data.len() != SIGNING_KEY_LENGTH {
                    return Err("Invalid signing key size");
                }
                self.signing_key.copy_from_slice(&data);
            },
            Err(_) => return Err("Failed to read signing key"),
        }
        
        Ok(())
    }

    fn save_keys(&self) -> Result<(), &'static str> {
        let mut fs = FILESYSTEM.lock();

        let read_only = FilePermissions {
            read: true,
            write: false,
            execute: false,
        };

        match fs.create_file(VERIFICATION_KEY_PATH, read_only) {
            Ok(_) => match fs.write_file(VERIFICATION_KEY_PATH, &self.verification_key) {
                Ok(_) => (),
                Err(_) => return Err("Failed to write verification key data"),
            },
            Err(_) => return Err("Failed to create verification key file"),
        }

        match fs.create_file(SIGNING_KEY_PATH, read_only) {
            Ok(_) => match fs.write_file(SIGNING_KEY_PATH, &self.signing_key) {
                Ok(_) => (),
                Err(_) => return Err("Failed to write signing key data"),
            },
            Err(_) => return Err("Failed to create signing key file"),
        }
        
        Ok(())
    }

    fn generate_keys(&mut self) -> Result<(), &'static str> {
        let mut verifier = crate::crypto::CRYPTO_VERIFIER.lock();

        match verifier.generate_new_keypair() {
            Ok(private_key) => {
                self.signing_key.copy_from_slice(&private_key);
                self.verification_key = verifier.get_verification_key()?;
                
                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    pub fn get_verification_key(&self) -> Result<[u8; VERIFICATION_KEY_LENGTH], &'static str> {
        if !self.initialized {
            return Err("KeyStore not initialized");
        }
        
        Ok(self.verification_key)
    }

    pub fn get_signing_key(&self) -> Result<[u8; SIGNING_KEY_LENGTH], &'static str> {
        if !self.initialized {
            return Err("KeyStore not initialized");
        }
        
        Ok(self.signing_key)
    }

    pub fn sign_data(&self, data: &[u8]) -> Result<[u8; SIGNING_KEY_LENGTH], &'static str> {
        if !self.initialized {
            return Err("KeyStore not initialized");
        }
        
        let verifier = crate::crypto::CRYPTO_VERIFIER.lock();
        verifier.sign_data(data, &self.signing_key)
    }
}

lazy_static! {
    pub static ref KEY_STORE: Mutex<KeyStore> = Mutex::new(KeyStore::new());
}

pub fn init() -> Result<(), &'static str> {
    serial_println!("Initializing key management subsystem");
    let mut key_store = KEY_STORE.lock();
    key_store.init()
}