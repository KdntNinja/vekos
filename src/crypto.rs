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
use crate::serial_println;
use ed25519_compact::{Signature, PublicKey, Noise};
use spin::Mutex;
use crate::key_store;

const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
const VKFS_KEY_LENGTH: usize = 64;
const ED25519_SIGNATURE_LENGTH: usize = 64;

pub struct CryptoVerifier {
    verification_key: [u8; VKFS_KEY_LENGTH],
}

macro_rules! array_ref {
    ($arr:expr, $offset:expr, $len:expr) => {{
        {
            #[inline]
            unsafe fn as_array<T>(slice: &[T]) -> &[T; $len] {
                &*(slice.as_ptr() as *const [T; $len])
            }
            let slice = &$arr[$offset..];
            debug_assert!(slice.len() >= $len);
            unsafe { as_array(slice) }
        }
    }};
}


impl CryptoVerifier {
    pub fn new(initial_key: [u8; VKFS_KEY_LENGTH]) -> Self {
        Self {
            verification_key: initial_key,
        }
    }

    pub fn set_verification_key(&mut self, key: &[u8; VKFS_KEY_LENGTH]) {
        self.verification_key[..].copy_from_slice(key);
    }

    pub fn verify_signature(&self, data: &[u8], signature: &[u8; ED25519_SIGNATURE_LENGTH]) -> bool {
        serial_println!("Starting ED25519 signature verification");
        serial_println!("Data length: {} bytes", data.len());
        serial_println!("Signature: {:02x?}...", &signature[..4]);

        if signature.len() != ED25519_SIGNATURE_LENGTH {
            serial_println!("Invalid signature length: {}", signature.len());
            return false;
        }

        let public_key_bytes = array_ref!(self.verification_key, 0, ED25519_PUBLIC_KEY_LENGTH);

        let public_key = match PublicKey::from_slice(public_key_bytes) {
            Ok(key) => key,
            Err(e) => {
                serial_println!("Invalid public key format: {:?}", e);
                return false;
            }
        };
        
        let sig = match Signature::from_slice(signature) {
            Ok(s) => s,
            Err(e) => {
                serial_println!("Invalid signature format: {:?}", e);
                return false;
            }
        };

        match public_key.verify(data, &sig) {
            Ok(_) => {
                serial_println!("Signature verification successful");
                true
            },
            Err(e) => {
                serial_println!("Signature verification failed: {:?}", e);
                false
            }
        }
    }

    pub fn generate_new_keypair(&mut self) -> Result<[u8; ED25519_SIGNATURE_LENGTH], &'static str> {
        let mut seed_bytes = [0u8; 32];
        if let Some(random_value) = self.get_secure_random() {
            seed_bytes[0..8].copy_from_slice(&random_value.to_ne_bytes());

            for i in 1..4 {
                if let Some(r) = self.get_secure_random() {
                    seed_bytes[i*8..(i+1)*8].copy_from_slice(&r.to_ne_bytes());
                }
            }
            
            let seed = ed25519_compact::Seed::new(seed_bytes);
            let key_pair = ed25519_compact::KeyPair::from_seed(seed);

            let mut vkey = [0u8; VKFS_KEY_LENGTH];
            vkey[..ED25519_PUBLIC_KEY_LENGTH].copy_from_slice(key_pair.pk.as_ref());
            self.set_verification_key(&vkey);

            let mut private_key = [0u8; ED25519_SIGNATURE_LENGTH];
            private_key.copy_from_slice(key_pair.sk.as_ref());
            return Ok(private_key);
        }
        
        Err("Failed to generate secure random seed")
    }

    fn get_secure_random(&self) -> Option<u64> {
        if unsafe { core::arch::x86_64::__cpuid(1).ecx & (1 << 30) != 0 } {
            let mut val: u64 = 0;
            if unsafe { core::arch::x86_64::_rdrand64_step(&mut val) == 1 } {
                return Some(val);
            }
        }

        let tsc = crate::tsc::read_tsc();
        Some(tsc.wrapping_mul(0x9e3779b97f4a7c15).rotate_left(17))
    }

    pub fn sign_data(&self, data: &[u8], signing_key: &[u8; ED25519_SIGNATURE_LENGTH]) 
        -> Result<[u8; ED25519_SIGNATURE_LENGTH], &'static str> {

        let private_key = match ed25519_compact::SecretKey::from_slice(signing_key) {
            Ok(key) => key,
            Err(_) => return Err("Invalid signing key"),
        };

        let mut noise_bytes = [0u8; 16];
        for i in 0..2 {
            if let Some(random) = self.get_secure_random() {
                let bytes = random.to_ne_bytes();
                let start = i * 8;
                noise_bytes[start..start+8].copy_from_slice(&bytes);
            }
        }

        let signature = private_key.sign(data, Some(Noise::new(noise_bytes)));

        let mut sig_bytes = [0u8; ED25519_SIGNATURE_LENGTH];
        sig_bytes.copy_from_slice(signature.as_ref());
        Ok(sig_bytes)
    }

    pub fn get_verification_key(&self) -> Result<[u8; VKFS_KEY_LENGTH], &'static str> {
        let mut key_copy = [0u8; VKFS_KEY_LENGTH];
        key_copy.copy_from_slice(&self.verification_key);
        Ok(key_copy)
    }

    pub fn test_verification(&self) -> bool {
        serial_println!("Running ED25519 verification test with self-generated keypair");

        let seed = ed25519_compact::Seed::new([
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
            0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
            0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
        ]);
        
        let key_pair = ed25519_compact::KeyPair::from_seed(seed);
        let message = b"test message";

        let signature = key_pair.sk.sign(message, None);

        let mut test_verifier = CryptoVerifier::new([0; VKFS_KEY_LENGTH]);
        let mut test_key = [0; VKFS_KEY_LENGTH];
        test_key[..32].copy_from_slice(key_pair.pk.as_ref());
        test_verifier.set_verification_key(&test_key);

        let signature_bytes = signature.as_ref();
        let mut signature_array = [0u8; 64];
        signature_array.copy_from_slice(signature_bytes);
        
        let result = test_verifier.verify_signature(message, &signature_array);
        
        serial_println!("Test verification result: {}", result);

        let system_result = match key_store::KEY_STORE.lock().get_verification_key() {
            Ok(key) => {
                let has_real_key = !key.iter().all(|&b| b == 0);
                if !has_real_key {
                    serial_println!("WARNING: System is using zero verification key");
                    false
                } else {
                    let mut system_test = CryptoVerifier::new([0; VKFS_KEY_LENGTH]);
                    system_test.set_verification_key(&key);

                    let sign_result = match key_store::KEY_STORE.lock().sign_data(message) {
                        Ok(sig) => {
                            let verify_result = system_test.verify_signature(message, &sig);
                            serial_println!("System key verification test: {}", verify_result);
                            verify_result
                        },
                        Err(e) => {
                            serial_println!("System key signing test failed: {}", e);
                            false
                        }
                    };
                    
                    sign_result
                }
            },
            Err(e) => {
                serial_println!("Failed to get system verification key: {}", e);
                false
            }
        };
        
        serial_println!("System verification test: {}", system_result);
        
        result && system_result
    }
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result: u8 = 0;
    
    for i in 0..32 {
        result |= a[i] ^ b[i];
    }
    
    result == 0
}

pub fn init() -> bool {
    serial_println!("Initializing cryptographic subsystem");

    let verifier = CRYPTO_VERIFIER.lock();
    let test_result = verifier.test_verification();
    
    if test_result {
        serial_println!("Cryptographic subsystem initialization successful");
    } else {
        serial_println!("WARNING: Cryptographic subsystem initialization failed!");
    }
    
    test_result
}

lazy_static! {
    pub static ref CRYPTO_VERIFIER: Mutex<CryptoVerifier> = Mutex::new(
        CryptoVerifier::new([0; VKFS_KEY_LENGTH])
    );
}