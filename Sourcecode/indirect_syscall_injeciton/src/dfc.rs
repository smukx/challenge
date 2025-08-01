
/*
    DFC Encryption in Rust.
    Author: @5mukx
    For More: https://github.com/Whitecat18/Rust-for-malware-development
*/

#![allow(dead_code)]

pub const ROUNDS: usize = 8;
pub const BLOCK_SIZE: usize = 16;

// subkeys generated from the main key
pub static mut K: [[u8; 16]; ROUNDS] = [[0; 16]; ROUNDS];

// rotate left func
pub fn rot_l(x: u32, shift: u32) -> u32{
    (x << shift) | (x >> (32 - shift))
}

// function f for DFC round  
pub fn f(left: u32, key_part: u32) -> u32{
    rot_l(left.wrapping_add(key_part), 3) ^ key_part
}

// DFC G function applies Feistel structure in each round

pub fn g(left: &mut u32, right: &mut u32, round_key: &[u8]) {
    let temp_right = *right;
    *right = *left ^ f(*right, u32::from_ne_bytes(round_key[0..4].try_into().unwrap()));
    *left = temp_right;
}

// key schecule for DFC
pub fn key_schedule(key: &[u8]) {
    unsafe {
        for i in 0..ROUNDS {
            for j in 0..16 {
                K[i][j] = key[j % 8] ^ (i as u8 + j as u8);
            }
        }
    }
}

// DFC Encryption 
pub fn dfc_encrypt(block: &mut [u32; 2], _key: &[u8]) {
    let (mut left, mut right) = (block[0], block[1]);

    unsafe {
        for i in 0..ROUNDS {
            g(&mut left, &mut right, &K[i]);
        }
    }

    block[0] = right;
    block[1] = left;
}

// DFC decryption function
pub fn dfc_decrypt(block: &mut [u32; 2], _key: &[u8]) {
    let (mut left, mut right) = (block[0], block[1]);

    unsafe {
        for i in (0..ROUNDS).rev() {
            g(&mut left, &mut right, &K[i]);
        }
    }

    block[0] = right;
    block[1] = left;
}

// encrypt shellcode
pub fn dfc_encrypt_shellcode(shellcode: &mut [u8], key: &[u8]) {
    key_schedule(key);
    for chunk in shellcode.chunks_exact_mut(BLOCK_SIZE) {
        let mut block = [u32::from_ne_bytes(chunk[0..4].try_into().unwrap()), 
                         u32::from_ne_bytes(chunk[4..8].try_into().unwrap())];
        dfc_encrypt(&mut block, key);
        chunk[0..4].copy_from_slice(&block[0].to_ne_bytes());
        chunk[4..8].copy_from_slice(&block[1].to_ne_bytes());
    }
}

// decrypt shellcode 
pub fn dfc_decrypt_shellcode(shellcode: &mut [u8], key: &[u8]) {
    key_schedule(key);
    for chunk in shellcode.chunks_exact_mut(BLOCK_SIZE) {
        let mut block = [u32::from_ne_bytes(chunk[0..4].try_into().unwrap()), 
                         u32::from_ne_bytes(chunk[4..8].try_into().unwrap())];
        dfc_decrypt(&mut block, key);
        chunk[0..4].copy_from_slice(&block[0].to_ne_bytes());
        chunk[4..8].copy_from_slice(&block[1].to_ne_bytes());
    }
}
