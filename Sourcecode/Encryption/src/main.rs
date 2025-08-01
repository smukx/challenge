use std::fs::File;
use std::io::Write;
mod shellcode;
mod dfc;

use dfc::{dfc_encrypt_shellcode, BLOCK_SIZE};

fn main() {

    let original_shellcode = shellcode::SHELLCODE;
    let payload_len = original_shellcode.len();

    let pad_len = payload_len + (BLOCK_SIZE - payload_len % BLOCK_SIZE) % BLOCK_SIZE;
    
    let mut padded_shellcode = vec![0x90; pad_len];
    padded_shellcode[..payload_len].copy_from_slice(&original_shellcode);

    let key: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    dfc_encrypt_shellcode(&mut padded_shellcode, &key);

    let mut file = File::create("shellcode.rs").expect("Failed to create shellcode.rs");

    writeln!(file, "pub const ENCRYPTED_SHELLCODE: [u8; {}] = [", pad_len).expect("Failed to write to file");

    for chunk in padded_shellcode.chunks(16) {
        write!(file, "    ").expect("Failed to write to file");
        for byte in chunk {
            write!(file, "0x{:02x}, ", byte).expect("Failed to write to file");
        }
        writeln!(file).expect("Failed to write to file");
    }

    writeln!(file, "];").expect("Failed to write to file");

    println!("Encrypted shellcode written to shellcode.rs");
}

