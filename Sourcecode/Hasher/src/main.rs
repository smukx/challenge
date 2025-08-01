/*
    This is an hasher function. We are going to use this !
    
*/

const SEED: u32 = 0xEDB88320;
const STR: &str = "_CRC32";

fn crc32h(message: &str) -> u32 {
    let g0 = SEED;
    let g1 = g0 >> 1;
    let g2 = g0 >> 2;
    let g3 = g0 >> 3;
    let g4 = g0 >> 4;
    let g5 = g0 >> 5;
    let g6 = (g0 >> 6) ^ g0;
    let g7 = ((g0 >> 6) ^ g0) >> 1;

    let mut crc: i32 = -1;

    for &byte in message.as_bytes() {
        crc ^= byte as i32;

        let c = ((crc << 31) >> 31) as u32 & g7
              ^ ((crc << 30) >> 31) as u32 & g6
              ^ ((crc << 29) >> 31) as u32 & g5
              ^ ((crc << 28) >> 31) as u32 & g4
              ^ ((crc << 27) >> 31) as u32 & g3
              ^ ((crc << 26) >> 31) as u32 & g2
              ^ ((crc << 25) >> 31) as u32 & g1
              ^ ((crc << 24) >> 31) as u32 & g0;

        crc = ((crc as u32) >> 8) as i32 ^ c as i32;
    }

    !(crc as u32)
}


// use std::env;
// use std::fmt::write;
// use std::fs;
// use std::io::{self, Write};
// use std::process;
// use std::process::exit;

// fn main() -> io::Result<()>{
//     let args: Vec<String> = env::args().collect();
    
//     if args.len() != 2{
//         eprintln!("[-] Usage {} <path to shellcode.bin>", args[0]);
//         exit(0);
//     }

//     let path = &args[1];
//     let bytes = fs::read(path)?;

//     let len = bytes.len();

//     println!("const SHELLCODE: [u8; {}] = [", len);

//     let stdout = io::stdout();
//     let mut handle = stdout.lock();

//     for (i, &byte) in bytes.iter().enumerate() {
//         if i % 16 == 0 && i != 0{
//             writeln!(handle)?;
//             write!(handle, "    ")?;
//         } else if i != 0{
//             write!(handle, " ")?;
//         }
//         write!(handle, "0x{:02X},", byte)?;
//     }
    
//     writeln!(handle)?;
//     writeln!(handle, "];")?;

    
//     Ok(())
// }


fn main() {

    println!("const {}{}: u32 = 0x{:08X};", "NT_OPEN_PROCESS", STR, crc32h("NtOpenProcess"));
    println!("const {}{}: u32 = 0x{:08X};", "NT_ALLOCATE_VIRTUAL_MEMORY", STR, crc32h("NtAllocateVirtualMemory"));
    println!("const {}{}: u32 = 0x{:08X};", "NT_WRITE_VIRTUAL_MEMORY", STR, crc32h("NtWriteVirtualMemory"));
    println!("const {}{}: u32 = 0x{:08X};", "NT_PROTECT_VIRTUAL_MEMORY", STR, crc32h("NtProtectVirtualMemory"));
    println!("const {}{}: u32 = 0x{:08X};", "NT_CREATE_THREAD_EX", STR, crc32h("NtCreateThreadEx"));
    println!("const {}{}: u32 = 0x{:08X};", "NT_WAIT_FOR_SINGLE_OBJECT", STR, crc32h("NtWaitForSingleObject"));
}

