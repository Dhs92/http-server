use crate::config::Config;
use crate::handle_request;
use nng::{Message, Protocol, Socket};
use serde::{Deserialize, Serialize};
use std::io::{Error as IoError, Result as IoResult, Write};
use std::mem::{size_of, size_of_val};
use std::net::{TcpListener, ToSocketAddrs};
use std::os::windows::io::{AsRawSocket, FromRawSocket};
use std::process::exit;
use std::{convert::TryInto, fs::OpenOptions, mem::ManuallyDrop, thread::sleep, time::Duration};
use std::{ffi::CString, fmt::Display};
#[cfg(not(debug_assertions))]
use std::{fs::create_dir, mem};
use thread_pool::ThreadPool;
use winapi::{ctypes::c_void, shared::windef::HWND};
use winapi::{
    ctypes::{c_int, c_uchar, c_ulong, c_ushort},
    shared::{
        guiddef::GUID,
        minwindef::DWORD,
        ntdef::{FALSE, NULL},
        ws2def::{AF_INET, IPPROTO_TCP},
    },
    um::{
        handleapi::CloseHandle,
        processthreadsapi::GetProcessId,
        processthreadsapi::{GetCurrentProcess, OpenProcessToken},
        securitybaseapi::GetTokenInformation,
        shellapi::ShellExecuteA,
        winnt::{TokenElevation, HANDLE, TOKEN_ELEVATION, TOKEN_QUERY},
        winsock2::WSAPROTOCOL_INFOA,
        winsock2::{
            WSADuplicateSocketA, WSASocketA, LPWSAPROTOCOL_INFOA, SOCK_STREAM, WSAPROTOCOLCHAIN,
            WSA_FLAG_OVERLAPPED,
        },
    },
};

#[cfg(not(debug_assertions))]
const CONFIG_PATH: &str = "C:\\Program Files\\Common Files\\http-server\\";
#[cfg(debug_assertions)]
const CONFIG_PATH: &str = "./";

const CONFIG_NAME: &str = "config.json";

#[derive(Debug)]
pub struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
                self.0 = NULL;
            }
        }
    }
}

impl Handle {
    fn into_raw(self) -> HANDLE {
        // would drop value at the end of the function, but copy the pointer's address before doing so
        let handle = ManuallyDrop::new(self);
        handle.0
    }
}

#[derive(Debug)]
pub enum HandleCheck {
    Valid(Handle),
    Invalid(IoError), // error code
}

impl HandleCheck {
    pub fn validate(handle: HANDLE) -> Self {
        if !handle.is_null() {
            Self::Valid(Handle(handle))
        } else {
            Self::Invalid(IoError::last_os_error())
        }
    }
}

pub type TokenCheck = HandleCheck;

// "wrappers" that will allow use of derived Ser/De
#[derive(Serialize, Deserialize)]
struct WSAProcessInfo {
    service_flags: [DWORD; 5],
    provider_id: Guid,
    catalogue_entry_id: DWORD,
    protocol_chain: WSAProtocolChain,
    version: c_int,
    address_family: c_int,
    max_sock_addr: c_int,
    min_sock_addr: c_int,
    socket_type: c_int,
    i_protocol: c_int,
    protocol_max_offset: c_int,
    network_byte_order: c_int,
    security_scheme: c_int,
    message_size: DWORD,
    provider_reserved: DWORD,
    sz_protocol: String, // convert to CHAR when converting back
}

impl From<WSAPROTOCOL_INFOA> for WSAProcessInfo {
    fn from(info: WSAPROTOCOL_INFOA) -> Self {
        let sz_protocol = info.szProtocol.iter().map(|&c| c as u8).collect();
        let sz_protocol = String::from_utf8(sz_protocol).unwrap(); // WinAPI should provide valid ASCII, which is also valid UTF-8

        Self {
            service_flags: [
                info.dwServiceFlags1,
                info.dwServiceFlags2,
                info.dwServiceFlags3,
                info.dwServiceFlags4,
                info.dwServiceFlags5,
            ],
            provider_id: info.ProviderId.into(),
            catalogue_entry_id: info.dwCatalogEntryId,
            protocol_chain: info.ProtocolChain.into(),
            version: info.iVersion,
            address_family: info.iAddressFamily,
            max_sock_addr: info.iMaxSockAddr,
            min_sock_addr: info.iMinSockAddr,
            socket_type: info.iSocketType,
            i_protocol: info.iProtocol,
            protocol_max_offset: info.iProtocolMaxOffset,
            network_byte_order: info.iNetworkByteOrder,
            security_scheme: info.iSecurityScheme,
            message_size: info.dwMessageSize,
            provider_reserved: info.dwProviderReserved,
            sz_protocol,
        }
    }
}

impl From<WSAProcessInfo> for WSAPROTOCOL_INFOA {
    fn from(info: WSAProcessInfo) -> Self {
        let mut sz_protocol = [0; 256];
        for (c1, c2) in info
            .sz_protocol
            .chars()
            .map(|c| c as i8)
            .zip(sz_protocol.iter_mut())
        {
            *c2 = c1;
        }

        Self {
            dwServiceFlags1: info.service_flags[0],
            dwServiceFlags2: info.service_flags[1],
            dwServiceFlags3: info.service_flags[2],
            dwServiceFlags4: info.service_flags[3],
            dwServiceFlags5: info.service_flags[4],
            ProviderId: info.provider_id.into(),
            dwCatalogEntryId: info.catalogue_entry_id,
            ProtocolChain: info.protocol_chain.into(),
            iVersion: info.version,
            iAddressFamily: info.address_family,
            iMaxSockAddr: info.max_sock_addr,
            iMinSockAddr: info.min_sock_addr,
            iSocketType: info.socket_type,
            iProtocol: info.i_protocol,
            iProtocolMaxOffset: info.protocol_max_offset,
            iNetworkByteOrder: info.network_byte_order,
            iSecurityScheme: info.security_scheme,
            dwMessageSize: info.message_size,
            dwProviderReserved: info.provider_reserved,
            szProtocol: sz_protocol,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Guid {
    data1: c_ulong,
    data2: c_ushort,
    data3: c_ushort,
    data4: [c_uchar; 8],
}

impl From<GUID> for Guid {
    fn from(guid: GUID) -> Self {
        Self {
            data1: guid.Data1,
            data2: guid.Data2,
            data3: guid.Data3,
            data4: guid.Data4,
        }
    }
}

impl From<Guid> for GUID {
    fn from(guid: Guid) -> Self {
        Self {
            Data1: guid.data1,
            Data2: guid.data2,
            Data3: guid.data3,
            Data4: guid.data4,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct WSAProtocolChain {
    chain_len: c_int,
    chain_entries: [DWORD; 7],
}

impl From<WSAPROTOCOLCHAIN> for WSAProtocolChain {
    fn from(proto_chain: WSAPROTOCOLCHAIN) -> Self {
        Self {
            chain_len: proto_chain.ChainLen,
            chain_entries: proto_chain.ChainEntries,
        }
    }
}

impl From<WSAProtocolChain> for WSAPROTOCOLCHAIN {
    fn from(proto_chain: WSAProtocolChain) -> Self {
        Self {
            ChainLen: proto_chain.chain_len,
            ChainEntries: proto_chain.chain_entries,
        }
    }
}

pub fn start(pid: Option<u32>) {
    simple_logging::log_to_stderr(log::LevelFilter::Error);
    #[cfg(not(debug_assertions))]
    match create_dir(CONFIG_PATH) {
        Ok(_) => (),
        Err(e) => log::error!("Could not create config directory: {}", e),
    }

    let mut config_file = match OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open(format!("{}/{}", CONFIG_PATH, CONFIG_NAME))
    {
        Ok(conf_file) => conf_file,
        Err(e) => {
            log::error!("Unable to create {}: {}", CONFIG_NAME, e);
            exit(-1)
        }
    };

    if let Ok(config_meta) = config_file.metadata() {
        if config_meta.len() < 80 {
            config_file
                .write_all(
                    serde_json::to_string_pretty(&Config::default())
                        .unwrap()
                        .as_bytes(),
                )
                .unwrap();
        }
    }

    let config = Config::load_config(config_file);
    simple_logging::log_to_stderr(config.log_level());

    let mut listener;
    let elevated = is_elevated().unwrap(); // If this fails, we want to panic. Should NOT fail
    if config.port() > 1024 {
        listener = bind(&config.address())
    } else if !elevated {
        let pipe = match Socket::new(Protocol::Pull0) {
            Ok(p) => p,
            Err(e) => {
                log::error!("Unable to create pipe: {}", e);
                exit(89)
            }
        };

        let pid = get_process_pid(get_process()); // TODO GetProcessInfo

        elevate(pid);

        pipe.listen("ipc:///tmp/binding.ipc").unwrap(); // <---- unwrap is TEMPORARY, fix it you lazy ass

        sleep(Duration::from_secs(2));

        let raw_process_info = recv_msg(&pipe);
        let raw_process_info = raw_process_info.as_slice();
        let process_info: WSAProcessInfo = bincode::deserialize(raw_process_info).unwrap();
        let raw_listener = socket_handoff(&mut process_info.into());

        listener = unsafe { TcpListener::from_raw_socket(raw_listener) }; // not infallible
    } else if elevated {
        let pid = match pid {
            Some(pid) => pid,
            None => {
                log::error!("PID not provided, cannot continue. Exiting..");
                exit(-15)
            }
        };

        let pipe = match Socket::new(Protocol::Push0) {
            Ok(p) => p,
            Err(_) => exit(999),
        };
        pipe.dial("ipc:///tmp/binding.ipc").unwrap(); // <---- unwrap is TEMPORARY, fix it you lazy ass

        listener = bind(&config.address());

        let mut process_info = WSAPROTOCOL_INFOA::default();
        begin_socket_handoff(listener.as_raw_socket() as usize, pid, &mut process_info);

        let in_buf = bincode::serialize(&WSAProcessInfo::from(process_info)).unwrap();
        send_msg(&pipe, &in_buf);

        exit(0)
    } else {
        log::error!("An unknown error has occured");

        exit(444)
    }

    let thread_pool = ThreadPool::new(config.thread_count());

    listen(&mut listener, &thread_pool)
}

fn bind<A>(addr: A) -> TcpListener
where
    A: ToSocketAddrs + Copy + Display,
{
    match TcpListener::bind(addr) {
        Ok(listener) => listener,
        Err(e) => {
            log::error!("Failed to bind {}: {}", addr, e);

            exit(420)
        }
    }
}

fn recv_msg(pipe: &Socket) -> Message {
    match pipe.recv() {
        Ok(message) => message,
        Err(e) => {
            log::error!("Failed to read message from pipe: {}", e);
            exit(90)
        }
    }
}

fn send_msg(pipe: &Socket, in_buf: &[u8]) {
    match pipe.send(in_buf) {
        Ok(_) => (),
        Err((_, e)) => {
            log::error!("Failed to send message: {}", e);
            exit(10)
        }
    }
}

pub fn listen(listener: &mut TcpListener, thread_pool: &ThreadPool) {
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => thread_pool.execute(move || handle_request(&mut stream)),
            Err(e) if e.raw_os_error().unwrap() == 10093 || e.raw_os_error().unwrap() == 10038 => {
                log::error!("Listening Failed: {}", e);
                exit(-1)
            }
            Err(e) => {
                log::warn!("Connection failed: {:?}", e);
            }
        }
    }
}

#[rustfmt::skip]
fn is_elevated() -> IoResult<bool> {
    let mut token = NULL;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut size = size_of::<TOKEN_ELEVATION>() as u32;

    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == (FALSE as i32) {
        log::error!("OpenProcessToken failed: {}", IoError::last_os_error());
        exit(67)
    }

    let token_check = TokenCheck::validate(token);

    let token = match token_check {
        TokenCheck::Valid(token) => token,
        TokenCheck::Invalid(err) => {
            log::error!("Failed to get Process Token: {}", err);
            
            return Err(err)
        }
    };
    

    if unsafe {
        let elevation_ptr = &mut elevation as *mut _ as *mut c_void;
        let elevation_size = size_of_val(&elevation) as u32;

        GetTokenInformation(token.into_raw(), TokenElevation, elevation_ptr, elevation_size, &mut size)
    } == (FALSE as i32)
    {
        let err = IoError::last_os_error();
        log::error!("Failed to get Token Information: {}", err);

        return Err(err)
    }
    
    Ok(elevation.TokenIsElevated != 0)
}

fn elevate(pid: u32) {
    shell_execute_a(
        None,
        CString::new("runas").unwrap(),
        CString::new("http-server.exe").unwrap(),
        CString::new(format!("--p {}", pid)).unwrap(),
        CString::new(".\\").unwrap(),
        8,
    )
    .unwrap();
}

fn shell_execute_a(
    hwnd: Option<HWND>,
    operation: CString,
    file_name: CString,
    param: CString,
    dir: CString,
    show_cmd: i32,
) -> IoResult<Handle> {
    let hwnd = match hwnd {
        Some(hwnd) => hwnd,
        None => NULL as HWND,
    };

    let handle = unsafe {
        ShellExecuteA(
            hwnd,
            operation.as_ptr(),
            file_name.as_ptr(),
            param.as_ptr(),
            dir.as_ptr(),
            show_cmd,
        )
    };

    match HandleCheck::validate(handle as *mut c_void) {
        HandleCheck::Valid(h) => Ok(h),
        HandleCheck::Invalid(e) => Err(e),
    }
}

fn get_process() -> HandleCheck {
    let process = unsafe { GetCurrentProcess() };
    HandleCheck::validate(process)
}

fn get_process_pid(process: HandleCheck) -> u32 {
    let process = match process {
        HandleCheck::Valid(proc) => proc,
        HandleCheck::Invalid(e) => {
            log::error!("Invalid process handle: {}", e);
            exit(22)
        }
    };

    unsafe { GetProcessId(process.into_raw()) }
}

fn begin_socket_handoff(socket: usize, pid: u32, info: LPWSAPROTOCOL_INFOA) {
    if unsafe { WSADuplicateSocketA(socket, pid, info) } != 0 {
        log::error!(
            "WSADuplicateSocket returned non-zero value: {}",
            IoError::last_os_error()
        );
        exit(15)
    }
}

fn socket_handoff(info: LPWSAPROTOCOL_INFOA) -> u64 {
    unsafe {
        WSASocketA(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP.try_into().unwrap(),
            info,
            0,
            WSA_FLAG_OVERLAPPED,
        )
        .try_into()
        .unwrap()
    }
}
