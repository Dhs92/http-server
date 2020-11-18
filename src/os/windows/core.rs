use crate::config::Config;
use crate::handle_request;
use crate::os::windows::util::{get_process, get_process_pid};
use nng::{Message, Protocol, Socket};
use std::io::{Error as IoError, Result as IoResult, Write};
use std::mem::{size_of, size_of_val};
use std::net::{TcpListener, ToSocketAddrs};
use std::os::windows::io::{AsRawSocket, FromRawSocket};
use std::process::exit;
use std::{ffi::CString, fmt::Display};
#[cfg(not(debug_assertions))]
use std::{fs::create_dir, mem};
use std::{fs::OpenOptions, mem::ManuallyDrop, thread::sleep, time::Duration};
use thread_pool::ThreadPool;
use winapi::{ctypes::c_void, shared::windef::HWND};
use winapi::{
    shared::ntdef::{FALSE, NULL},
    um::{
        handleapi::CloseHandle,
        processthreadsapi::{GetCurrentProcess, OpenProcessToken},
        securitybaseapi::GetTokenInformation,
        shellapi::ShellExecuteA,
        winnt::{TokenElevation, HANDLE, TOKEN_ELEVATION, TOKEN_QUERY},
        winsock2::WSAPROTOCOL_INFOA,
    },
};

use super::wsa::{begin_socket_handoff, socket_handoff, WSAProcessInfo};

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
    pub fn into_raw(self) -> HANDLE {
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

// Shouldn't fail, but if it does we should
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
