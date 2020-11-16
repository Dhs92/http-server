use crate::config::Config;
use crate::handle_request;
use raw_sync::{events::*, Timeout};
use shared_memory::{Shmem, ShmemConf, ShmemError};
use std::{io::ErrorKind, fs::OpenOptions};
use std::io::{Error as IoError, Result as IoResult, Write};
use std::mem::{size_of, size_of_val};
use std::net::{TcpListener, ToSocketAddrs};
use std::os::windows::io::{AsRawSocket, FromRawSocket};
use std::process::exit;
use std::time::Duration;
use std::{ffi::CString, fmt::Display};
#[cfg(not(debug_assertions))]
use std::{fs::create_dir, mem};
use thread_pool::ThreadPool;
use winapi::shared::ntdef::{FALSE, NULL, TRUE};
use winapi::um::{
    handleapi::CloseHandle,
    processthreadsapi::{GetCurrentProcess, OpenProcessToken},
    securitybaseapi::GetTokenInformation,
    shellapi::ShellExecuteA,
    winnt::{TokenElevation, HANDLE, TOKEN_ELEVATION, TOKEN_QUERY},
};
use winapi::{ctypes::c_void, shared::windef::HWND};

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
                log::debug!("Dropping HANDLE!");
                CloseHandle(self.0);
                self.0 = NULL;
            }
        }
    }
}

impl Handle {
    fn into_raw(self) -> HANDLE {
        // would drop value at the end of the function, but copy the pointer's address before doing so
        let handle = std::mem::ManuallyDrop::new(self);
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

// Need way to separate shared mem handle names for multiple server instances
// Look into RPC?
pub fn start() {
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
        if config_meta.len() < 75 {
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
    let mut shmem = init_shared_mem();
    let elevated = is_elevated().unwrap(); // If this fails, we want to panic. Should NOT fail
    if elevated && !shmem.is_owner() {
        // TODO match
        let (evt, _) = unsafe { Event::from_existing(shmem.as_ptr()).unwrap() };
        listener = bind(&config.address());
        let shared_mem = unsafe { shmem.as_slice_mut() }; 
        // need to duplicate socket after copying
        let in_buf = &mut bincode::serialize(&listener.as_raw_socket()).unwrap(); // shouldn't fail for any reason
        // Event should be at the front of the buffer, so skip over the number of bytes an Event takes up
        for (serialized, mem) in in_buf
            .iter()
            .zip(shared_mem.iter_mut().skip(size_of::<Event>()))
        {
            *mem = *serialized
        }

        // Tell parent process that the buffer is no longer in use
        evt.set(EventState::Signaled).unwrap();

        exit(0)
    } else if !elevated && shmem.is_owner() {
        let (evt, _) = unsafe { Event::new(shmem.as_ptr(), true).unwrap() };

        elevate();

        match evt.wait(Timeout::Val(Duration::from_secs(30))) {
            Ok(_) => (),
            Err(e) => {
                log::error!("Timed out while binding address: {}", e);

                exit(65)
            }
        }
        drop(std::net::TcpListener::bind("255.255.255.255:0"));

        // TODO elevate
        let out_buf = unsafe { shmem.as_slice() };

        let listener_raw = bincode::deserialize(out_buf).unwrap();
        listener = unsafe { TcpListener::from_raw_socket(listener_raw) }; // not infallible
        log::debug!("{:?}", listener)
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

            exit(-0x420)
        }
    }
}

pub fn listen(listener: &mut TcpListener, thread_pool: &ThreadPool) {
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => thread_pool.execute(move || handle_request(&mut stream)),
            Err(ek) if ek.raw_os_error().unwrap() == 10093 => {
                log::error!("Listening Failed: {}", ek);
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

    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token); }

    let token_check = TokenCheck::validate(token);

    let token = match token_check {
        TokenCheck::Valid(token) => { log::debug!("Token Ptr: {:?}, {}", token, IoError::last_os_error()); token },
        TokenCheck::Invalid(err) => {
            log::error!("Failed to get Process Token: {}", err);
            
            return Err(err)
        }
    };
    

    if unsafe {
        let elevation_ptr = &mut elevation as *mut _ as *mut c_void;
        let elevation_size = size_of_val(&elevation) as u32;
        log::debug!("Token Ptr: {:?}", token);
        GetTokenInformation(token.into_raw(), TokenElevation, elevation_ptr, elevation_size, &mut size)
    } == (FALSE as i32)
    {
        let err = IoError::last_os_error();
        log::error!("Failed to get Token Information: {}", err);

        return Err(err)
    }
    
    Ok(elevation.TokenIsElevated != 0)
}

fn init_shared_mem() -> Shmem {
    let bind_path = "binding";

    match ShmemConf::new()
        .size(get_buf_size())
        .flink(bind_path)
        .create()
    {
        Ok(m) => m,
        Err(ShmemError::LinkExists) => match ShmemConf::new().flink(bind_path).open() {
            Ok(m) => m,
            Err(e) => {
                log::error!("Could not open memory mapping: {}", e);

                exit(51)
            }
        },
        Err(e) => {
            log::error!("Could not create memory mapping: {}", e);

            exit(52)
        }
    }
}

const fn get_buf_size() -> usize {
    size_of::<u64>() + size_of::<Event>()
}

fn elevate() {
    shell_execute_a(
        None,
        CString::new("runas").unwrap(),
        CString::new("http-server.exe").unwrap(),
        CString::new("").unwrap(),
        CString::new(".\\").unwrap(),
        10,
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
