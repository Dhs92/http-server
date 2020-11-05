use crate::config::Config;
use crate::handle_request;
use crate::SERVER_NAME;
use std::error::Error;
use std::ffi::CString;
use std::fmt::Display;
#[cfg(not(debug_assertions))]
use std::fs::create_dir;
use std::fs::OpenOptions;
use std::io::{Error as IoError, ErrorKind, Result as IoResult, Write};
use std::mem::{size_of, size_of_val};
use std::net::{TcpListener, ToSocketAddrs};
use std::os::windows::io::{AsRawSocket, FromRawSocket};
use std::process::exit;
use thread_pool::ThreadPool;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::{FALSE, NULL};
use winapi::um::{
    fileapi::{CreateFileA, ReadFile, WriteFile, OPEN_EXISTING},
    handleapi::CloseHandle,
    minwinbase::OVERLAPPED,
    minwinbase::SECURITY_ATTRIBUTES,
    processthreadsapi::{GetCurrentProcess, OpenProcessToken},
    securitybaseapi::GetTokenInformation,
    winbase::{
        CreateNamedPipeA, PIPE_ACCESS_DUPLEX, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND,
        PIPE_TYPE_BYTE, PIPE_TYPE_MESSAGE,
    },
    winnt::{
        TokenElevation, FILE_ATTRIBUTE_NORMAL, GENERIC_WRITE, HANDLE, TOKEN_ELEVATION, TOKEN_QUERY,
    },
};

#[path = "windows/pipe.rs"]
mod pipe;

#[cfg(not(debug_assertions))]
const CONFIG_PATH: &str = "C:\\Program Files\\Common Files\\http-server\\";
#[cfg(debug_assertions)]
const CONFIG_PATH: &str = "./";

const CONFIG_NAME: &str = "config.json";

#[allow(dead_code)]
pub enum PipeDirection {
    Duplex,
    Inbound,
    Outbound,
}

#[allow(dead_code)]
pub enum PipeType {
    Byte,
    Message,
}

pub struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != NULL {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

// impl Deref for Handle {
//     type Target = HANDLE;

//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }

impl Handle {
    fn into_raw(self) -> *mut c_void {
        self.0
    }
}

enum HandleCheck<E: Error> {
    Valid(Handle),
    Invalid(E), // error code
}

type TokenCheck<E> = HandleCheck<E>;
type PipeCheck<E> = HandleCheck<E>;

// TODO error handling instead of unwraps
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

    let handle_size = size_of::<HANDLE>() as u32;
    let pipe_name = CString::new(format!("\\\\.\\pipe\\{}", SERVER_NAME)).unwrap(); // COULD FAIL IF UNICODE PASSED

    let mut listener;
    if is_elevated().unwrap() { // TODO match
        listener = bind(&config.address());
        let mut in_buf = bincode::serialize(&listener.as_raw_socket()).unwrap(); // shouldn't fail for any reason
        let handle = open_pipe(pipe_name);
        write_pipe(handle, &mut in_buf);
    } else {
        // TODO elevate after pipe creation
        let pipe = create_pipe(
            pipe_name,
            PipeDirection::Duplex,
            PipeType::Byte,
            2, // max instances
            handle_size,
            handle_size,
            0, // value of 0 means default timeout
        );

        let pipe = match pipe {
            PipeCheck::Valid(p) => p,
            PipeCheck::Invalid(err) => {
                log::error!("Unable to create pipe: {}", err);
                exit(err.raw_os_error().unwrap())
            }
        };

        let mut out_buf = [0; 4096];
        read_pipe(pipe.into_raw(), &mut out_buf);

        let listener_raw = bincode::deserialize(&out_buf).unwrap();
        listener = unsafe { TcpListener::from_raw_socket(listener_raw) };
    }

    simple_logging::log_to_stderr(config.log_level());

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
            Err(e) => log::warn!("Connection failed: {}", e),
        }
    }
}

fn create_pipe(
    name: CString,
    open_mode: PipeDirection,
    pipe_type: PipeType,
    max_instances: DWORD,
    out_buffer_size: DWORD,
    in_buffer_size: DWORD,
    default_timeout: DWORD,
) -> PipeCheck<IoError> {
    let pipe_access = match open_mode {
        PipeDirection::Duplex => PIPE_ACCESS_DUPLEX,
        PipeDirection::Inbound => PIPE_ACCESS_INBOUND,
        PipeDirection::Outbound => PIPE_ACCESS_OUTBOUND,
    };
    let pipe_mode = match pipe_type {
        PipeType::Byte => PIPE_TYPE_BYTE,
        PipeType::Message => PIPE_TYPE_MESSAGE,
    };

    let handle;
    unsafe {
        handle = CreateNamedPipeA(
            name.as_ptr(),
            pipe_access,
            pipe_mode,
            max_instances,
            out_buffer_size,
            in_buffer_size,
            default_timeout,
            &mut SECURITY_ATTRIBUTES::default(),
        );
    }

    let error = IoError::last_os_error();
    if error.raw_os_error().is_some() {
        PipeCheck::Invalid(error)
    } else {
        PipeCheck::Valid(Handle(handle))
    }
}

// TODO convert to CreateFile
pub fn open_pipe(pipe_name: CString) -> HANDLE {
    unsafe {
        CreateFileA(
            pipe_name.as_ptr(),
            GENERIC_WRITE,
            0, // use default timeout
            &mut SECURITY_ATTRIBUTES::default(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL,
        )
    }
}

// Take PipeCheck instead
pub fn write_pipe(pipe: HANDLE, in_buf: &mut [u8]) -> u32 {
    let mut bytes_written = 0;
    let mut overlap = OVERLAPPED::default();

    unsafe {
        WriteFile(
            pipe,
            in_buf.as_mut_ptr() as *mut c_void,
            in_buf.len() as u32,
            &mut bytes_written,
            &mut overlap,
        );
    }

    bytes_written
}

// Take PipeCheck instead
pub fn read_pipe(pipe: HANDLE, out_buf: &mut [u8]) -> u32 {
    let mut bytes_read = 0;
    let mut overlap = OVERLAPPED::default();

    unsafe {
        ReadFile(
            pipe,
            out_buf.as_mut_ptr() as *mut c_void,
            size_of::<DWORD>() as u32,
            &mut bytes_read,
            &mut overlap,
        );
    }

    bytes_read
}

#[rustfmt::skip]
fn is_elevated() -> IoResult<bool> {
    let mut token = NULL;
    let mut token_check = TokenCheck::Invalid(IoError::new(ErrorKind::Other, "default"));
    let mut elevation = TOKEN_ELEVATION::default();
    let mut size = 0;

    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == (FALSE as i32) {
        token_check = TokenCheck::Invalid(IoError::last_os_error())
    }

    if token != NULL { token_check = TokenCheck::<IoError>::Valid(Handle(token)); }

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
