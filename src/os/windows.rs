use crate::config::Config;
use crate::SERVER_NAME;
use crate::handle_request;
use thread_pool::ThreadPool;
use std::ffi::CString;
use std::fmt::Display;
use std::fs::OpenOptions;
use std::io::Write;
use std::mem::{size_of, size_of_val};
use std::net::{TcpListener, ToSocketAddrs};
use std::os::windows::io::{AsRawSocket, FromRawSocket};
use std::process::exit;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::{FALSE, NULL};
use winapi::um::{
    errhandlingapi::GetLastError,
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

enum PipeCheck {
    Pipe(HANDLE),
    Invalid(DWORD), // error code
}

// TODO error handling instead of unwraps
pub fn start() {
    simple_logging::log_to_stderr(log::LevelFilter::Error);
    #[cfg(not(debug_assertions))]
    match create_dir(CONFIG_PATH) {
        Ok(_) => log::debug!("Created config directory: {}", CONFIG_PATH),
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
    if is_elevated() {
        listener = bind(&config.address());
        let mut in_buf = bincode::serialize(&listener.as_raw_socket()).unwrap(); // shouldn't fail for any reason
        let handle = open_pipe(pipe_name);
        write_pipe(handle, &mut in_buf);
    } else {
        // TODO read from pipe
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
            PipeCheck::Pipe(p) => p,
            PipeCheck::Invalid(err) => {
                log::error!("Unable to create pipe, error code: {:0X}", err);
                exit(err as i32)
            }
        };

        let mut out_buf = [0; 4096];
        read_pipe(pipe, &mut out_buf);

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
) -> PipeCheck {
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

    let error = unsafe { GetLastError() };
    if error != 0 {
        PipeCheck::Invalid(error)
    } else {
        PipeCheck::Pipe(handle)
    }
}

// TODO convert to CreateFile
pub fn open_pipe(pipe_name: CString) -> HANDLE {
    unsafe {
        CreateFileA(
            pipe_name.as_ptr(),
            GENERIC_WRITE,
            0,
            &mut SECURITY_ATTRIBUTES::default(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL,
        )
    }
}

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
fn is_elevated() -> bool {
    let mut is_elevated = false;
    let mut token: HANDLE = NULL;
    let mut elevation: TOKEN_ELEVATION = TOKEN_ELEVATION::default();
    let mut check = true;
    let mut size: DWORD = 0;

    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == (FALSE as i32) {
        log::error!("Failed to get Process Token: {}", unsafe { GetLastError() });
        check = false;
    }

    if unsafe {
        let elevation_ptr = &mut elevation as *mut _ as *mut c_void;
        let elevation_size = size_of_val(&elevation) as u32;
        GetTokenInformation(token, TokenElevation, elevation_ptr, elevation_size, &mut size)
    } == (FALSE as i32) && !check
    {
        log::error!("Failed to get Token Information: {}", unsafe {
            GetLastError()
        });
        check = false
    }

    if check {
        is_elevated = elevation.TokenIsElevated != 0
    }

    if token != NULL {
        unsafe { CloseHandle(token) };
    }

    is_elevated
}
