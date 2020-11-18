use std::process::exit;

use winapi::um::processthreadsapi::{GetCurrentProcess, GetProcessId};

use super::handle::HandleCheck;

pub fn get_process() -> HandleCheck {
    let process = unsafe { GetCurrentProcess() };
    HandleCheck::validate(process)
}

pub fn get_process_pid(process: HandleCheck) -> u32 {
    let process = match process {
        HandleCheck::Valid(proc) => proc,
        HandleCheck::Invalid(e) => {
            log::error!("Invalid process handle: {}", e);
            exit(22)
        }
    };

    unsafe { GetProcessId(process.into_raw()) }
}
