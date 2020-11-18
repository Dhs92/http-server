use std::{io::Error as IoError, mem::ManuallyDrop};

use winapi::{
    shared::ntdef::NULL,
    um::{handleapi::CloseHandle, winnt::HANDLE},
};

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
