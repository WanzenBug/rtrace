use crate::OsError;
use crate::StoppedProcess;
use std::ffi::OsString;
use std::io::{Error, ErrorKind};
use std::mem::size_of;
use std::mem::MaybeUninit;
use std::os::raw::c_void;
use std::slice::from_raw_parts_mut;

pub unsafe trait FromStoppedProcess: Sized {
    unsafe fn from_process(process: &StoppedProcess, address: *mut c_void)
        -> Result<Self, OsError>;
}

unsafe impl FromStoppedProcess for [*mut c_void; 512] {
    unsafe fn from_process(process: &StoppedProcess, address: *mut c_void) -> Result<Self, Error> {
        let mut uninit = MaybeUninit::uninit();
        let buffer = from_raw_parts_mut(uninit.as_mut_ptr() as *mut u8, size_of::<Self>());
        let n = process.read_in_child_vm(buffer, address)?;
        if n == 0 {
            return Err(OsError::from(ErrorKind::InvalidData));
        }
        Ok(uninit.assume_init())
    }
}

unsafe impl FromStoppedProcess for OsString {
    unsafe fn from_process(process: &StoppedProcess, address: *mut c_void) -> Result<Self, Error> {
        process.read_os_string_in_child_vm(address)
    }
}

unsafe impl FromStoppedProcess for Vec<OsString> {
    unsafe fn from_process(process: &StoppedProcess, address: *mut c_void) -> Result<Self, Error> {
        let address_buffer: [*mut c_void; 512] =
            FromStoppedProcess::from_process(process, address)?;
        let mut result = Vec::new();
        for &item_address in address_buffer.iter() {
            if item_address.is_null() {
                break;
            }
            result.push(FromStoppedProcess::from_process(process, item_address)?)
        }
        Ok(result)
    }
}
