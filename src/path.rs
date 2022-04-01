use std::ffi::c_void;
use std::fs;
use widestring::U16CString;
pub struct CPath(pub U16CString);

impl CPath {
    pub fn new(u16cstring: U16CString) -> Self {
        Self(u16cstring)
    }
    pub fn path_exists(&self) -> bool {
        let rstring_version = self.0.to_string().unwrap();
        fs::metadata(&rstring_version).is_ok()
    }
    pub fn len(&self) -> usize {
        self.0.len() * 2 + 1
    }
    pub fn as_ptr(&self) -> *const c_void {
        self.0.as_ptr() as _
    }
}
