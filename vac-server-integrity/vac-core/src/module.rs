use crate::buffer::DataBuffer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanError {
    None,
    PermissionDenied,
    SystemCallFailed,
    InvalidState,
    NotSupportedOnPlatform,
}

#[derive(Debug)]
pub struct ScanReport {
    pub data: DataBuffer,
    pub module_id: u32,
    pub error: ScanError,
}

impl ScanReport {
    pub fn new(module_id: u32) -> Self {
        Self {
            data: DataBuffer::new(),
            module_id,
            error: ScanError::None,
        }
    }
}

pub trait Module {
    fn name(&self) -> &'static str;
    fn module_id(&self) -> u32;
    fn scan(&mut self, report: &mut ScanReport);
}
