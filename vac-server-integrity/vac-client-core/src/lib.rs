pub mod scan;
pub use scan::run_module;

pub const CLIENT_MODULE_PROCESS: u32 = 1;
pub const CLIENT_MODULE_LIBRARIES: u32 = 2;
pub const CLIENT_MODULE_DEBUGGER: u32 = 3;
pub const CLIENT_MODULE_ASSEMBLIES: u32 = 4;
pub const CLIENT_MODULE_ENVIRONMENT: u32 = 5;
pub const CLIENT_MODULE_CHEATS: u32 = 6;
