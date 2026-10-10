//! The one file that reads C headers: sudo's plugin API and PAM's.

pub const c = @cImport({
    @cInclude("sudo_plugin.h");
    @cInclude("security/pam_appl.h");
});

pub const api_version: c_uint = (c.SUDO_API_VERSION_MAJOR << 16) | c.SUDO_API_VERSION_MINOR;
