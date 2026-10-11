//! The one file that reads C headers: sudo's plugin API, PAM's, and the
//! libc id calls the drop for the agent's connect makes.

pub const c = @cImport({
    @cDefine("_GNU_SOURCE", {});
    @cInclude("unistd.h");
    @cInclude("grp.h");
    @cInclude("sudo_plugin.h");
    @cInclude("security/pam_appl.h");
});

pub const api_version: c_uint = (c.SUDO_API_VERSION_MAJOR << 16) | c.SUDO_API_VERSION_MINOR;
