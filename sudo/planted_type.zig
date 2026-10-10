//! A plugin of the wrong type, 1 (policy), under the audit plugin's name:
//! sudo would load it and call its slots as the wrong functions.

const abi = @import("abi");

export var frisket_audit: abi.c.struct_audit_plugin = .{ .type = 1, .version = abi.api_version };
