//! Planted descriptor bugs for zwanzig, on the gate connection's handle as
//! the plugin calls it. Analysed, never compiled; each function is one bug.

const fd = @import("fd");

// double close
pub fn doubleClose() !void {
    const s = try fd.connectUnix("/run/frisket-sudo/gate.sock", null);
    s.close();
    s.close();
}

// send after close
pub fn sendAfterClose() !void {
    const s = try fd.connectUnix("/run/frisket-sudo/gate.sock", null);
    s.close();
    try s.sendAll("FSUD");
}

// peer check after close
pub fn peerAfterClose() !u32 {
    const s = try fd.connectUnix("/run/frisket-sudo/gate.sock", null);
    s.close();
    return s.peerUid();
}

// control: closed once, used before
pub fn ok() !void {
    const s = try fd.connectUnix("/run/frisket-sudo/gate.sock", null);
    defer s.close();
    try s.sendAll("FSUD");
}
