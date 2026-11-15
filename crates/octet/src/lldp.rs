//! Decodes a switch's CDP or LLDP announcement from a raw Ethernet frame.

use serde::Serialize;

#[derive(Serialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Neighbour {
    pub proto: &'static str,
    pub switch: String,
    pub port: String,
    pub model: String,
    pub vlan: Option<u16>,
    pub mgmt: String,
    pub mac: String,
}

/// Either protocol; None when the frame is neither or is malformed. Never panics.
pub fn parse(frame: &[u8]) -> Option<Neighbour> {
    let dst = frame.get(0..6)?;
    let mut n = match dst {
        [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc] => parse_cdp(frame)?,
        [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e | 0x03 | 0x00] => parse_lldp(frame)?,
        _ => return None,
    };
    n.mac = mac_str(frame.get(6..12)?);
    if n.switch.is_empty() && n.port.is_empty() {
        return None;
    }
    Some(n)
}

fn parse_cdp(f: &[u8]) -> Option<Neighbour> {
    if u16be(f, 12)? > 1500 || f.get(14..22)? != [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00] {
        return None;
    }
    let mut n = Neighbour { proto: "CDP", ..Default::default() };
    // CDP header (version, ttl, checksum) is 4 bytes at 22..26; TLVs follow.
    let mut p = 26;
    while let Some(h) = f.get(p..p + 4) {
        let t = u16::from_be_bytes([h[0], h[1]]);
        let len = u16::from_be_bytes([h[2], h[3]]) as usize;
        if len < 4 {
            break;
        }
        let Some(v) = f.get(p + 4..p + len) else { break };
        p += len;
        match t {
            0x0001 => n.switch = text(v),
            0x0002 => {
                if n.mgmt.is_empty() {
                    n.mgmt = cdp_ipv4(v).unwrap_or_default();
                }
            }
            0x0003 => n.port = text(v),
            0x0006 => n.model = text(v),
            0x000a => n.vlan = u16be(v, 0),
            _ => {}
        }
    }
    Some(n)
}

/// First IPv4 entry of a CDP Addresses TLV value.
fn cdp_ipv4(v: &[u8]) -> Option<String> {
    let count = u32::from_be_bytes(v.get(0..4)?.try_into().ok()?);
    let mut p = 4;
    for _ in 0..count {
        let pt = *v.get(p)?;
        let pl = *v.get(p + 1)? as usize;
        let proto = v.get(p + 2..p + 2 + pl)?;
        let al = u16be(v, p + 2 + pl)? as usize;
        let addr = v.get(p + 4 + pl..p + 4 + pl + al)?;
        if pt == 1 && matches!(proto, [0xcc]) && al == 4 {
            return Some(dotted(addr));
        }
        p += 4 + pl + al;
    }
    None
}

fn parse_lldp(f: &[u8]) -> Option<Neighbour> {
    let mut off = 12;
    if u16be(f, off)? == 0x8100 {
        off = 16; // 802.1Q tag present
    }
    if u16be(f, off)? != 0x88cc {
        return None;
    }
    let mut n = Neighbour { proto: "LLDP", ..Default::default() };
    let mut chassis = String::new();
    let mut port_id = String::new();
    let mut port_is_mac = false;
    let mut port_desc = String::new();
    let mut vlan = None;
    let mut p = off + 2;
    while let Some(h) = f.get(p..p + 2) {
        let hdr = u16::from_be_bytes([h[0], h[1]]);
        let t = hdr >> 9;
        let len = (hdr & 0x1ff) as usize;
        if t == 0 {
            break;
        }
        let Some(v) = f.get(p + 2..p + 2 + len) else { break };
        p += 2 + len;
        match t {
            1 => chassis = lldp_id(v, 4).0,
            2 => (port_id, port_is_mac) = lldp_id(v, 3),
            4 => port_desc = text(v),
            5 => n.switch = text(v),
            6 => n.model = text(v).lines().next().unwrap_or("").to_string(),
            // alen (5 = subtype + IPv4), addr subtype 1, then the 4 address bytes
            8 if n.mgmt.is_empty() && v.first() == Some(&5) && v.get(1) == Some(&1) => {
                if let Some(ip) = v.get(2..6) {
                    n.mgmt = dotted(ip);
                }
            }
            127 if vlan.is_none() && matches!(v.get(0..4), Some([0x00, 0x80, 0xc2, 0x01])) => vlan = u16be(v, 4),
            _ => {}
        }
    }
    if n.switch.is_empty() {
        n.switch = chassis;
    }
    n.port = if (port_is_mac || port_id.is_empty()) && !port_desc.is_empty() { port_desc } else { port_id };
    n.vlan = vlan;
    Some(n)
}

/// LLDP chassis/port ID value: subtype byte, then the ID. Returns (text, is_mac).
fn lldp_id(v: &[u8], mac_subtype: u8) -> (String, bool) {
    match v.split_first() {
        Some((&s, body)) if s == mac_subtype && body.len() == 6 => (mac_str(body), true),
        Some((_, body)) => (text(body), false),
        None => (String::new(), false),
    }
}

fn u16be(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at + 2)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).trim_end_matches(|c: char| c == '\0' || c.is_whitespace()).to_string()
}

fn mac_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
}

fn dotted(b: &[u8]) -> String {
    b.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(".")
}

const NO_NPCAP: &str = "Install Npcap (npcap.com, or with Wireshark) to see the switch port";

/// Listens on one adapter (its id, "{GUID}") until a CDP or LLDP announcement comes, or `secs` pass (None).
/// Through Npcap, loaded from System32\Npcap only when it is installed: the card must be promiscuous to pass these
/// frames up (pktmon, built into Windows, never sees them), and Npcap is what can ask for that. Octet doesn't ship it.
#[cfg(windows)]
pub fn listen(id: &str, secs: u64) -> Result<Option<Neighbour>, String> {
    use std::ffi::{CString, c_char, c_void};
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW};
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    #[repr(C)]
    struct Hdr { sec: i32, usec: i32, caplen: u32, len: u32 }
    #[repr(C)]
    struct Bpf { len: u32, insns: *mut c_void }
    type Open = unsafe extern "C" fn(*const c_char, i32, i32, i32, *mut c_char) -> *mut c_void;
    type Next = unsafe extern "C" fn(*mut c_void, *mut *const Hdr, *mut *const u8) -> i32;
    type Compile = unsafe extern "C" fn(*mut c_void, *mut Bpf, *const c_char, i32, u32) -> i32;
    type SetFilter = unsafe extern "C" fn(*mut c_void, *mut Bpf) -> i32;
    type FreeCode = unsafe extern "C" fn(*mut Bpf);
    type Close = unsafe extern "C" fn(*mut c_void);
    struct Handle(*mut c_void, Close);
    impl Drop for Handle {
        fn drop(&mut self) { unsafe { (self.1)(self.0) } }
    }
    // A GUID only: it goes into a device path.
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_hexdigit() || "{}-".contains(c)) {
        return Err("Not an adapter id".into());
    }
    // By full path from System32, never searched for: a planted wpcap.dll beside Octet must not load.
    let mut sys = [0u16; 260];
    let n = unsafe { GetSystemDirectoryW(sys.as_mut_ptr(), 260) } as usize;
    if n == 0 || n >= 260 {
        return Err(NO_NPCAP.into());
    }
    let path: Vec<u16> = format!(r"{}\Npcap\wpcap.dll", String::from_utf16_lossy(&sys[..n])).encode_utf16().chain([0]).collect();
    let lib = unsafe { LoadLibraryExW(path.as_ptr(), std::ptr::null_mut(), LOAD_WITH_ALTERED_SEARCH_PATH) };
    if lib.is_null() {
        return Err(NO_NPCAP.into());
    }
    macro_rules! sym {
        ($name:literal, $t:ty) => {
            unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $t>(GetProcAddress(lib, concat!($name, "\0").as_ptr()).ok_or(NO_NPCAP)?) }
        };
    }
    let (open, next, close) = (sym!("pcap_open_live", Open), sym!("pcap_next_ex", Next), sym!("pcap_close", Close));
    let (compile, set_filter, free_code) = (sym!("pcap_compile", Compile), sym!("pcap_setfilter", SetFilter), sym!("pcap_freecode", FreeCode));
    let dev = CString::new(format!(r"\Device\NPF_{id}")).map_err(|e| e.to_string())?;
    let mut err = [0 as c_char; 256];
    // Promiscuous, 0.5 s read timeout so the deadline is checked.
    let p = unsafe { open(dev.as_ptr(), 2048, 1, 500, err.as_mut_ptr()) };
    if p.is_null() {
        let why = unsafe { std::ffi::CStr::from_ptr(err.as_ptr()) }.to_string_lossy().into_owned();
        return Err(format!("Npcap could not open this adapter: {why}"));
    }
    let h = Handle(p, close);
    // Only these frames come up, so a busy network costs nothing; without the filter `parse` still sorts them.
    let filter = CString::new("ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc").map_err(|e| e.to_string())?;
    let mut prog = Bpf { len: 0, insns: std::ptr::null_mut() };
    if unsafe { compile(h.0, &mut prog, filter.as_ptr(), 1, u32::MAX) } == 0 {
        unsafe { set_filter(h.0, &mut prog); free_code(&mut prog) };
    }
    let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < end {
        let (mut hdr, mut data) = (std::ptr::null(), std::ptr::null());
        match unsafe { next(h.0, &mut hdr, &mut data) } {
            1 if !hdr.is_null() && !data.is_null() => {
                let frame = unsafe { std::slice::from_raw_parts(data, (*hdr).caplen as usize) };
                if let Some(n) = parse(frame) {
                    return Ok(Some(n));
                }
            }
            0 | 1 => {}
            _ => return Err("Npcap stopped reading this adapter".into()),
        }
    }
    Ok(None)
}

// ponytail: macOS can read these through BPF (/dev/bpf*, as root); not built yet.
#[cfg(not(windows))]
pub fn listen(_id: &str, _secs: u64) -> Result<Option<Neighbour>, String> {
    Err("Not on macOS yet".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CDP_HEX: &str = "01000ccccccc48a98a225cc10062aaaa0300000c20000179ec1600010009313057494e00020011000000010101cc0004c0a80afe0003000a65746865723500040008000000010005001e372e32352e3120323032362d31312d30322031323a33393a35330006000c4d696b726f54696b";
    const LLDP_HEX: &str = "0180c200000e48a98a225cc188cc02070448a98a225cbd040705657468657235060200790a05313057494e0c3d4d696b726f54696b20526f757465724f5320372e32352e3120323032362d31312d30322031323a33393a35332043353269472d354861784432486178440e04001400100806657468657235fe070012bb01000104100c0501c0a80afe0200000008000000";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn cdp_frame() {
        let n = parse(&hex(CDP_HEX)).unwrap();
        assert_eq!(n.proto, "CDP");
        assert_eq!(n.switch, "10WIN");
        assert_eq!(n.port, "ether5");
        assert_eq!(n.model, "MikroTik");
        assert_eq!(n.mgmt, "192.168.10.254");
        assert_eq!(n.mac, "48:a9:8a:22:5c:c1");
        assert_eq!(n.vlan, None);
    }

    #[test]
    fn lldp_frame() {
        let n = parse(&hex(LLDP_HEX)).unwrap();
        assert_eq!(n.proto, "LLDP");
        assert_eq!(n.switch, "10WIN");
        assert_eq!(n.port, "ether5");
        assert!(n.model.starts_with("MikroTik RouterOS 7.25.1"), "{}", n.model);
        assert_eq!(n.mgmt, "192.168.10.254");
        assert_eq!(n.mac, "48:a9:8a:22:5c:c1");
        assert_eq!(n.vlan, None);
    }

    #[test]
    fn lldp_802_1_vlan_tlv() {
        let mut f = hex(LLDP_HEX);
        let end = f.len() - 2; // insert before the end-of-LLDPDU TLV
        f.splice(end..end, hex("fe060080c201000a"));
        assert_eq!(parse(&f).unwrap().vlan, Some(10));
    }

    #[test]
    fn truncated_frames_do_not_panic() {
        for frame in [hex(CDP_HEX), hex(LLDP_HEX)] {
            for n in 0..=frame.len() {
                let _ = parse(&frame[..n]);
            }
        }
    }

    /// Listens on a real adapter: `$env:OCTET_NIC="{GUID}"; cargo test -p octet listens_here -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn listens_here() {
        let id = std::env::var("OCTET_NIC").expect("set OCTET_NIC to the adapter's {GUID}");
        println!("{:?}", listen(&id, 65));
    }

    #[test]
    fn ipv4_frame_is_none() {
        let f = hex("001122334455 48a98a225cc1 0800 450000140000000040060000c0a80a01c0a80afe".replace(' ', "").as_str());
        assert_eq!(parse(&f), None);
    }
}
