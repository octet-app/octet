//! Read-only MCP server over stdio. It never changes a setting: it must not call
//! crate::change, crate::win or crate::ics.

use serde::Serialize;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};

const DEFAULT_PROTOCOL: &str = "2025-06-18";

pub fn run() {
    let stdout = io::stdout();
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if let Some(out) = handle(&line) {
            let mut lock = stdout.lock();
            let _ = writeln!(lock, "{out}");
            let _ = lock.flush();
        }
    }
}

fn reply(id: Value, result: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string()
}

fn rpc_error(id: Value, code: i64, message: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}).to_string()
}

/// Pure dispatch: one request line in, one response line out (None for notifications).
fn handle(line: &str) -> Option<String> {
    let Ok(req) = serde_json::from_str::<Value>(line) else {
        return Some(rpc_error(Value::Null, -32700, "Parse error"));
    };
    let id = req.get("id")?.clone();
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    match req.get("method").and_then(Value::as_str).unwrap_or("") {
        "initialize" => {
            let protocol = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_PROTOCOL);
            Some(reply(id, json!({
                "protocolVersion": protocol,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "octet", "version": env!("CARGO_PKG_VERSION")}
            })))
        }
        "ping" => Some(reply(id, json!({}))),
        "tools/list" => Some(reply(id, json!({"tools": tools()}))),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return Some(rpc_error(id, -32602, "Invalid params: missing tool name"));
            };
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let (text, is_error) = match call_tool(name, &args) {
                Ok(v) => (serde_json::to_string_pretty(&v).unwrap_or_default(), false),
                Err(e) => (e, true),
            };
            Some(reply(id, json!({
                "content": [{"type": "text", "text": text}],
                "isError": is_error
            })))
        }
        _ => Some(rpc_error(id, -32601, "Method not found")),
    }
}

fn tools() -> Value {
    let ip = json!({"type": "string", "description": "IPv4 address, e.g. 192.168.1.10"});
    let index = json!({"type": "number", "description": "Adapter interface index from adapters"});
    json!([
        {
            "name": "adapters",
            "description": "Lists this PC's network adapters with their ids, indexes, addresses and gateways. Reads only; changes nothing.",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "ping",
            "description": "Pings one IPv4 address once from this PC and reports the round trip in milliseconds. Reads only; changes nothing.",
            "inputSchema": {"type": "object", "properties": {"address": ip}, "required": ["address"]}
        },
        {
            "name": "scan",
            "description": "Scans a private /24 (or smaller) network for responding hosts and returns their MAC, vendor and ping. Reads only; changes nothing.",
            "inputSchema": {"type": "object", "properties": {
                "network": {"type": "string", "description": "Private network, e.g. 192.168.1.0/24"},
                "index": index
            }, "required": ["network", "index"]}
        },
        {
            "name": "neighbours",
            "description": "Lists the IP and MAC address pairs this PC's neighbour table knows on one adapter. Reads only; changes nothing.",
            "inputSchema": {"type": "object", "properties": {"index": index}, "required": ["index"]}
        },
        {
            "name": "mikrotik",
            "description": "Finds MikroTik devices on the network that announce themselves over MNDP and returns what they report. Reads only; changes nothing.",
            "inputSchema": {"type": "object", "properties": {
                "address": {"type": "string", "description": "This PC's own IPv4 address on that network"}
            }, "required": ["address"]}
        },
        {
            "name": "switch_port",
            "description": "Listens for a switch's LLDP or CDP announcement on one adapter to show which switch and port this PC is plugged into. Reads only; changes nothing.",
            "inputSchema": {"type": "object", "properties": {
                "id": {"type": "string", "description": "Adapter id from adapters"},
                "seconds": {"type": "number", "description": "How long to listen, 1 to 120 (default 65)"}
            }, "required": ["id"]}
        }
    ])
}

fn call_tool(name: &str, args: &Value) -> Result<Value, String> {
    match name {
        "adapters" => to_value(crate::adapters::read()?),
        "ping" => {
            let ip = ipv4_arg(args, "address")?;
            let ms = crate::net::ping(ip, None, 1500);
            Ok(json!({"address": ip.to_string(), "ms": ms}))
        }
        "scan" => {
            let (first, last) = network_arg(args, "network")?;
            let index = u32_arg(args, "index")?;
            let ips: Vec<Ipv4Addr> = (first..=last).map(Ipv4Addr::from).collect();
            let cursor = AtomicUsize::new(0);
            let mut found: Vec<(Ipv4Addr, crate::net::Host)> = std::thread::scope(|s| {
                let workers: Vec<_> = (0..16)
                    .map(|_| {
                        s.spawn(|| {
                            let mut mine = Vec::new();
                            loop {
                                let i = cursor.fetch_add(1, Ordering::Relaxed);
                                let Some(ip) = ips.get(i) else { break };
                                if let Some(host) = crate::net::scan_host(*ip, None, index) {
                                    mine.push((*ip, host));
                                }
                            }
                            mine
                        })
                    })
                    .collect();
                workers.into_iter().flat_map(|w| w.join().unwrap_or_default()).collect()
            });
            found.sort_by_key(|(ip, _)| *ip);
            let mut out = Vec::new();
            for (ip, host) in found {
                let mut v = to_value(host)?;
                v["address"] = json!(ip.to_string());
                out.push(v);
            }
            Ok(Value::Array(out))
        }
        "neighbours" => {
            let index = u32_arg(args, "index")?;
            let list = neighbours_for(index)?;
            Ok(Value::Array(list.into_iter()
                .map(|(ip, mac)| json!({"ip": ip.to_string(), "mac": mac}))
                .collect()))
        }
        "mikrotik" => {
            let local = ipv4_arg(args, "address")?;
            to_value(crate::net::mndp(local, 1500)?)
        }
        "switch_port" => {
            let id = str_arg(args, "id")?;
            let secs = match args.get("seconds") {
                None | Some(Value::Null) => 65,
                Some(v) => v.as_u64().filter(|s| (1..=120).contains(s))
                    .ok_or("seconds must be a whole number from 1 to 120")?,
            };
            match crate::lldp::listen(id, secs)? {
                Some(n) => to_value(n),
                None => Ok(json!({
                    "heard": null,
                    "note": "Nothing heard: CDP/LLDP may be off on the switch"
                })),
            }
        }
        _ => Err(format!("Unknown tool: {name}")),
    }
}

#[cfg(windows)]
fn neighbours_for(index: u32) -> Result<Vec<(Ipv4Addr, String)>, String> {
    Ok(crate::net::neighbours(index))
}

#[cfg(target_os = "macos")]
fn neighbours_for(index: u32) -> Result<Vec<(Ipv4Addr, String)>, String> {
    Ok(crate::mac::neighbours(index))
}

fn to_value<T: Serialize>(v: T) -> Result<Value, String> {
    serde_json::to_value(v).map_err(|e| e.to_string())
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .ok_or_else(|| format!("Missing argument: {key}"))?
        .as_str()
        .ok_or_else(|| format!("{key} must be a string"))
}

fn ipv4_arg(args: &Value, key: &str) -> Result<Ipv4Addr, String> {
    let s = str_arg(args, key)?;
    s.parse().map_err(|_| format!("{key} is not an IPv4 address: {s}"))
}

fn u32_arg(args: &Value, key: &str) -> Result<u32, String> {
    args.get(key)
        .ok_or_else(|| format!("Missing argument: {key}"))?
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| format!("{key} must be a whole number"))
}

/// "192.168.1.0/24" -> first and last address to scan (network and broadcast excluded).
/// Only private networks of /24 or smaller are allowed.
fn network_arg(args: &Value, key: &str) -> Result<(u32, u32), String> {
    let s = str_arg(args, key)?;
    let usage = "network must look like 192.168.1.0/24";
    let (addr, prefix) = s.split_once('/').ok_or(usage)?;
    let ip: Ipv4Addr = addr.parse().map_err(|_| usage)?;
    let prefix: u32 = prefix.parse::<u32>().ok().filter(|p| *p <= 32).ok_or(usage)?;
    if !ip.is_private() {
        return Err(format!("Only private networks can be scanned: {s}"));
    }
    if prefix < 24 {
        return Err(format!("Network too big: use a /24 or smaller, not {s}"));
    }
    let mask = u32::MAX << (32 - prefix);
    let net = u32::from(ip) & mask;
    let broadcast = net | !mask;
    Ok((net + 1, broadcast - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_error(out: Option<String>) -> bool {
        let v: Value = serde_json::from_str(&out.expect("expected a response")).unwrap();
        v["result"]["isError"] == true
    }

    fn call(name: &str, args: Value) -> Option<String> {
        handle(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": args}}).to_string())
    }

    #[test]
    fn initialize_echoes_protocol() {
        let out = handle(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(v["result"]["serverInfo"]["name"], "octet");
    }

    #[test]
    fn notification_gets_no_reply() {
        assert!(handle(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
    }

    #[test]
    fn tools_list_has_six_tools() {
        let out = handle(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let names: Vec<&str> = v["result"]["tools"].as_array().unwrap()
            .iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["adapters", "ping", "scan", "neighbours", "mikrotik", "switch_port"]);
    }

    #[test]
    fn unknown_method_is_32601() {
        let out = handle(r#"{"jsonrpc":"2.0","id":3,"method":"nope"}"#).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["error"]["code"], -32601);
    }

    #[test]
    fn garbage_line_is_32700() {
        let out = handle("{not json").unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["error"]["code"], -32700);
        assert!(v["id"].is_null());
    }

    #[test]
    fn bad_ping_address_is_tool_error() {
        assert!(is_error(call("ping", json!({"address": "not-an-ip"}))));
    }

    #[test]
    fn public_scan_is_rejected() {
        assert!(is_error(call("scan", json!({"network": "8.8.8.0/24", "index": 1}))));
    }

    #[test]
    fn oversized_scan_is_rejected() {
        assert!(is_error(call("scan", json!({"network": "10.0.0.0/16", "index": 1}))));
    }

    #[test]
    fn unknown_tool_is_tool_error() {
        assert!(is_error(call("set_dns", json!({}))));
    }

    #[test]
    fn network_range_is_host_addresses_only() {
        let (first, last) = network_arg(&json!({"network": "192.168.1.0/24"}), "network").unwrap();
        assert_eq!(Ipv4Addr::from(first), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(Ipv4Addr::from(last), Ipv4Addr::new(192, 168, 1, 254));
    }
}
