use std::ffi::{CStr, c_char};
use std::sync::LazyLock;

use dashmap::DashMap;
use nanorpc::{JrpcRequest, JrpcResponse};

use crate::{Client, Config};

struct SlotState {
    client: Client,
}

static SLOTS: LazyLock<DashMap<i32, SlotState>> = LazyLock::new(DashMap::new);

#[unsafe(no_mangle)]
pub extern "C" fn nullspace_start(slot: i32, toml_cfg: *const c_char) -> i32 {
    if toml_cfg.is_null() {
        return -1;
    }
    if SLOTS.contains_key(&slot) {
        return -1;
    }
    let cfg_str = unsafe { CStr::from_ptr(toml_cfg) };
    let cfg_str = match cfg_str.to_str() {
        Ok(value) => value,
        Err(_) => return -1,
    };
    let config: Config = match toml::from_str(cfg_str) {
        Ok(value) => value,
        Err(_) => return -1,
    };
    let client = Client::new(config);
    SLOTS.insert(slot, SlotState { client });
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn nullspace_stop(slot: i32) -> i32 {
    if SLOTS.remove(&slot).is_none() {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn nullspace_rpc(
    slot: i32,
    jrpc_inout: *mut c_char,
    jrpc_inout_maxlen: usize,
) -> i32 {
    if jrpc_inout.is_null() || jrpc_inout_maxlen == 0 {
        return -1;
    }
    let entry = match SLOTS.get(&slot) {
        Some(entry) => entry,
        None => return -1,
    };
    let input = unsafe { CStr::from_ptr(jrpc_inout) };
    let input = match input.to_str() {
        Ok(value) => value,
        Err(_) => return -1,
    };
    let req: JrpcRequest = match serde_json::from_str(input) {
        Ok(value) => value,
        Err(_) => return -1,
    };
    let resp_rx = match entry.client.send_rpc_raw(req) {
        Ok(receiver) => receiver,
        Err(_) => return -1,
    };
    let response: JrpcResponse = match pollster::block_on(resp_rx) {
        Ok(value) => value,
        Err(_) => return -1,
    };
    let output = match serde_json::to_string(&response) {
        Ok(value) => value,
        Err(_) => return -1,
    };
    let bytes = output.as_bytes();
    if bytes.len() + 1 > jrpc_inout_maxlen {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), jrpc_inout.cast::<u8>(), bytes.len());
        *jrpc_inout.add(bytes.len()) = 0;
    }
    bytes.len() as i32
}
