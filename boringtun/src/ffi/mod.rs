// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Requiring explicit per-fn "Safety" docs not worth it. Just pass in valid
// pointers and buffers/lengths to these, ok?
#![allow(clippy::missing_safety_doc)]
#![allow(unsafe_code, reason = "C ABI boundary")]

//! C bindings for the BoringTun library
use super::noise::{Tunn, TunnResult};
use crate::x25519::{PublicKey, StaticSecret};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hex::encode as encode_hex;
use libc::{SIGSEGV, raise};
use parking_lot::Mutex;
use rand_core::OsRng;
use tracing_subscriber::fmt;

use crate::serialization::KeyBytes;
use std::ffi::{CStr, CString};
use std::io::{Error, Write};
use std::os::raw::c_char;
use std::panic;
use std::ptr;
use std::slice;
use std::sync::Once;

static PANIC_HOOK: Once = Once::new();

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// Indicates the operation required from the caller
pub enum result_type {
    /// No operation is required.
    WIREGUARD_DONE = 0,
    /// Write dst buffer to network. Size indicates the number of bytes to write.
    WRITE_TO_NETWORK = 1,
    /// Some error occurred, no operation is required. Size indicates error code.
    WIREGUARD_ERROR = 2,
    /// Write dst buffer to the interface as an ipv4 packet. Size indicates the number of bytes to write.
    WRITE_TO_TUNNEL_IPV4 = 4,
    /// Write dst buffer to the interface as an ipv6 packet. Size indicates the number of bytes to write.
    WRITE_TO_TUNNEL_IPV6 = 6,
}

/// The return type of WireGuard functions
#[repr(C)]
#[derive(Debug)]
pub struct wireguard_result {
    /// The operation to be performed by the caller
    pub op: result_type,
    /// Additional information, required to perform the operation
    pub size: usize,
}

#[repr(C)]
#[derive(Debug)]
/// Tunnel statistics returned by `wireguard_stats`.
pub struct stats {
    /// Seconds since the last handshake, or -1.
    pub time_since_last_handshake: i64,
    /// Bytes sent.
    pub tx_bytes: usize,
    /// Bytes received.
    pub rx_bytes: usize,
    /// Estimated packet loss in `[0, 1]`.
    pub estimated_loss: f32,
    /// Round-trip time of the last handshake in milliseconds, or -1.
    pub estimated_rtt: i32,
    reserved: [u8; 56], // Make sure to add new fields in this space, keeping total size constant
}

impl<'a> From<TunnResult<'a>> for wireguard_result {
    fn from(res: TunnResult<'a>) -> Self {
        match res {
            TunnResult::Done => Self {
                op: result_type::WIREGUARD_DONE,
                size: 0,
            },
            TunnResult::Err(e) => Self {
                op: result_type::WIREGUARD_ERROR,
                size: e as _,
            },
            TunnResult::WriteToNetwork(b) => Self {
                op: result_type::WRITE_TO_NETWORK,
                size: b.len(),
            },
            TunnResult::WriteToTunnelV4(b, _) => Self {
                op: result_type::WRITE_TO_TUNNEL_IPV4,
                size: b.len(),
            },
            TunnResult::WriteToTunnelV6(b, _) => Self {
                op: result_type::WRITE_TO_TUNNEL_IPV6,
                size: b.len(),
            },
        }
    }
}

#[repr(C)]
/// An X25519 key.
pub struct x25519_key {
    /// The raw key bytes.
    pub key: [u8; 32],
}

impl std::fmt::Debug for x25519_key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("x25519_key(<redacted>)")
    }
}

impl wireguard_result {
    const INVALID_ARGUMENT: Self = Self {
        op: result_type::WIREGUARD_ERROR,
        size: 0,
    };
}

/// Converts a Rust string into a C string owned by the caller, or NULL if it contains a NUL byte.
fn into_c_string(s: String) -> *const c_char {
    CString::new(s).map_or(ptr::null(), |s| CString::into_raw(s).cast_const())
}

/// Reads a UTF-8 C string; NULL or invalid UTF-8 yields `None`.
///
/// # Safety
/// `ptr` must be NULL or point to a NUL-terminated string that outlives `'a`.
unsafe fn str_from_ptr<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `ptr` is a valid NUL-terminated string.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// Locks the tunnel behind `tunnel`, or returns `None` for NULL.
///
/// # Safety
/// `tunnel` must be NULL or a pointer returned by `new_tunnel` that was not freed.
const unsafe fn tunnel_ref<'a>(tunnel: *const Mutex<Tunn>) -> Option<&'a Mutex<Tunn>> {
    // SAFETY: the caller guarantees `tunnel` is NULL or a live pointer from `new_tunnel`.
    unsafe { tunnel.as_ref() }
}

/// Builds the byte slices for a C buffer pair.
///
/// # Safety
/// `ptr` must be valid for `len` bytes (or `len` must be 0) for the lifetime `'a`.
const unsafe fn buf_mut<'a>(ptr: *mut u8, len: u32) -> &'a mut [u8] {
    if ptr.is_null() || len == 0 {
        return &mut [];
    }
    // SAFETY: the caller guarantees `ptr` is valid for writes of `len` bytes and not aliased.
    unsafe { slice::from_raw_parts_mut(ptr, len as usize) }
}

/// # Safety
/// `ptr` must be valid for reads of `len` bytes (or `len` must be 0) for the lifetime `'a`.
const unsafe fn buf<'a>(ptr: *const u8, len: u32) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: the caller guarantees `ptr` is valid for reads of `len` bytes.
    unsafe { slice::from_raw_parts(ptr, len as usize) }
}

/// Generates a new x25519 secret key.
#[unsafe(no_mangle)]
pub extern "C" fn x25519_secret_key() -> x25519_key {
    x25519_key {
        key: StaticSecret::random_from_rng(OsRng).to_bytes(),
    }
}

/// Computes a public x25519 key from a secret key.
#[unsafe(no_mangle)]
pub extern "C" fn x25519_public_key(private_key: x25519_key) -> x25519_key {
    let private = StaticSecret::from(private_key.key);
    let public = PublicKey::from(&private);
    x25519_key {
        key: public.to_bytes(),
    }
}

/// Returns the base64 encoding of a key as a UTF8 C-string.
///
/// The memory has to be freed by calling `x25519_key_to_str_free`
#[unsafe(no_mangle)]
pub extern "C" fn x25519_key_to_base64(key: x25519_key) -> *const c_char {
    into_c_string(BASE64.encode(key.key))
}

/// Returns the hex encoding of a key as a UTF8 C-string.
///
/// The memory has to be freed by calling `x25519_key_to_str_free`
#[unsafe(no_mangle)]
pub extern "C" fn x25519_key_to_hex(key: x25519_key) -> *const c_char {
    into_c_string(encode_hex(key.key))
}

/// Frees memory of the string given by `x25519_key_to_hex` or `x25519_key_to_base64`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x25519_key_to_str_free(stringified_key: *mut c_char) {
    if stringified_key.is_null() {
        return;
    }
    // SAFETY: the caller passes a string returned by `x25519_key_to_hex`/`x25519_key_to_base64`.
    drop(unsafe { CString::from_raw(stringified_key) });
}

/// Check if the input C-string represents a valid base64 encoded x25519 key.
/// Return 1 if valid 0 otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn check_base64_encoded_x25519_key(key: *const c_char) -> i32 {
    // SAFETY: the caller passes NULL or a valid NUL-terminated string.
    let Some(utf8_key) = (unsafe { str_from_ptr(key) }) else {
        return 0;
    };

    BASE64.decode(utf8_key).map_or(0, |key| {
        let len = key.len();
        let zero = key.into_iter().fold(0u8, |acc, b| acc | b);
        i32::from(len == 32 && zero != 0)
    })
}

/// Custom `tracing_subscriber` writer to an external function pointer
struct FFIFunctionPointerWriter {
    log_func: unsafe extern "C" fn(*const c_char),
}

/// Implements Write trait for use with `tracing_subscriber`
impl Write for FFIFunctionPointerWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        let out_str = String::from_utf8_lossy(buf).to_string();
        if let Ok(c_string) = CString::new(out_str) {
            // SAFETY: `log_func` was supplied by the C caller and receives a valid C string
            // that lives until the call returns.
            unsafe { (self.log_func)(c_string.as_ptr()) }
            Ok(buf.len())
        } else {
            Err(Error::other("Failed to create CString from buffer."))
        }
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        // no-op
        Ok(())
    }
}

/// Sets the default `tracing_subscriber` to write to `log_func`.
///
/// Uses Compact format without level, target, thread ids, thread names, or ansi control characters.
/// Subscribes to TRACE level events.
///
/// This function should only be called once as setting the default `tracing_subscriber`
/// more than once will result in an error.
///
/// Returns false on failure.
///
/// # Safety
///
/// `c_char` will be freed by the library after calling `log_func`. If the value needs
/// to be stored then `log_func` needs to create a copy, e.g. `strcpy`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn set_logging_function(
    log_func: unsafe extern "C" fn(*const c_char),
) -> bool {
    let result = std::panic::catch_unwind(|| -> bool {
        let writer = FFIFunctionPointerWriter { log_func };
        let format = fmt::format()
            // don't include levels in formatted output
            .with_level(false)
            // don't include targets
            .with_target(false)
            // don't 'include the thread ID of the current thread
            .with_thread_ids(false)
            // don't 'include the name of the current thread
            .with_thread_names(false)
            // use the `Compact` formatting style.
            .compact()
            // disable terminal escape codes
            .with_ansi(false);

        fmt()
            .event_format(format)
            .with_writer(std::sync::Mutex::new(writer))
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .try_init()
            .is_ok()
    });
    result.unwrap_or_default()
}

/// Allocate a new tunnel, return NULL on failure.
/// Keys must be valid base64 encoded 32-byte keys.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn new_tunnel(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
) -> *mut Mutex<Tunn> {
    // SAFETY: the caller passes NULL or valid NUL-terminated strings.
    let (static_private, server_static_public) = unsafe {
        (
            str_from_ptr(static_private),
            str_from_ptr(server_static_public),
        )
    };
    let (Some(static_private), Some(server_static_public)) = (static_private, server_static_public)
    else {
        return ptr::null_mut();
    };

    let preshared_key = if preshared_key.is_null() {
        None
    } else {
        // SAFETY: `preshared_key` is non-NULL and the caller guarantees it is a C string.
        match unsafe { str_from_ptr(preshared_key) }.map(str::parse::<KeyBytes>) {
            Some(Ok(key)) => Some(key.0),
            _ => return ptr::null_mut(),
        }
    };

    let Ok(private_key) = static_private.parse::<KeyBytes>() else {
        return ptr::null_mut();
    };
    let Ok(public_key) = server_static_public.parse::<KeyBytes>() else {
        return ptr::null_mut();
    };

    let keep_alive = if keep_alive == 0 {
        None
    } else {
        Some(keep_alive)
    };

    let tunnel = Box::new(Mutex::new(Tunn::new(
        StaticSecret::from(private_key.0),
        PublicKey::from(public_key.0),
        preshared_key,
        keep_alive,
        index,
        None,
    )));

    PANIC_HOOK.call_once(|| {
        // FFI won't properly unwind on panic, but it will if we cause a segmentation fault
        panic::set_hook(Box::new(move |_| {
            // SAFETY: raising a signal has no memory-safety preconditions.
            unsafe {
                raise(SIGSEGV);
            }
        }));
    });

    Box::into_raw(tunnel)
}

/// Drops the Tunn object
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tunnel_free(tunnel: *mut Mutex<Tunn>) {
    if tunnel.is_null() {
        return;
    }
    // SAFETY: the caller passes a pointer returned by `new_tunnel`, exactly once.
    drop(unsafe { Box::from_raw(tunnel) });
}

/// Write an IP packet from the tunnel interface.
/// For more details check `noise::tunnel_to_network` functions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wireguard_write(
    tunnel: *const Mutex<Tunn>,
    src: *const u8,
    src_size: u32,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    // SAFETY: the caller passes a live tunnel and buffers valid for the given sizes.
    let (tunnel, src, dst) = unsafe {
        (
            tunnel_ref(tunnel),
            buf(src, src_size),
            buf_mut(dst, dst_size),
        )
    };
    let Some(tunnel) = tunnel else {
        return wireguard_result::INVALID_ARGUMENT;
    };
    wireguard_result::from(tunnel.lock().encapsulate(src, dst))
}

/// Read a UDP packet from the server.
/// For more details check `noise::network_to_tunnel` functions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wireguard_read(
    tunnel: *const Mutex<Tunn>,
    src: *const u8,
    src_size: u32,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    // SAFETY: the caller passes a live tunnel and buffers valid for the given sizes.
    let (tunnel, src, dst) = unsafe {
        (
            tunnel_ref(tunnel),
            buf(src, src_size),
            buf_mut(dst, dst_size),
        )
    };
    let Some(tunnel) = tunnel else {
        return wireguard_result::INVALID_ARGUMENT;
    };
    wireguard_result::from(tunnel.lock().decapsulate(None, src, dst))
}

/// This is a state keeping function, that need to be called periodically.
/// Recommended interval: 100ms.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wireguard_tick(
    tunnel: *const Mutex<Tunn>,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    // SAFETY: the caller passes a live tunnel and a buffer valid for `dst_size` bytes.
    let (tunnel, dst) = unsafe { (tunnel_ref(tunnel), buf_mut(dst, dst_size)) };
    let Some(tunnel) = tunnel else {
        return wireguard_result::INVALID_ARGUMENT;
    };
    wireguard_result::from(tunnel.lock().update_timers(dst))
}

/// Force the tunnel to initiate a new handshake, dst buffer must be at least 148 byte long.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wireguard_force_handshake(
    tunnel: *const Mutex<Tunn>,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    // SAFETY: the caller passes a live tunnel and a buffer valid for `dst_size` bytes.
    let (tunnel, dst) = unsafe { (tunnel_ref(tunnel), buf_mut(dst, dst_size)) };
    let Some(tunnel) = tunnel else {
        return wireguard_result::INVALID_ARGUMENT;
    };
    wireguard_result::from(tunnel.lock().format_handshake_initiation(dst, true))
}

/// Returns stats from the tunnel:
/// Time of last handshake in seconds (or -1 if no handshake occurred)
/// Number of data bytes encapsulated
/// Number of data bytes decapsulated
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wireguard_stats(tunnel: *const Mutex<Tunn>) -> stats {
    // SAFETY: the caller passes NULL or a live tunnel.
    let Some(tunnel) = (unsafe { tunnel_ref(tunnel) }) else {
        return stats {
            time_since_last_handshake: -1,
            tx_bytes: 0,
            rx_bytes: 0,
            estimated_loss: 0.0,
            estimated_rtt: -1,
            reserved: [0u8; 56],
        };
    };
    let (time, tx_bytes, rx_bytes, estimated_loss, estimated_rtt) = tunnel.lock().stats();
    stats {
        time_since_last_handshake: time
            .map_or(-1, |t| i64::try_from(t.as_secs()).unwrap_or(i64::MAX)),
        tx_bytes,
        rx_bytes,
        estimated_loss,
        estimated_rtt: estimated_rtt.map_or(-1, |r| i32::try_from(r).unwrap_or(i32::MAX)),
        reserved: [0u8; 56],
    }
}
