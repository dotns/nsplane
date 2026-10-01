// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// temporary, we need to do some verification around these bindings later
#![allow(clippy::missing_safety_doc)]
#![allow(unsafe_code, reason = "JNI ABI boundary")]

/// JNI bindings for BoringTun library
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use base64::Engine as _;
use jni::JNIEnv;
use jni::objects::{JByteBuffer, JClass, JString};
use jni::sys::{jbyteArray, jint, jlong, jshort, jstring};
use parking_lot::Mutex;

use crate::ffi::new_tunnel;
use crate::ffi::wireguard_read;
use crate::ffi::wireguard_result;
use crate::ffi::wireguard_tick;
use crate::ffi::wireguard_write;
use crate::ffi::x25519_key;
use crate::ffi::x25519_public_key;
use crate::ffi::x25519_secret_key;

use crate::noise::Tunn;

/// Logging callback placeholder for Android apps.
pub const extern "C" fn log_print(_log_string: *const c_char) {
    /*
    XXX:
    Define callback function in app.
    */
}

/// Reads a 32-byte key out of a Java byte array.
fn read_key(env: JNIEnv<'_>, array: jbyteArray) -> Option<[u8; 32]> {
    let mut key = [0i8; 32];
    env.get_byte_array_region(array, 0, &mut key).ok()?;
    Some(key.map(i8::cast_unsigned))
}

/// Reads a Java string into an owned C string; Java `null` yields `Ok(None)`.
fn read_c_string(env: JNIEnv<'_>, string: JString<'_>) -> Result<Option<CString>, ()> {
    if string.is_null() {
        return Ok(None);
    }
    let string: String = env.get_string(string).map_err(|_| ())?.into();
    CString::new(string).map(Some).map_err(|_| ())
}

/// Returns a direct buffer as a slice, or `None` if it is not a direct buffer.
fn direct_buffer<'a>(env: &'a JNIEnv<'_>, buffer: JByteBuffer<'_>) -> Option<&'a mut [u8]> {
    env.get_direct_buffer_address(buffer).ok()
}

/// Writes the operation into `op` and converts the size for Java.
fn finish(output: &wireguard_result, op: &mut [u8]) -> jint {
    if let Some(first) = op.first_mut() {
        *first = output.op as u8;
    }
    jint::try_from(output.size).unwrap_or(jint::MAX)
}

/// Generates new x25519 secret key and converts into java byte array.
#[unsafe(export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_x25519_1secret_1key")]
pub extern "C" fn generate_secret_key(env: JNIEnv<'_>, _class: JClass<'_>) -> jbyteArray {
    env.byte_array_from_slice(&x25519_secret_key().key)
        .unwrap_or(ptr::null_mut())
}

/// Computes public x25519 key from secret key and converts into java byte array.
#[unsafe(export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_x25519_1public_1key")]
pub extern "C" fn generate_public_key1(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    arg_secret_key: jbyteArray,
) -> jbyteArray {
    let Some(key) = read_key(env, arg_secret_key) else {
        return ptr::null_mut();
    };

    env.byte_array_from_slice(&x25519_public_key(x25519_key { key }).key)
        .unwrap_or(ptr::null_mut())
}

/// Converts x25519 key to hex string.
#[unsafe(export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_x25519_1key_1to_1hex")]
pub extern "C" fn convert_x25519_key_to_hex(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    arg_key: jbyteArray,
) -> jstring {
    let Some(key) = read_key(env, arg_key) else {
        return ptr::null_mut();
    };

    env.new_string(hex::encode(key))
        .map_or(ptr::null_mut(), |s| s.into_inner())
}

/// Converts x25519 key to base64 string.
#[unsafe(export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_x25519_1key_1to_1base64")]
pub extern "C" fn convert_x25519_key_to_base64(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    arg_key: jbyteArray,
) -> jstring {
    let Some(key) = read_key(env, arg_key) else {
        return ptr::null_mut();
    };

    env.new_string(base64::engine::general_purpose::STANDARD.encode(key))
        .map_or(ptr::null_mut(), |s| s.into_inner())
}

/// Creates new tunnel
#[unsafe(export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_new_1tunnel")]
pub extern "C" fn create_new_tunnel(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    arg_secret_key: JString<'_>,
    arg_public_key: JString<'_>,
    arg_preshared_key: JString<'_>,
    keep_alive: jshort,
    index: jint,
) -> jlong {
    let (Ok(Some(secret_key)), Ok(Some(public_key)), Ok(preshared_key)) = (
        read_c_string(env, arg_secret_key),
        read_c_string(env, arg_public_key),
        read_c_string(env, arg_preshared_key),
    ) else {
        return 0;
    };

    // SAFETY: all pointers are valid NUL-terminated strings (or NULL for the optional
    // preshared key) that outlive the call.
    let tunnel = unsafe {
        new_tunnel(
            secret_key.as_ptr(),
            public_key.as_ptr(),
            preshared_key.as_ref().map_or(ptr::null(), |k| k.as_ptr()),
            keep_alive.cast_unsigned(),
            index.cast_unsigned(),
        )
    };

    tunnel as jlong
}

/// Encrypts raw IP packets into WG formatted packets.
#[unsafe(export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_wireguard_1write")]
pub extern "C" fn encrypt_raw_packet(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    tunnel: jlong,
    src: jbyteArray,
    src_size: jint,
    dst: JByteBuffer<'_>,
    dst_size: jint,
    op: JByteBuffer<'_>,
) -> jint {
    let (Some(dst), Some(op), Ok(src)) = (
        direct_buffer(&env, dst),
        direct_buffer(&env, op),
        env.convert_byte_array(src),
    ) else {
        return 0;
    };
    let src_size = src.len().min(usize::try_from(src_size).unwrap_or(0));
    let dst_size = dst.len().min(usize::try_from(dst_size).unwrap_or(0));

    // SAFETY: `tunnel` was returned by `new_tunnel`; `src` and `dst` are valid for the
    // clamped sizes.
    let output = unsafe {
        wireguard_write(
            tunnel as *const Mutex<Tunn>,
            src.as_ptr(),
            u32::try_from(src_size).unwrap_or(0),
            dst.as_mut_ptr(),
            u32::try_from(dst_size).unwrap_or(0),
        )
    };
    finish(&output, op)
}

/// Decrypts WG formatted packets into raw IP packets.
#[unsafe(export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_wireguard_1read")]
pub extern "C" fn decrypt_to_raw_packet(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    tunnel: jlong,
    src: jbyteArray,
    src_size: jint,
    dst: JByteBuffer<'_>,
    dst_size: jint,
    op: JByteBuffer<'_>,
) -> jint {
    let (Some(dst), Some(op), Ok(src)) = (
        direct_buffer(&env, dst),
        direct_buffer(&env, op),
        env.convert_byte_array(src),
    ) else {
        return 0;
    };
    let src_size = src.len().min(usize::try_from(src_size).unwrap_or(0));
    let dst_size = dst.len().min(usize::try_from(dst_size).unwrap_or(0));

    // SAFETY: `tunnel` was returned by `new_tunnel`; `src` and `dst` are valid for the
    // clamped sizes.
    let output = unsafe {
        wireguard_read(
            tunnel as *const Mutex<Tunn>,
            src.as_ptr(),
            u32::try_from(src_size).unwrap_or(0),
            dst.as_mut_ptr(),
            u32::try_from(dst_size).unwrap_or(0),
        )
    };
    finish(&output, op)
}

/// Periodic function that writes WG formatted packets into destination buffer
#[unsafe(export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_wireguard_1tick")]
pub extern "C" fn run_periodic_task(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    tunnel: jlong,
    dst: JByteBuffer<'_>,
    dst_size: jint,
    op: JByteBuffer<'_>,
) -> jint {
    let (Some(dst), Some(op)) = (direct_buffer(&env, dst), direct_buffer(&env, op)) else {
        return 0;
    };
    let dst_size = dst.len().min(usize::try_from(dst_size).unwrap_or(0));

    // SAFETY: `tunnel` was returned by `new_tunnel`; `dst` is valid for the clamped size.
    let output = unsafe {
        wireguard_tick(
            tunnel as *const Mutex<Tunn>,
            dst.as_mut_ptr(),
            u32::try_from(dst_size).unwrap_or(0),
        )
    };
    finish(&output, op)
}
