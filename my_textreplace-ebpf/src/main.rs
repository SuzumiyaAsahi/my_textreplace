#![no_std]
#![no_main]

use core::ffi::c_void;

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid,
        gen::{bpf_probe_read, bpf_probe_read_user},
    },
    macros::{map, tracepoint},
    maps::{HashMap, ProgramArray},
    programs::TracePointContext,
};
use aya_log_ebpf::info;
use my_textreplace_common::*;

#[map]
// Map to hold the File Descriptors from 'openat' calls
static map_fds: HashMap<u64, u32> = HashMap::<u64, u32>::with_max_entries(8192, 0);

#[map]
// Map to hold the buffer sized from 'read' calls
static map_buff_addrs: HashMap<u64, u64> = HashMap::<u64, u64>::with_max_entries(8192, 0);

#[map]
static map_name_addrs: HashMap<u64, u64> =
    HashMap::<u64, u64>::with_max_entries(MAX_POSSIBLE_ADDRS, 0);

#[map]
static map_to_replace_addrs: HashMap<u64, u64> =
    HashMap::<u64, u64>::with_max_entries(MAX_POSSIBLE_ADDRS, 0);

#[map]
static map_prog_array: ProgramArray = ProgramArray::with_max_entries(5, 0);

#[tracepoint]
pub fn some_handle_close_exit(ctx: TracePointContext) -> u32 {
    match handle_close_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn handle_close_exit(ctx: TracePointContext) -> Result<u32, u32> {
    // Check if we're a process thread of interest
    let pid_tgid = bpf_get_current_pid_tgid();
    let check = unsafe { map_fds.get(&pid_tgid) };
    if check.is_none() {
        return Ok(0);
    }
    // Closing file, delete fd from all maps to clean up
    let _ = map_fds.remove(&pid_tgid);
    let _ = map_buff_addrs.remove(&pid_tgid);
    Ok(0)
}

#[tracepoint]
fn some_handle_openat_enter(ctx: TracePointContext) -> u32 {
    match handle_openat_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn handle_openat_enter(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid >> 32;
    // Get filename from arguments
    let mut check_filename: [u8; FILENAME_LEN_MAX] = [0; FILENAME_LEN_MAX];
    let target_filename = unsafe { ctx.read_at::<u64>(24) };
    if target_filename.is_err() {
        return Ok(0);
    }
    let target_filename = target_filename.unwrap() as *const c_void;
    // let needed_len = unsafe { filename_len + 1 } as usize;
    if unsafe { filename_len } > FILENAME_LEN_MAX as u32 {
        return Ok(0);
    }
    let ret = unsafe {
        bpf_probe_read_user(
            check_filename.as_mut_ptr() as *mut c_void,
            filename_len,
            target_filename,
        )
    };
    if ret < 0 {
        return Ok(0);
    }
    unsafe {
        for (&i, &j) in filename.iter().zip(check_filename.iter()) {
            if i != j {
                return Ok(0);
            }
        }
    }
    let zero = 0;
    let _ = map_fds.insert(&pid_tgid, &zero, 0);

    info!(&ctx, "[TEXT_REPLACE] PID {} Filename {}", pid, unsafe {
        core::str::from_utf8_unchecked(&filename)
    });
    Ok(0)
}

#[tracepoint]
pub fn some_handle_openat_exit(ctx: TracePointContext) -> u32 {
    match handle_openat_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn handle_openat_exit(ctx: TracePointContext) -> Result<u32, u32> {
    // Check this open call is opening our target file
    let pid_tgid = bpf_get_current_pid_tgid();
    let check = unsafe { map_fds.get(&pid_tgid) };
    if check.is_none() {
        return Ok(0);
    }
    let fd = unsafe { ctx.read_at::<u32>(16) };
    if fd.is_err() {
        return Ok(0);
    }
    let fd = fd.unwrap();
    let _ = map_fds.insert(&pid_tgid, &fd, 0);
    Ok(0)
}

#[tracepoint]
pub fn some_handle_read_enter(ctx: TracePointContext) -> u32 {
    match handle_read_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn handle_read_enter(ctx: TracePointContext) -> Result<u32, u32> {
    // Check this open call is opening our target file
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid >> 32;
    let pfd = unsafe { map_fds.get(&pid_tgid) };
    if pfd.is_none() {
        return Ok(0);
    }
    // Check this is the correct file descriptor
    let map_fd = *pfd.unwrap();

    let fd = unsafe { ctx.read_at::<u32>(16) };
    if fd.is_err() {
        return Ok(0);
    }
    let fd = fd.unwrap();
    if map_fd != fd {
        return Ok(0);
    }

    // Store buffer address from arguments in map
    let buff_addr = unsafe { ctx.read_at::<u64>(24) };
    if buff_addr.is_err() {
        return Ok(0);
    }
    let buff_addr = buff_addr.unwrap();
    let _ = map_buff_addrs.insert(&pid_tgid, &buff_addr, 0);

    // log and exit
    info!(
        &ctx,
        "[TEXT_REPLACE] PID {} | fd {} | buff_addr 0x{:x}", pid, fd, buff_addr
    );
    Ok(0)
}

#[tracepoint]
pub fn some_find_possible_addrs(ctx: TracePointContext) -> u32 {
    match find_possible_addrs(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn find_possible_addrs(ctx: TracePointContext) -> Result<u32, u32> {
    // Check this open call is reading our target file
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid >> 32;
    let pbuff_addr = unsafe { map_buff_addrs.get(&pid_tgid) };
    if pbuff_addr.is_none() {
        return Ok(0);
    }
    let mut buff_addr = *pbuff_addr.unwrap();
    let mut name_addr = 0;
    if buff_addr == 0 {
        return Ok(0);
    }
    // This is amount of data returned from the read syscall
    let ret = unsafe { ctx.read_at::<i64>(16) };
    if ret.is_err() {
        return Ok(0);
    }
    let mut read_size = ret.unwrap();
    if read_size <= 0 {
        return Ok(0);
    }
    info!(
        &ctx,
        "[TEXT_REPLACE] PID {} | read_size {} | buff_addr 0x{:x}", pid, read_size, buff_addr
    );
    let mut local_buff: [u8; LOCAL_BUFF_SIZE] = [0; LOCAL_BUFF_SIZE];
    if read_size as usize > LOCAL_BUFF_SIZE + 1 {
        // Need to loop :-(
        read_size += LOCAL_BUFF_SIZE as i64;
    }
    // Read the data returned in chunks, and note every instance
    // of the first character of our 'to find' text.
    // This is all very convoluted, but is required to keep
    // the program complexity and size low enough the pass the verifier checks
    let mut tofind_counter: u64 = 0;

    for _ in 0..LOCAL_BUFF_SIZE {
        // Read in chunks from buffer
        unsafe {
            bpf_probe_read(
                &local_buff as *const _ as *mut c_void,
                read_size as u32,
                buff_addr as *const c_void,
            );
        }
        for j in 0..LOCAL_BUFF_SIZE {
            // Look for the first char of our 'to find' text
            if local_buff[j] == unsafe { text_find[0] } {
                name_addr = buff_addr + (j as u64);
                // This is possibly out text, add the address to the map to be
                // checked by program 'check_possible_addrs'
                let _ = map_name_addrs.insert(&tofind_counter, &name_addr, 0);
                tofind_counter += 1;
            }
        }

        buff_addr += LOCAL_BUFF_SIZE as u64;
    }
    // Tail-call into 'check_possible_addrs' to loop over possible addresses
    info!(
        &ctx,
        "[TEXT_REPLACE] PID {} | tofind_counter {}", pid, tofind_counter
    );

    unsafe {
        if map_prog_array.tail_call(&ctx, PROG_0).is_err() {
            return Ok(0);
        }
    }

    Ok(0)
}

#[tracepoint]
fn check_possible_addresses(ctx: TracePointContext) -> Result<u32, u32> {
    Ok(0)
}

#[tracepoint]
fn overwrite_addresses(ctx: TracePointContext) -> Result<u32, u32> {
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
