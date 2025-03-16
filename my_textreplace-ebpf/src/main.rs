#![no_std]
#![no_main]

use core::ffi::c_void;

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid,
        gen::{bpf_probe_read_user, bpf_probe_read_user_str},
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
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid >> 32;
    // Get filename from arguments
    let mut check_filename: [u8; FILENAME_LEN_MAX] = [0; FILENAME_LEN_MAX];
    let target_filename = unsafe { ctx.read_at::<u64>(24) };
    if target_filename.is_err() {
        return 0;
    }
    let target_filename = target_filename.unwrap() as *const c_void;
    // let needed_len = unsafe { filename_len + 1 } as usize;
    if unsafe { filename_len } > FILENAME_LEN_MAX as u32 {
        return 0;
    }
    let ret = unsafe {
        bpf_probe_read_user_str(
            check_filename.as_mut_ptr() as *mut c_void,
            filename_len + 1,
            target_filename,
        )
    };
    if ret < 0 {
        return 0;
    }
    // Check filename is our target
    // the filename_len is a "const mut" variable,
    // I change it at loading ebpf program by overwriting .rodata
    unsafe {
        // for i in 0..FILENAME_LEN_MAX as usize {
        //     if filename[i] != check_filename[i] {
        //         return 0;
        //     }
        //     if i >= filename_len as usize {
        //         break;
        //     }
        // }
        for (i, j) in filename.iter().zip(check_filename.iter()) {
            if i != j {
                return 0;
            }
        }
    }
    // Add pid_tgid to map for our sys_exit call
    let zero = 0;
    let _ = map_fds.insert(&pid_tgid, &zero, 0);

    info!(&ctx, "[TEXT_REPLACE] PID {} Filename {}", pid, unsafe {
        core::str::from_utf8_unchecked(&filename)
    });
    0
}

#[tracepoint]
pub fn some_handle_openat_exit(ctx: TracePointContext) -> u32 {
    match handle_openat_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn handle_openat_exit(ctx: TracePointContext) -> Result<u32, u32> {
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
