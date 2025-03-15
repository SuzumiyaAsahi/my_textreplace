#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{HashMap, ProgramArray},
    programs::TracePointContext,
};
use aya_log_ebpf::info;
use my_textreplace_common::MAX_POSSIBLE_ADDRS;

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
    info!(&ctx, "tracepoint syscalls called");
    Ok(0)
}

#[tracepoint]
pub fn some_handle_openat_enter(ctx: TracePointContext) -> u32 {
    match handle_openat_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn handle_openat_enter(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint syscalls called");
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
    info!(&ctx, "tracepoint syscalls called");
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
    info!(&ctx, "tracepoint syscalls called");
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
    info!(&ctx, "tracepoint syscalls called");
    Ok(0)
}
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
