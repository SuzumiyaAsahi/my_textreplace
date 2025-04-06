#![no_std]

pub const MAX_POSSIBLE_ADDRS: u32 = 300;
pub const FILENAME_LEN_MAX: usize = 50;
pub const TEXT_LEN_MAX: usize = 20;
pub const LOCAL_BUFF_SIZE: usize = 64;
pub const PROG_0: u32 = 0;
pub const PROG_1: u32 = 0;

// These store the name of the file to replace text in
#[no_mangle]
pub static mut filename_len: u32 = 0;
#[no_mangle]
pub static mut filename: [u8; FILENAME_LEN_MAX] = [0; FILENAME_LEN_MAX];

// These store the text to find and replace in the file
#[no_mangle]
pub static mut text_len: u32 = 0;
#[no_mangle]
pub static mut text_find: [u8; TEXT_LEN_MAX] = [0; TEXT_LEN_MAX];
#[no_mangle]
pub static mut text_replace: [u8; TEXT_LEN_MAX] = [0; TEXT_LEN_MAX];
