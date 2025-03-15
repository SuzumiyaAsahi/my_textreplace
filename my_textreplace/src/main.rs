#![feature(ascii_char)]
use anyhow::anyhow;
use aya::programs::TracePoint;
#[rustfmt::skip]
use log::{debug, warn};
use clap::{Arg, ArgMatches, Command};
use my_textreplace_common::*;
use tokio::signal;

struct Env {
    filename: String,
    input: String,
    replace: String,
}

struct Opt {
    filename: [u8; FILENAME_LEN_MAX],
    text_find: [u8; TEXT_LEN_MAX],
    text_replace: [u8; TEXT_LEN_MAX],
}

impl Opt {
    fn new() -> Opt {
        Opt {
            filename: [0; FILENAME_LEN_MAX],
            text_find: [0; TEXT_LEN_MAX],
            text_replace: [0; TEXT_LEN_MAX],
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches: ArgMatches = Command::new("textreplace")
        .version("1.0")
        .author("Your Name <path@tofile.dev>")
        .about("Text Replace\n\nReplaces text in a file.")
        .long_about(
            "Text Replace\n\nReplaces text in a file.\n\
            To pass in newlines use \\%'\\n' e.g.:\n    \
            ./textreplace -f /proc/modules -i ppdev -r $'aaaa\\n'\n\n\
            USAGE: ./textreplace -f filename -i input -r output [-t 1111]",
        ).after_help( "EXAMPLES:\n\
            Hide kernel module:\n  \
            ./textreplace -f /proc/modules -i 'joydev' -r 'cryptd'\n\
            Fake Ethernet adapter (used in sandbox detection):\n  \
            ./textreplace -f /sys/class/net/eth0/address -i '00:15:5d:01:ca:05' -r '00:00:00:00:00:00'",)
        .arg(
            Arg::new("filename")
                .short('f')
                .long("filename")
                .value_name("FILENAME")
                .help("Path to file to replace text in")
                .required(true),
        )
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_name("INPUT")
                .help("Text to be replaced in file, max 20 chars")
                .required(true),
        )
        .arg(
            Arg::new("replace")
                .short('r')
                .long("replace")
                .value_name("REPLACE")
                .help("Text to replace with in file, must be same size as -i")
                .required(true),
        )
        .get_matches();

    let env = Env {
        filename: matches
            .get_one::<String>("filename")
            .expect("filename should be a string")
            .to_string(),
        input: matches
            .get_one::<String>("input")
            .expect("input should be a string")
            .to_string(),
        replace: matches
            .get_one::<String>("replace")
            .expect("replace should be a string")
            .to_string(),
    };

    if env.input.len() > TEXT_LEN_MAX || env.replace.len() > TEXT_LEN_MAX {
        return Err(anyhow!(format!(
            "Input or replace text exceeds maximum length of {} characters.",
            TEXT_LEN_MAX
        )));
    }

    if env.input.len() != env.replace.len() {
        return Err(anyhow!(
            "Input and replace text must be of the same length."
        ));
    }

    let mut opt = Opt::new();
    opt.filename[..env.filename.len()].copy_from_slice(env.filename.as_bytes());
    opt.text_find[..env.input.len()].copy_from_slice(env.input.as_bytes());
    opt.text_replace[..env.replace.len()].copy_from_slice(env.replace.as_bytes());

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::EbpfLoader::new()
        .set_global("filename_len", &(env.filename.len() as u32 + 1), true)
        .set_global("filename", &opt.filename, true)
        .set_global("text_len", &(env.input.len() as u32 + 1), true)
        .set_global("text_find", &opt.text_find, true)
        .set_global("text_replace", &opt.text_replace, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/my_textreplace"
        )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program_1: &mut TracePoint = ebpf
        .program_mut("some_handle_close_exit")
        .unwrap()
        .try_into()?;
    program_1.load()?;
    program_1.attach("syscalls", "sys_exit_close")?;

    let program_2: &mut TracePoint = ebpf
        .program_mut("some_handle_openat_enter")
        .unwrap()
        .try_into()?;
    program_2.load()?;
    program_2.attach("syscalls", "sys_enter_openat")?;

    let program_3: &mut TracePoint = ebpf
        .program_mut("some_handle_openat_exit")
        .unwrap()
        .try_into()?;
    program_3.load()?;
    program_3.attach("syscalls", "sys_exit_openat")?;

    let program_4: &mut TracePoint = ebpf
        .program_mut("some_handle_read_enter")
        .unwrap()
        .try_into()?;
    program_4.load()?;
    program_4.attach("syscalls", "sys_enter_read")?;

    let program_5: &mut TracePoint = ebpf
        .program_mut("some_find_possible_addrs")
        .unwrap()
        .try_into()?;
    program_5.load()?;
    program_5.attach("syscalls", "sys_exit_read")?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
