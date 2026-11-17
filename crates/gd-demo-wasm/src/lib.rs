//! The browser entry point (WebAssembly, no JavaScript glue needed).
//!
//! `demo_run()` runs the demo scenes and returns a pointer to the events as
//! UTF-8 JSON; `demo_len()` gives its length. The page reads the bytes straight
//! out of the module's memory. An export needs `#[unsafe(no_mangle)]`, so each
//! of the two functions carries its own `#[allow(unsafe_code)]`; there are no
//! `unsafe` blocks.

use std::sync::Mutex;

static OUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

fn out() -> std::sync::MutexGuard<'static, Vec<u8>> {
    OUT.lock().unwrap_or_else(|e| e.into_inner())
}

/// Runs the demo and returns a pointer to its JSON events.
///
/// The pointer is valid only until the next call to `demo_run`, which replaces the bytes.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn demo_run() -> *const u8 {
    let json = gd_demo::to_json(&gd_demo::run()).into_bytes();
    let mut o = out();
    *o = json;
    o.as_ptr()
}

/// Length in bytes of the JSON from the last `demo_run()`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn demo_len() -> usize {
    out().len()
}
