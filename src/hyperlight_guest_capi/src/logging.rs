use core::ffi::c_char;

/// # Safety
///
/// Dereferences the given raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hl_log(
    level: log::Level,
    message: *const c_char,
    line: i32,
    file: *const c_char,
) {
    if log::log_enabled!(level) {
        let message = unsafe { core::ffi::CStr::from_ptr(message).to_string_lossy() };
        let file = unsafe { core::ffi::CStr::from_ptr(file).to_string_lossy() };

        log::logger().log(
            &log::RecordBuilder::new()
                .args(format_args!("{}: {}", level, message))
                .level(level)
                .line(Some(line as u32))
                .file(Some(&file))
                .build(),
        );
    }
}
