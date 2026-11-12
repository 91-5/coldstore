//! Raw Win32 calls behind NTFS transparent compression (card D3).
//!
//! Three calls do all the work — no external `compact.exe` (the card rules
//! that out: an external process is a dependency we cannot guarantee, and
//! its console output is encoding-hostile):
//!
//! - `FSCTL_SET_COMPRESSION` via `DeviceIoControl` with
//!   `COMPRESSION_FORMAT_DEFAULT` to **enable** and `COMPRESSION_FORMAT_NONE`
//!   to **undo** — this is exactly what `compact.exe /C` and `/U` do
//!   internally, and it is fully reversible;
//! - `GetFileAttributesW` to read `FILE_ATTRIBUTE_COMPRESSED` (skip files
//!   that are already compressed — the card's "跳过已压缩的文件");
//! - `GetCompressedFileSizeW` to measure the **real on-disk size**, so the
//!   reported compression ratio is measured, never estimated.
//!
//! Every function is a thin, audited wrapper: open → call → close, with the
//! handle closed on every path.

use std::io;
use std::path::Path;

#[cfg(windows)]
mod windows_impl {
    use std::io;
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetCompressedFileSizeW, GetFileAttributesW, COMPRESSION_FORMAT_DEFAULT,
        COMPRESSION_FORMAT_NONE, FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_NORMAL,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_COMPRESSION;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    /// Open a file for compression control.
    ///
    /// Access rights are tried from most to least capable, because a
    /// read-only file legitimately accepts `FILE_WRITE_ATTRIBUTES` but not
    /// `FILE_WRITE_DATA`; the compression request itself needs write access
    /// to the *attributes* / data stream.
    fn open_for_control(path: &Path) -> io::Result<windows_sys::Win32::Foundation::HANDLE> {
        let name = wide(path);
        let access_candidates: [u32; 3] = [
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
            FILE_WRITE_ATTRIBUTES,
        ];
        let mut last_err: Option<io::Error> = None;
        for access in access_candidates {
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                    std::ptr::null_mut(),
                )
            };
            if handle != INVALID_HANDLE_VALUE {
                return Ok(handle);
            }
            last_err = Some(io::Error::last_os_error());
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("CreateFileW 失败且无错误码")))
    }

    /// Enable or disable NTFS compression on a single file.
    pub fn set_compression(path: &Path, enable: bool) -> io::Result<()> {
        let handle = open_for_control(path)?;
        let format: u16 = if enable {
            COMPRESSION_FORMAT_DEFAULT
        } else {
            COMPRESSION_FORMAT_NONE
        };
        let mut bytes_returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_SET_COMPRESSION,
                &format as *const u16 as *const std::ffi::c_void,
                std::mem::size_of::<u16>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };
        let err = if ok == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        unsafe {
            CloseHandle(handle);
        }
        match err {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    /// `FILE_ATTRIBUTE_COMPRESSED` — is this file already compressed?
    pub fn is_compressed(path: &Path) -> io::Result<bool> {
        let name = wide(path);
        let attrs = unsafe { GetFileAttributesW(name.as_ptr()) };
        if attrs == windows_sys::Win32::Storage::FileSystem::INVALID_FILE_ATTRIBUTES {
            return Err(io::Error::last_os_error());
        }
        Ok(attrs & FILE_ATTRIBUTE_COMPRESSED != 0)
    }

    /// Real on-disk size (compressed size when the file is compressed, the
    /// logical size otherwise) — this is what the compression ratio is
    /// computed from.
    pub fn compressed_size(path: &Path) -> io::Result<u64> {
        let name = wide(path);
        let mut high: u32 = 0;
        let low = unsafe { GetCompressedFileSizeW(name.as_ptr(), &mut high) };
        if low == windows_sys::Win32::Storage::FileSystem::INVALID_FILE_SIZE && high == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(((high as u64) << 32) | low as u64)
    }
}

#[cfg(not(windows))]
mod stub_impl {
    use std::io;
    use std::path::Path;

    pub fn set_compression(_path: &Path, _enable: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NTFS 透明压缩仅支持 Windows",
        ))
    }

    pub fn is_compressed(_path: &Path) -> io::Result<bool> {
        Ok(false)
    }

    pub fn compressed_size(path: &Path) -> io::Result<u64> {
        Ok(std::fs::metadata(path)?.len())
    }
}

#[cfg(not(windows))]
use stub_impl as imp;
#[cfg(windows)]
use windows_impl as imp;

/// Enable or disable NTFS transparent compression on one file.
pub fn set_compression(path: &Path, enable: bool) -> io::Result<()> {
    imp::set_compression(path, enable)
}

/// Is the file already NTFS-compressed (`FILE_ATTRIBUTE_COMPRESSED`)?
pub fn is_compressed(path: &Path) -> io::Result<bool> {
    imp::is_compressed(path)
}

/// Real on-disk size of the file (compressed size when compressed).
pub fn compressed_size(path: &Path) -> io::Result<u64> {
    imp::compressed_size(path)
}

#[cfg(test)]
mod tests {
    use super::is_compressed;

    #[test]
    fn is_compressed_on_missing_file_is_an_error_not_a_false() {
        // Fail-closed: an unreadable path must not be reported as
        // "not compressed" (that would silently re-compress it).
        let missing = std::path::PathBuf::from("Z:/coldstore-does-not-exist/x.bin");
        assert!(is_compressed(&missing).is_err());
    }
}
