//! Filesystem identity helpers: the (volume, file-index, link-count)
//! triple that identifies *stored data* regardless of path.
//!
//! Needed by the dedupe planner to avoid the pnpm trap (AV-N1): files
//! already sharing one inode (hardlinked stores) must be reported as
//! "already hardlinked, 0 bytes reclaimable", never as fake savings.
//! std's `MetadataExt::file_index`/`number_of_links` are still
//! unstable (`windows_by_handle`), so this module calls
//! `GetFileInformationByHandle` via `windows-sys` directly.

use std::io;
use std::path::Path;

/// OS-level identity of a file's stored content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub volume_serial: u64,
    pub file_index: u64,
    pub link_count: u64,
}

#[cfg(windows)]
pub fn file_identity(path: &Path) -> io::Result<FileIdentity> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            0, // query attributes only — no access rights needed
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let mut info: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        let ok = GetFileInformationByHandle(handle, &mut info);
        CloseHandle(handle);
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(FileIdentity {
            volume_serial: info.dwVolumeSerialNumber as u64,
            file_index: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
            link_count: info.nNumberOfLinks as u64,
        })
    }
}

#[cfg(not(windows))]
pub fn file_identity(path: &Path) -> io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    let m = std::fs::metadata(path)?;
    Ok(FileIdentity {
        volume_serial: m.dev(),
        file_index: m.ino() as u64,
        link_count: m.nlink() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::file_identity;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn hardlinked_paths_share_identity_and_link_count() {
        let dir = std::env::temp_dir().join(format!(
            "coldstore-fsinfo-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let a: PathBuf = dir.join("a.bin");
        let b: PathBuf = dir.join("b.bin");
        fs::write(&a, vec![42u8; 1000]).unwrap();
        fs::hard_link(&a, &b).unwrap();

        let ia = file_identity(&a).unwrap();
        let ib = file_identity(&b).unwrap();
        assert_eq!(ia, ib, "hardlinks share (volume, index)");
        assert_eq!(ia.link_count, 2, "link count visible via handle info");

        let c: PathBuf = dir.join("c.bin");
        fs::write(&c, vec![42u8; 1000]).unwrap();
        let ic = file_identity(&c).unwrap();
        assert_ne!(ia, ic, "independent copies differ");
        assert_eq!(ic.link_count, 1);

        fs::remove_dir_all(&dir).ok();
    }
}
