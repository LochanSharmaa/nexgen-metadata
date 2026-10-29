// forensics.rs — NexGen Metadata Windows NTFS low-level metadata extractor
//
// This module exposes two public entry points:
//
//   * `get_ntfs_metadata` – extracts MACB timestamps, inode number, volume
//     serial number, link count, and a basic timestomp heuristic by calling
//     the Win32 file-handle APIs directly.  This gives us data that is
//     completely invisible to `std::fs::metadata()`, which only surfaces the
//     high-level `WIN32_FILE_ATTRIBUTE_DATA` view.
//
//   * `get_ads_info` – reads the Zone.Identifier Alternate Data Stream
//     written by the Windows Mark-of-the-Web mechanism, parses its key=value
//     payload, and enumerates every ADS attached to the file via the
//     `FindFirstStreamW` / `FindNextStreamW` API pair.
//
// LIMITATION (timestomp detection)
// ─────────────────────────────────
// A definitive timestomp determination requires comparing the $STD_INFO MFT
// attribute (which the APIs below expose) against the $FILE_NAME MFT
// attribute (which is only updated by the NTFS driver on rename/move
// operations and cannot be read through a file handle).  Accessing $FILE_NAME
// requires either raw volume I/O (opening "\\.\C:" as a device, parsing the
// MFT directly) or a kernel-mode driver.  The heuristic implemented here is
// therefore only a first-level indicator: if `ChangeTime < LastWriteTime` by
// more than one second it strongly suggests the $STD_INFO write timestamp was
// retroactively altered (a common anti-forensics technique).  A full
// comparison must be performed with a dedicated MFT parser.

#![cfg(target_os = "windows")]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use chrono::{DateTime, TimeZone, Utc};
use tracing::{debug, warn};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FIND_STREAM_DATA,
    FindClose, FindFirstStreamW, FindNextStreamW, GetFileInformationByHandle,
    GetFileInformationByHandleEx, FileBasicInfo, OPEN_EXISTING,
    CreateFileW,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

use crate::errors::NexGenError;

// Windows generic access rights (not re-exported by windows-sys as const in
// the Storage::FileSystem feature set, so we define them locally).
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;

// ─────────────────────────────────────────────────────────────────────────────
// Public data structures
// ─────────────────────────────────────────────────────────────────────────────

/// NTFS low-level metadata for a single file-system object.
///
/// All four MACB timestamps are stored as ISO-8601 UTC strings so they can be
/// serialised directly into the SQLite database or a JSON export without any
/// additional conversion.  `None` means the value could not be retrieved (e.g.
/// the caller lacked `SeBackupPrivilege`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NtfsMetadata {
    /// $STD_INFO CreationTime — "Born" timestamp.
    pub macb_created: Option<String>,
    /// $STD_INFO LastAccessTime — last time any process opened the file.
    pub macb_accessed: Option<String>,
    /// $STD_INFO LastWriteTime — last time the file data was modified.
    pub macb_modified: Option<String>,
    /// $STD_INFO ChangeTime — last time any metadata attribute was changed.
    pub macb_changed: Option<String>,
    /// 64-bit inode number derived from `nFileIndexHigh:nFileIndexLow`.
    pub inode_number: Option<u64>,
    /// NTFS volume serial number.
    pub volume_serial: Option<u64>,
    /// Hard-link count for this file-system object.
    pub link_count: Option<u32>,
    /// `true` when the heuristic detects a likely timestamp manipulation.
    /// See the module-level comment for the scope and limitations of this
    /// detection.
    pub timestomp_suspect: bool,
}

/// Information extracted from the Zone.Identifier Alternate Data Stream and
/// from enumerating all ADS streams present on the file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdsInfo {
    /// Internet Explorer / Edge security zone identifier.
    /// Zone 3 = Internet, Zone 4 = Restricted.
    pub zone_id: Option<u32>,
    /// `HostUrl` field from Zone.Identifier — the original download URL.
    pub host_url: Option<String>,
    /// `ReferrerUrl` field from Zone.Identifier — the page that linked to
    /// the download.
    pub referrer_url: Option<String>,
    /// Names of every Alternate Data Stream attached to the file, excluding
    /// the default `::$DATA` stream.  Stream names are returned exactly as
    /// the file system reports them (e.g. `":Zone.Identifier:$DATA"`).
    pub ads_names: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Extract NTFS low-level metadata from `path` using Win32 file-handle APIs.
///
/// # Errors
///
/// Returns `NexGenError::Forensic` when the file cannot be opened or when a
/// required Win32 API call fails.  The error message always includes the
/// Win32 last-error code so the caller can distinguish access-denied from
/// file-not-found.
pub fn get_ntfs_metadata(path: &Path) -> Result<NtfsMetadata, NexGenError> {
    // ── 1. Open the file ─────────────────────────────────────────────────────
    //
    // We request FILE_READ_ATTRIBUTES (not GENERIC_READ of file data) plus the
    // three FILE_SHARE_* flags so we never block other processes.
    // FILE_FLAG_BACKUP_SEMANTICS is required to open directories; it is
    // harmless on regular files and is also needed to retrieve `ChangeTime`
    // on some Windows versions.

    let wide_path = to_wide_null(path.as_os_str());

    // SAFETY: all arguments are valid Win32 constants; the path buffer is
    // NUL-terminated and lives for the duration of the call.
    let handle: HANDLE = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),           // default security attributes
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut() as HANDLE,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        let err_code = unsafe { GetLastError() };
        return Err(NexGenError::Forensic(format!(
            "CreateFileW failed for '{}': Win32 error 0x{:08X}",
            path.display(),
            err_code
        )));
    }

    // Ensure the handle is closed on every return path.
    let _guard = HandleGuard(handle);

    // ── 2. FILE_BASIC_INFO — four MACB timestamps ────────────────────────────
    //
    // `GetFileInformationByHandleEx` with `FileBasicInfo` fills a
    // `FILE_BASIC_INFO` structure.  The four time fields are i64 values
    // in 100-nanosecond intervals since 1601-01-01T00:00:00Z.

    let mut basic_info: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };

    // SAFETY: `handle` is valid; `basic_info` is zeroed memory of the correct
    // size; `FileBasicInfo` selects a compatible structure layout.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            &mut basic_info as *mut FILE_BASIC_INFO as *mut std::ffi::c_void,
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    };

    if ok == 0 {
        let err_code = unsafe { GetLastError() };
        return Err(NexGenError::Forensic(format!(
            "GetFileInformationByHandleEx(FileBasicInfo) failed for '{}': \
             Win32 error 0x{:08X}",
            path.display(),
            err_code
        )));
    }

    // The four LARGE_INTEGER fields inside FILE_BASIC_INFO are defined as i64
    // in the windows-sys bindings.
    let creation_time: i64 = basic_info.CreationTime;
    let last_access_time: i64 = basic_info.LastAccessTime;
    let last_write_time: i64 = basic_info.LastWriteTime;
    let change_time: i64 = basic_info.ChangeTime;

    let macb_created = filetime_to_iso8601(creation_time);
    let macb_accessed = filetime_to_iso8601(last_access_time);
    let macb_modified = filetime_to_iso8601(last_write_time);
    let macb_changed = filetime_to_iso8601(change_time);

    debug!(
        path = %path.display(),
        created = ?macb_created,
        accessed = ?macb_accessed,
        modified = ?macb_modified,
        changed = ?macb_changed,
        "NTFS MACB timestamps retrieved"
    );

    // ── 3. BY_HANDLE_FILE_INFORMATION — inode, serial, links ─────────────────

    let mut file_info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };

    // SAFETY: `handle` is valid; `file_info` is zeroed memory of the correct
    // size.
    let ok = unsafe { GetFileInformationByHandle(handle, &mut file_info) };

    if ok == 0 {
        let err_code = unsafe { GetLastError() };
        return Err(NexGenError::Forensic(format!(
            "GetFileInformationByHandle failed for '{}': Win32 error 0x{:08X}",
            path.display(),
            err_code
        )));
    }

    // Reconstruct the 64-bit inode from the two 32-bit halves.
    let inode_number: u64 =
        ((file_info.nFileIndexHigh as u64) << 32) | (file_info.nFileIndexLow as u64);

    let volume_serial: u64 = file_info.dwVolumeSerialNumber as u64;
    let link_count: u32 = file_info.nNumberOfLinks;

    // ── 4. Timestomp heuristic ───────────────────────────────────────────────
    //
    // Normal NTFS behaviour: whenever $STD_INFO LastWriteTime is updated by
    // the kernel, ChangeTime is updated to the same instant (or a slightly
    // later one, accounting for the time taken by the write path).  Therefore
    // ChangeTime should always be >= LastWriteTime.
    //
    // If an attacker calls `SetFileTime()` to roll LastWriteTime backwards
    // *after* the write, the kernel sets ChangeTime to the actual wall-clock
    // moment of the SetFileTime call — but LastWriteTime is now set to
    // whatever the attacker chose.  The result: ChangeTime > LastWriteTime.
    //
    // The converse (ChangeTime < LastWriteTime) can occur when a tool modifies
    // ChangeTime directly (possible from kernel mode) or when the file was
    // copied from a source with a different clock.  We flag both divergences
    // greater than 1 second as suspicious.
    //
    // For a definitive verdict the $FILE_NAME attribute (which NTFS updates
    // only on rename/move, not on SetFileTime) must be compared; that requires
    // raw MFT access — see the module-level documentation.

    let timestomp_suspect = {
        let divergence = (change_time - last_write_time).unsigned_abs();
        // 1 second expressed in 100-ns FILETIME units.
        let one_second: u64 = 10_000_000;
        if divergence > one_second {
            warn!(
                path = %path.display(),
                change_time,
                last_write_time,
                divergence_100ns = divergence,
                "Timestomp heuristic triggered: ChangeTime/LastWriteTime \
                 diverge by more than 1 s"
            );
            true
        } else {
            false
        }
    };

    Ok(NtfsMetadata {
        macb_created,
        macb_accessed,
        macb_modified,
        macb_changed,
        inode_number: Some(inode_number),
        volume_serial: Some(volume_serial),
        link_count: Some(link_count),
        timestomp_suspect,
    })
}

/// Read and parse the `Zone.Identifier` ADS and enumerate all ADS streams on
/// `path`.
///
/// # Errors
///
/// Returns `NexGenError::Io` or `NexGenError::Forensic` only for genuine
/// failures (permission denied, path too long, etc.).  A missing
/// `Zone.Identifier` stream is not an error — it simply leaves the
/// `zone_id`, `host_url`, and `referrer_url` fields as `None`.
pub fn get_ads_info(path: &Path) -> Result<AdsInfo, NexGenError> {
    // ── 1. Read Zone.Identifier:$DATA ────────────────────────────────────────
    //
    // The MOTW stream path is constructed by appending ":Zone.Identifier:$DATA"
    // to the file path.  We build it as a wide string so we can pass it
    // directly to CreateFileW without going through the standard library's
    // path handling (which strips ADS suffixes on some configurations).

    let zone_path_str = format!("{}:Zone.Identifier:$DATA", path.display());
    let zone_path_wide = to_wide_null(OsStr::new(&zone_path_str));

    let (zone_id, host_url, referrer_url) = read_zone_identifier(&zone_path_wide);

    // ── 2. Enumerate all ADS streams ─────────────────────────────────────────

    let ads_names = enumerate_ads_streams(path)?;

    Ok(AdsInfo {
        zone_id,
        host_url,
        referrer_url,
        ads_names,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Convert a Windows FILETIME value (i64, 100-nanosecond intervals since
/// 1601-01-01T00:00:00Z) to a UTC ISO-8601 string.
///
/// Returns `None` if the FILETIME value is zero (unset) or negative, or if
/// the resulting timestamp falls outside the range representable by
/// `chrono::DateTime<Utc>`.
///
/// # Formula
///
/// ```text
/// unix_epoch_secs = (filetime - 116_444_736_000_000_000) / 10_000_000
/// sub_second_ns   = ((filetime - 116_444_736_000_000_000) % 10_000_000)
///                   * 100
/// ```
///
/// The constant `116_444_736_000_000_000` is the number of 100-nanosecond
/// intervals between the Windows epoch (1601-01-01) and the Unix epoch
/// (1970-01-01).
pub(crate) fn filetime_to_iso8601(ft: i64) -> Option<String> {
    // A zero FILETIME means "not set" in Windows APIs.
    if ft <= 0 {
        return None;
    }

    /// Windows → Unix epoch offset in 100-ns ticks.
    const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;

    let ticks_since_unix = ft.checked_sub(EPOCH_DIFF_100NS)?;

    // Split into whole seconds and sub-second nanoseconds.
    let secs: i64 = ticks_since_unix / 10_000_000;
    let subsec_100ns: u32 = (ticks_since_unix % 10_000_000).unsigned_abs() as u32;
    let nanos: u32 = subsec_100ns * 100;

    // `DateTime::from_timestamp` is the non-deprecated constructor in
    // chrono ≥ 0.4.31; it returns `Option<DateTime<Utc>>`.
    let dt: DateTime<Utc> = DateTime::from_timestamp(secs, nanos)?;

    Some(dt.format("%Y-%m-%dT%H:%M:%S%.fZ").to_string())
}

/// Attempt to open and parse a Zone.Identifier stream.
///
/// Returns a triple `(zone_id, host_url, referrer_url)`.  Any field that
/// cannot be found in the stream is returned as `None`.  Errors opening or
/// reading the stream are silently swallowed — their absence is normal for
/// locally-created files.
fn read_zone_identifier(
    zone_path_wide: &[u16],
) -> (Option<u32>, Option<String>, Option<String>) {
    // SAFETY: `zone_path_wide` is a valid NUL-terminated wide string.
    let handle: HANDLE = unsafe {
        CreateFileW(
            zone_path_wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            0, // no special flags needed for reading a small ADS
            std::ptr::null_mut() as HANDLE,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        // File has no Zone.Identifier — this is the common case.
        return (None, None, None);
    }

    let _guard = HandleGuard(handle);

    // Read up to 4 KiB of content (Zone.Identifier is always tiny).
    let mut buf = vec![0u8; 4096];
    let mut bytes_read: u32 = 0;

    // SAFETY: `handle` is valid; `buf` is a properly-sized mutable slice;
    // `bytes_read` will receive the number of bytes actually read.
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::ReadFile(
            handle,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut bytes_read,
            std::ptr::null_mut::<OVERLAPPED>(),
        )
    };

    if ok == 0 {
        let code = unsafe { GetLastError() };
        warn!("ReadFile on Zone.Identifier stream failed: Win32 error 0x{:08X}", code);
        return (None, None, None);
    }

    buf.truncate(bytes_read as usize);

    // The Zone.Identifier stream uses Windows-1252 / UTF-8 encoding.
    // We accept both; `from_utf8_lossy` handles either gracefully.
    let content = String::from_utf8_lossy(&buf);

    let mut zone_id: Option<u32> = None;
    let mut host_url: Option<String> = None;
    let mut referrer_url: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("ZoneId=") {
            zone_id = val.trim().parse::<u32>().ok();
        } else if let Some(val) = line.strip_prefix("HostUrl=") {
            host_url = Some(val.trim().to_owned());
        } else if let Some(val) = line.strip_prefix("ReferrerUrl=") {
            referrer_url = Some(val.trim().to_owned());
        }
    }

    (zone_id, host_url, referrer_url)
}

/// Enumerate all Alternate Data Streams attached to `path` using the
/// `FindFirstStreamW` / `FindNextStreamW` API pair.
///
/// The main stream `::$DATA` is excluded from the results.
///
/// # Errors
///
/// Returns `NexGenError::Forensic` only when the underlying API fails for a
/// reason other than "no more data" or "the file has no extra streams".
fn enumerate_ads_streams(path: &Path) -> Result<Vec<String>, NexGenError> {
    // FindStreamInfoStandard = 0; the only value currently defined by Windows.
    const FIND_STREAM_INFO_STANDARD: u32 = 0;

    let mut ads_names: Vec<String> = Vec::new();
    let wide_path = to_wide_null(path.as_os_str());

    let mut stream_data: FIND_STREAM_DATA = unsafe { std::mem::zeroed() };

    // SAFETY: `wide_path` is a valid NUL-terminated wide string;
    // `stream_data` is zeroed memory of the correct layout.
    let find_handle: HANDLE = unsafe {
        FindFirstStreamW(
            wide_path.as_ptr(),
            FIND_STREAM_INFO_STANDARD,
            &mut stream_data as *mut FIND_STREAM_DATA as *mut std::ffi::c_void,
            0, // reserved; must be zero
        )
    };

    // ERROR_HANDLE_EOF (0x26) is returned when the file has no streams at all
    // (extremely rare on NTFS) or the API is unavailable.
    // INVALID_HANDLE_VALUE with ERROR_HANDLE_EOF is the normal "no streams"
    // response on older systems.
    if find_handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        // 0x26 = ERROR_HANDLE_EOF  — no streams found, not a real error.
        if err == 0x26 {
            return Ok(ads_names);
        }
        return Err(NexGenError::Forensic(format!(
            "FindFirstStreamW failed for '{}': Win32 error 0x{:08X}",
            path.display(),
            err
        )));
    }

    // Process the first stream entry.
    collect_stream_name(&stream_data, &mut ads_names);

    // Iterate remaining streams.
    loop {
        let mut next_data: FIND_STREAM_DATA = unsafe { std::mem::zeroed() };

        // SAFETY: `find_handle` is valid; `next_data` is zeroed memory.
        let ok = unsafe {
            FindNextStreamW(
                find_handle,
                &mut next_data as *mut FIND_STREAM_DATA as *mut std::ffi::c_void,
            )
        };

        if ok == 0 {
            let err = unsafe { GetLastError() };
            // ERROR_HANDLE_EOF = 0x26 signals normal end of stream list.
            if err == 0x26 {
                break;
            }
            // Any other error is unexpected.
            // We still close the find handle (below) before returning.
            unsafe { FindClose(find_handle) };
            return Err(NexGenError::Forensic(format!(
                "FindNextStreamW failed for '{}': Win32 error 0x{:08X}",
                path.display(),
                err
            )));
        }

        collect_stream_name(&next_data, &mut ads_names);
    }

    // SAFETY: `find_handle` was opened successfully and must be closed.
    unsafe { FindClose(find_handle) };

    Ok(ads_names)
}

/// Extract the stream name from a `FIND_STREAM_DATA` entry, convert it from
/// UTF-16 to UTF-8, and push it onto `acc` — unless it is the default
/// `::$DATA` stream.
fn collect_stream_name(data: &FIND_STREAM_DATA, acc: &mut Vec<String>) {
    // `cStreamName` is a fixed-size [u16; 296] array (MAX_PATH * 2) with a
    // NUL terminator.
    let nul_pos = data
        .cStreamName
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(data.cStreamName.len());

    let name_slice = &data.cStreamName[..nul_pos];

    // Decode from UTF-16; replace surrogates with U+FFFD.
    let name = String::from_utf16_lossy(name_slice);

    // Skip the main (default) data stream.
    if name == "::$DATA" {
        return;
    }

    acc.push(name);
}

/// Encode an `OsStr` as a NUL-terminated UTF-16 wide string (`Vec<u16>`).
///
/// This is the canonical form expected by all `W`-suffix Win32 APIs.
fn to_wide_null(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0u16)).collect()
}

/// RAII guard that closes a Win32 `HANDLE` when dropped.
///
/// Using an RAII guard guarantees handle closure on every return path,
/// including early returns triggered by `?`.
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
            // SAFETY: the contained handle is valid and not yet closed.
            unsafe { CloseHandle(self.0) };
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::filetime_to_iso8601;

    /// Windows epoch itself must convert to 1601-01-01T00:00:00Z.
    /// `chrono::DateTime::from_timestamp` does support pre-Unix epochs via
    /// negative Unix timestamps.
    #[test]
    fn filetime_zero_returns_none() {
        assert!(filetime_to_iso8601(0).is_none());
    }

    #[test]
    fn filetime_negative_returns_none() {
        assert!(filetime_to_iso8601(-1).is_none());
    }

    /// The Unix epoch (1970-01-01T00:00:00Z) in FILETIME units is exactly
    /// 116_444_736_000_000_000 (100-nanosecond intervals between 1601-01-01
    /// and 1970-01-01).
    #[test]
    fn filetime_unix_epoch() {
        let result = filetime_to_iso8601(116_444_736_000_000_000);
        assert!(result.is_some(), "expected Some, got None");
        let s = result.unwrap();
        assert!(
            s.starts_with("1970-01-01T00:00:00"),
            "unexpected timestamp: {}",
            s
        );
    }

    /// A known FILETIME: 2024-06-15T12:34:56Z.
    /// Python: int((datetime(2024,6,15,12,34,56) - datetime(1601,1,1)).total_seconds() * 10_000_000)
    /// = 133_628_840_960_000_000
    #[test]
    fn filetime_known_date() {
        let ft: i64 = 133_628_840_960_000_000;
        let result = filetime_to_iso8601(ft).unwrap();
        assert!(
            result.starts_with("2024-06-15T12:34:56"),
            "unexpected: {}",
            result
        );
    }
}
