//! parsers/pe.rs — Deep PE (Portable Executable) binary parser using goblin.

use crate::errors::NexGenError;
use crate::models::{FileMetadata, PeAuthenticodeStatus};
use chrono::{DateTime, Utc};
use md5::Md5;
use sha2::Digest;

pub fn parse_pe(data: &[u8], metadata: &mut FileMetadata) -> Result<(), NexGenError> {
    let pe = match goblin::pe::PE::parse(data) {
        Ok(parsed) => parsed,
        Err(e) => {
            if let Some(errs) = metadata.parse_errors.as_mut() {
                errs.push(format!("PE parse error: {}", e));
            } else {
                metadata.parse_errors = Some(vec![format!("PE parse error: {}", e)]);
            }
            return Ok(());
        }
    };

    metadata.pe_machine_type = Some(pe.header.coff_header.machine);
    metadata.pe_architecture = Some(match pe.header.coff_header.machine {
        0x014c => "x86 (32-bit)".to_string(),
        0x8664 => "x86_64 (64-bit AMD64)".to_string(),
        0xAA64 => "ARM64".to_string(),
        0x01c0 => "ARM".to_string(),
        0x0200 => "IA64".to_string(),
        other => format!("Unknown (0x{:04X})", other),
    });

    let raw_timestamp = pe.header.coff_header.time_date_stamp;
    metadata.pe_compile_timestamp_raw = Some(raw_timestamp);
    if let Some(dt) = DateTime::<Utc>::from_timestamp(raw_timestamp as i64, 0) {
        metadata.pe_compile_timestamp = Some(dt.to_rfc3339());
    }

    metadata.pe_section_count = Some(pe.sections.len() as u16);
    metadata.pe_is_dll = Some((pe.header.coff_header.characteristics & 0x2000) != 0);
    metadata.pe_entry_point = Some(pe.entry as u64);

    if let Some(opt) = pe.header.optional_header {
        let (std, win) = (opt.standard_fields, opt.windows_fields);
        metadata.pe_image_base = Some(win.image_base);
        metadata.pe_checksum = Some(win.check_sum);
        metadata.pe_linker_version = Some(format!("{}.{}", std.major_linker_version, std.minor_linker_version));
        metadata.pe_os_version = Some(format!("{}.{}", win.major_operating_system_version, win.minor_operating_system_version));

        metadata.pe_subsystem = Some(match win.subsystem {
            1 => "Native".to_string(),
            2 => "Windows GUI".to_string(),
            3 => "Windows CUI (Console)".to_string(),
            7 => "POSIX CUI".to_string(),
            9 => "Windows CE GUI".to_string(),
            10 => "EFI Application".to_string(),
            11 => "EFI Boot Service Driver".to_string(),
            12 => "EFI Runtime Driver".to_string(),
            13 => "EFI ROM".to_string(),
            14 => "XBOX".to_string(),
            other => format!("Other ({})", other),
        });
    }

    metadata.pe_import_count = Some(pe.imports.len());
    metadata.pe_export_count = Some(pe.exports.len());

    // Imphash calculation: sorted lowercased lib.func MD5
    let mut import_entries = Vec::new();
    for imp in &pe.imports {
        let dll = imp.dll.to_ascii_lowercase();
        let name = imp.name.to_ascii_lowercase();
        import_entries.push(format!("{}.{}", dll, name));
    }
    if !import_entries.is_empty() {
        import_entries.sort();
        let joined = import_entries.join(",");
        let mut hasher = Md5::new();
        hasher.update(joined.as_bytes());
        metadata.pe_imphash = Some(format!("{:x}", hasher.finalize()));
    }

    // Section maximum entropy calculation
    let mut max_entropy: f64 = 0.0;
    for sec in &pe.sections {
        let start = sec.pointer_to_raw_data as usize;
        let size = sec.size_of_raw_data as usize;
        if start < data.len() && size > 0 {
            let end = (start + size).min(data.len());
            let sec_data = &data[start..end];
            let entropy = calculate_section_entropy(sec_data);
            if entropy > max_entropy {
                max_entropy = entropy;
            }
        }
    }
    metadata.pe_section_max_entropy = Some(max_entropy);

    if pe.certificates.is_empty() {
        metadata.pe_authenticode_status = Some(PeAuthenticodeStatus::Unsigned);
    } else {
        metadata.pe_authenticode_status = Some(PeAuthenticodeStatus::Valid);
    }

    Ok(())
}

fn calculate_section_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}
