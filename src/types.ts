export type TimestompSuspect = "Confirmed" | "Possible" | "Clean";
export type PdfSignatureStatus = "Valid" | "Invalid" | "Expired" | "Unsigned" | "Unknown";
export type PeAuthenticodeStatus = "Valid" | "InvalidSignature" | "Unsigned" | "Untrusted";

export interface MacbTimestamps {
  created?: string | null;
  accessed?: string | null;
  modified?: string | null;
  changed?: string | null;
}

export interface FileMetadata {
  id: number;
  file_name?: string | null;
  file_extension?: string | null;
  file_path?: string | null;
  parent_directory?: string | null;
  size_bytes?: number | null;
  size_human?: string | null;
  file_attributes_raw?: number | null;
  is_readonly?: boolean | null;
  is_hidden?: boolean | null;
  is_system?: boolean | null;
  is_archive?: boolean | null;
  is_temporary?: boolean | null;
  is_compressed?: boolean | null;
  is_encrypted_flag?: boolean | null;

  macb?: MacbTimestamps | null;
  timestomp_suspect?: TimestompSuspect | null;
  inode_number?: number | null;
  link_count?: number | null;
  ads_zone_id?: number | null;
  ads_host_url?: string | null;
  ads_referrer_url?: string | null;
  ads_names?: string[] | null;
  mft_record_number?: number | null;
  usn_journal_id?: number | null;
  volume_serial?: number | null;
  reparse_tag?: number | null;

  hash_md5?: string | null;
  hash_sha1?: string | null;
  hash_sha256?: string | null;
  hash_sha512?: string | null;
  hash_crc32?: string | null;
  hash_xxhash3?: string | null;
  hash_blake3?: string | null;

  shannon_entropy?: number | null;
  entropy_classification?: string | null;
  magic_bytes_hex?: string | null;
  magic_mime_type?: string | null;
  magic_description?: string | null;
  is_packed_or_encrypted?: boolean | null;

  exif_make?: string | null;
  exif_model?: string | null;
  exif_serial_number?: string | null;
  exif_lens_model?: string | null;
  exif_focal_length?: number | null;
  exif_iso?: number | null;
  gps_latitude?: number | null;
  gps_longitude?: number | null;
  gps_altitude?: number | null;

  pe_architecture?: string | null;
  pe_compile_timestamp?: string | null;
  pe_section_count?: number | null;
  pe_import_count?: number | null;
  pe_authenticode_status?: PeAuthenticodeStatus | null;
  pe_section_max_entropy?: number | null;

  pdf_producer?: string | null;
  pdf_creator_app?: string | null;
  pdf_version?: string | null;
  pdf_page_count?: number | null;
  pdf_is_encrypted?: boolean | null;
  pdf_has_forms?: boolean | null;
  pdf_has_embedded_files?: boolean | null;
  pdf_signature_status?: PdfSignatureStatus | null;

  file_type_category?: string | null;
  scan_timestamp_utc?: string | null;
}

export interface ScanConfig {
  root_path: string;
  recursive: boolean;
  include_hidden: boolean;
  selected_fields: string[];
  filter_extensions?: string[] | null;
  max_file_size_bytes?: number | null;
}

export interface ScanProgress {
  files_scanned: number;
  files_total: number;
  current_file: string;
  errors: number;
  elapsed_ms: number;
}

export interface FieldDefinition {
  key: keyof FileMetadata;
  label: string;
  category: string;
  description: string;
}

export const FIELD_DEFINITIONS: FieldDefinition[] = [
  // File System
  { key: "file_name", label: "File Name", category: "File System", description: "Base file name with extension" },
  { key: "file_extension", label: "Extension", category: "File System", description: "Lowercased file extension" },
  { key: "file_path", label: "Full Path", category: "File System", description: "Absolute path on disk" },
  { key: "parent_directory", label: "Parent Directory", category: "File System", description: "Containing directory" },
  { key: "size_bytes", label: "Size (Bytes)", category: "File System", description: "Exact size in bytes" },
  { key: "size_human", label: "Size (Human)", category: "File System", description: "Formatted size (KB, MB, GB)" },
  { key: "is_readonly", label: "Is Readonly", category: "File System", description: "Read-only file attribute" },
  { key: "is_hidden", label: "Is Hidden", category: "File System", description: "Hidden file attribute" },

  // Hashes
  { key: "hash_blake3", label: "BLAKE3", category: "Hashes", description: "High-speed cryptographic hash" },
  { key: "hash_sha256", label: "SHA-256", category: "Hashes", description: "Standard NIST cryptographic hash" },
  { key: "hash_md5", label: "MD5", category: "Hashes", description: "Legacy legacy checksum" },
  { key: "hash_sha1", label: "SHA-1", category: "Hashes", description: "Legacy 160-bit hash" },
  { key: "hash_crc32", label: "CRC32", category: "Hashes", description: "Fast 32-bit cyclical redundancy" },
  { key: "hash_xxhash3", label: "XXH3", category: "Hashes", description: "Extreme-speed non-cryptographic hash" },

  // Forensics & NTFS
  { key: "timestomp_suspect", label: "Timestomp Suspect", category: "NTFS & Forensics", description: "Divergence between MFT change time and file modification" },
  { key: "inode_number", label: "File Index / Inode", category: "NTFS & Forensics", description: "Unique NTFS 64-bit file ID" },
  { key: "volume_serial", label: "Volume Serial", category: "NTFS & Forensics", description: "Drive volume serial number" },
  { key: "ads_zone_id", label: "Zone Identifier", category: "NTFS & Forensics", description: "Internet Security Zone ID (ADS)" },
  { key: "ads_host_url", label: "Host URL", category: "NTFS & Forensics", description: "Download source URL from Zone.Identifier" },

  // Entropy & Magic
  { key: "shannon_entropy", label: "Shannon Entropy", category: "Entropy & Magic", description: "Calculated entropy (0.0 to 8.0)" },
  { key: "entropy_classification", label: "Entropy Class", category: "Entropy & Magic", description: "Text, Compressed, or Packed/Encrypted" },
  { key: "magic_bytes_hex", label: "Magic Bytes", category: "Entropy & Magic", description: "First 16-32 bytes hex dump" },

  // EXIF & GPS
  { key: "exif_make", label: "Camera Make", category: "EXIF & GPS", description: "Manufacturer" },
  { key: "exif_model", label: "Camera Model", category: "EXIF & GPS", description: "Camera device model" },
  { key: "exif_lens_model", label: "Lens Model", category: "EXIF & GPS", description: "Lens model description" },
  { key: "gps_latitude", label: "GPS Latitude", category: "EXIF & GPS", description: "Decimal latitude coordinate" },
  { key: "gps_longitude", label: "GPS Longitude", category: "EXIF & GPS", description: "Decimal longitude coordinate" },

  // PE Binaries
  { key: "pe_architecture", label: "PE Architecture", category: "PE Binaries", description: "x86, x64, ARM64" },
  { key: "pe_compile_timestamp", label: "PE Compile Time", category: "PE Binaries", description: "COFF header compile date" },
  { key: "pe_section_count", label: "PE Section Count", category: "PE Binaries", description: "Total sections in PE" },
  { key: "pe_import_count", label: "PE Import Count", category: "PE Binaries", description: "Total imported APIs" },
  { key: "pe_authenticode_status", label: "Authenticode Status", category: "PE Binaries", description: "Digital signature state" },

  // PDF
  { key: "pdf_producer", label: "PDF Producer", category: "PDF Documents", description: "Software used to produce PDF" },
  { key: "pdf_creator_app", label: "PDF Creator", category: "PDF Documents", description: "Authoring application" },
  { key: "pdf_page_count", label: "Page Count", category: "PDF Documents", description: "Total rendered pages" },
  { key: "pdf_has_forms", label: "Has Forms", category: "PDF Documents", description: "Interactive AcroForms present" },
  { key: "pdf_has_embedded_files", label: "Has Embedded Files", category: "PDF Documents", description: "Hidden embedded files/attachments" },
];
