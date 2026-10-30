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

  // ── File System extras ──
  file_size_bytes?: string | null;
  file_size_human?: string | null;
  creation_date?: string | null;
  modification_date?: string | null;
  access_date?: string | null;
  mime_type?: string | null;
  file_permissions?: string | null;
  is_read_only?: string | null;
  is_symlink?: string | null;
  owner_windows?: string | null;

  // ── Hashes & Checksums extras ──
  md5_hash?: string | null;
  sha1_hash?: string | null;
  sha224_hash?: string | null;
  sha256_hash?: string | null;
  sha384_hash?: string | null;
  sha512_hash?: string | null;
  sha3_224_hash?: string | null;
  sha3_256_hash?: string | null;
  sha3_384_hash?: string | null;
  sha3_512_hash?: string | null;
  blake2b_hash?: string | null;
  blake2s_hash?: string | null;
  crc32?: string | null;
  adler32?: string | null;
  xxhash64?: string | null;

  // ── Image / EXIF ──
  image_width?: string | null;
  image_height?: string | null;
  resolution_dpi?: string | null;
  bit_depth?: string | null;
  color_space?: string | null;
  color_profile?: string | null;
  orientation?: string | null;
  compression?: string | null;
  has_alpha_channel?: string | null;
  megapixels?: string | null;
  exif_version?: string | null;
  date_taken_original?: string | null;
  date_digitized?: string | null;
  software?: string | null;
  host_computer?: string | null;
  description_caption?: string | null;
  user_comment?: string | null;
  copyright?: string | null;
  artist_author?: string | null;
  rating?: string | null;

  // ── Camera / Lens ──
  camera_make?: string | null;
  camera_model?: string | null;
  camera_serial?: string | null;
  lens_model?: string | null;
  lens_make?: string | null;
  lens_serial?: string | null;
  lens_focal_length?: string | null;
  lens_max_aperture?: string | null;
  iso?: string | null;
  exposure_time?: string | null;
  f_stop?: string | null;
  exposure_program?: string | null;
  exposure_mode?: string | null;
  exposure_compensation?: string | null;
  metering_mode?: string | null;
  flash?: string | null;
  flash_mode?: string | null;
  white_balance?: string | null;
  focus_mode?: string | null;
  focus_distance?: string | null;
  scene_type?: string | null;
  shutter_count?: string | null;
  digital_zoom_ratio?: string | null;

  // ── GPS / Location extras ──
  gps_altitude_ref?: string | null;
  gps_latitude_ref?: string | null;
  gps_longitude_ref?: string | null;
  gps_speed?: string | null;
  gps_direction?: string | null;
  gps_timestamp?: string | null;
  gps_date?: string | null;
  gps_map_datum?: string | null;
  gps_coordinates_dms?: string | null;

  // ── Video ──
  video_codec?: string | null;
  video_width?: string | null;
  video_height?: string | null;
  video_frame_rate?: string | null;
  video_bitrate?: string | null;
  video_duration?: string | null;
  aspect_ratio?: string | null;
  rotation?: string | null;
  audio_codec_video?: string | null;
  audio_channels_video?: string | null;
  audio_sample_rate_video?: string | null;
  audio_bitrate_video?: string | null;
  total_bitrate?: string | null;
  container_format?: string | null;
  encoder?: string | null;
  video_creation_date?: string | null;
  video_track_count?: string | null;
  subtitle_track_count?: string | null;
  chapter_count?: string | null;

  // ── Audio ──
  audio_title?: string | null;
  audio_artist?: string | null;
  audio_album?: string | null;
  audio_album_artist?: string | null;
  audio_genre?: string | null;
  audio_year?: string | null;
  audio_track_number?: string | null;
  audio_disc_number?: string | null;
  audio_composer?: string | null;
  audio_duration?: string | null;
  audio_codec?: string | null;
  audio_bitrate?: string | null;
  audio_sample_rate?: string | null;
  audio_channels?: string | null;
  audio_bit_depth?: string | null;
  audio_bpm?: string | null;
  audio_comment?: string | null;
  audio_lyrics?: string | null;
  audio_publisher_label?: string | null;
  audio_encoder?: string | null;
  has_album_art?: string | null;
  album_art_size?: string | null;
  audio_replaygain?: string | null;

  // ── Documents ──
  document_title?: string | null;
  document_author?: string | null;
  document_subject?: string | null;
  document_keywords?: string | null;
  document_creator_app?: string | null;
  document_producer?: string | null;
  document_creation_date?: string | null;
  document_modification_date?: string | null;
  document_page_count?: string | null;
  document_word_count?: string | null;
  document_character_count?: string | null;
  document_line_count?: string | null;
  document_paragraph_count?: string | null;
  document_slide_count?: string | null;
  document_sheet_count?: string | null;
  document_revision?: string | null;
  document_last_author?: string | null;
  document_company?: string | null;
  document_manager?: string | null;
  document_category?: string | null;
  document_language?: string | null;
  document_template?: string | null;
  document_comments?: string | null;

  // ── PDF Specific extras ──
  pdf_encrypted?: string | null;
  pdf_has_signatures?: string | null;
  pdf_page_size?: string | null;
  pdf_creator?: string | null;
  pdf_linearized?: string | null;
  pdf_tagged?: string | null;

  // ── Forensics / PE extras ──
  file_entropy?: string | null;
  magic_bytes_header?: string | null;
  pe_compile_date?: string | null;
  pe_signed?: string | null;
  pe_original_filename?: string | null;
  pe_product_name?: string | null;
  pe_product_version?: string | null;
  pe_company_name?: string | null;
  pe_file_version?: string | null;
  pe_description?: string | null;
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
  scanned_files: number;
  total_files: number;
  current_file: string;
  percentage: number;
  status: string;
  errors: number;
  elapsed_ms: number;
  files_scanned?: number;
  files_total?: number;
}

export interface FieldDefinition {
  key: string;
  label: string;
  category: string;
  description: string;
}

export const FIELD_DEFINITIONS: FieldDefinition[] = [
  {
    "key": "file_name",
    "label": "File Name",
    "category": "File System",
    "description": "File Name"
  },
  {
    "key": "file_extension",
    "label": "File Extension",
    "category": "File System",
    "description": "File Extension"
  },
  {
    "key": "file_path",
    "label": "File Path",
    "category": "File System",
    "description": "File Path"
  },
  {
    "key": "parent_directory",
    "label": "Parent Directory",
    "category": "File System",
    "description": "Parent Directory"
  },
  {
    "key": "file_size_bytes",
    "label": "File Size (Bytes)",
    "category": "File System",
    "description": "File Size (Bytes)"
  },
  {
    "key": "file_size_human",
    "label": "File Size (Human)",
    "category": "File System",
    "description": "File Size (Human)"
  },
  {
    "key": "creation_date",
    "label": "Creation Date",
    "category": "File System",
    "description": "Creation Date"
  },
  {
    "key": "modification_date",
    "label": "Modification Date",
    "category": "File System",
    "description": "Modification Date"
  },
  {
    "key": "access_date",
    "label": "Access Date",
    "category": "File System",
    "description": "Access Date"
  },
  {
    "key": "mime_type",
    "label": "MIME Type",
    "category": "File System",
    "description": "MIME Type"
  },
  {
    "key": "file_permissions",
    "label": "File Permissions",
    "category": "File System",
    "description": "File Permissions"
  },
  {
    "key": "is_hidden",
    "label": "Is Hidden",
    "category": "File System",
    "description": "Is Hidden"
  },
  {
    "key": "is_read_only",
    "label": "Is Read-Only",
    "category": "File System",
    "description": "Is Read-Only"
  },
  {
    "key": "is_symlink",
    "label": "Is Symlink",
    "category": "File System",
    "description": "Is Symlink"
  },
  {
    "key": "owner_windows",
    "label": "Owner (Windows)",
    "category": "File System",
    "description": "Owner (Windows)"
  },
  {
    "key": "md5_hash",
    "label": "MD5 Hash",
    "category": "Hashes & Checksums",
    "description": "MD5 Hash"
  },
  {
    "key": "sha1_hash",
    "label": "SHA1 Hash",
    "category": "Hashes & Checksums",
    "description": "SHA1 Hash"
  },
  {
    "key": "sha224_hash",
    "label": "SHA224 Hash",
    "category": "Hashes & Checksums",
    "description": "SHA224 Hash"
  },
  {
    "key": "sha256_hash",
    "label": "SHA256 Hash",
    "category": "Hashes & Checksums",
    "description": "SHA256 Hash"
  },
  {
    "key": "sha384_hash",
    "label": "SHA384 Hash",
    "category": "Hashes & Checksums",
    "description": "SHA384 Hash"
  },
  {
    "key": "sha512_hash",
    "label": "SHA512 Hash",
    "category": "Hashes & Checksums",
    "description": "SHA512 Hash"
  },
  {
    "key": "sha3_224_hash",
    "label": "SHA3-224 Hash",
    "category": "Hashes & Checksums",
    "description": "SHA3-224 Hash"
  },
  {
    "key": "sha3_256_hash",
    "label": "SHA3-256 Hash",
    "category": "Hashes & Checksums",
    "description": "SHA3-256 Hash"
  },
  {
    "key": "sha3_384_hash",
    "label": "SHA3-384 Hash",
    "category": "Hashes & Checksums",
    "description": "SHA3-384 Hash"
  },
  {
    "key": "sha3_512_hash",
    "label": "SHA3-512 Hash",
    "category": "Hashes & Checksums",
    "description": "SHA3-512 Hash"
  },
  {
    "key": "blake2b_hash",
    "label": "BLAKE2b Hash",
    "category": "Hashes & Checksums",
    "description": "BLAKE2b Hash"
  },
  {
    "key": "blake2s_hash",
    "label": "BLAKE2s Hash",
    "category": "Hashes & Checksums",
    "description": "BLAKE2s Hash"
  },
  {
    "key": "crc32",
    "label": "CRC32",
    "category": "Hashes & Checksums",
    "description": "CRC32"
  },
  {
    "key": "adler32",
    "label": "Adler32",
    "category": "Hashes & Checksums",
    "description": "Adler32"
  },
  {
    "key": "xxhash64",
    "label": "xxHash64",
    "category": "Hashes & Checksums",
    "description": "xxHash64"
  },
  {
    "key": "image_width",
    "label": "Image Width",
    "category": "Image / EXIF",
    "description": "Image Width"
  },
  {
    "key": "image_height",
    "label": "Image Height",
    "category": "Image / EXIF",
    "description": "Image Height"
  },
  {
    "key": "resolution_dpi",
    "label": "Resolution (DPI)",
    "category": "Image / EXIF",
    "description": "Resolution (DPI)"
  },
  {
    "key": "bit_depth",
    "label": "Bit Depth",
    "category": "Image / EXIF",
    "description": "Bit Depth"
  },
  {
    "key": "color_space",
    "label": "Color Space",
    "category": "Image / EXIF",
    "description": "Color Space"
  },
  {
    "key": "color_profile",
    "label": "Color Profile",
    "category": "Image / EXIF",
    "description": "Color Profile"
  },
  {
    "key": "orientation",
    "label": "Orientation",
    "category": "Image / EXIF",
    "description": "Orientation"
  },
  {
    "key": "compression",
    "label": "Compression",
    "category": "Image / EXIF",
    "description": "Compression"
  },
  {
    "key": "has_alpha_channel",
    "label": "Has Alpha Channel",
    "category": "Image / EXIF",
    "description": "Has Alpha Channel"
  },
  {
    "key": "megapixels",
    "label": "Megapixels",
    "category": "Image / EXIF",
    "description": "Megapixels"
  },
  {
    "key": "exif_version",
    "label": "EXIF Version",
    "category": "Image / EXIF",
    "description": "EXIF Version"
  },
  {
    "key": "date_taken_original",
    "label": "Date Taken (Original)",
    "category": "Image / EXIF",
    "description": "Date Taken (Original)"
  },
  {
    "key": "date_digitized",
    "label": "Date Digitized",
    "category": "Image / EXIF",
    "description": "Date Digitized"
  },
  {
    "key": "software",
    "label": "Software",
    "category": "Image / EXIF",
    "description": "Software"
  },
  {
    "key": "host_computer",
    "label": "Host Computer",
    "category": "Image / EXIF",
    "description": "Host Computer"
  },
  {
    "key": "description_caption",
    "label": "Description / Caption",
    "category": "Image / EXIF",
    "description": "Description / Caption"
  },
  {
    "key": "user_comment",
    "label": "User Comment",
    "category": "Image / EXIF",
    "description": "User Comment"
  },
  {
    "key": "copyright",
    "label": "Copyright",
    "category": "Image / EXIF",
    "description": "Copyright"
  },
  {
    "key": "artist_author",
    "label": "Artist / Author",
    "category": "Image / EXIF",
    "description": "Artist / Author"
  },
  {
    "key": "rating",
    "label": "Rating",
    "category": "Image / EXIF",
    "description": "Rating"
  },
  {
    "key": "camera_make",
    "label": "Camera Make",
    "category": "Camera / Lens",
    "description": "Camera Make"
  },
  {
    "key": "camera_model",
    "label": "Camera Model",
    "category": "Camera / Lens",
    "description": "Camera Model"
  },
  {
    "key": "camera_serial",
    "label": "Camera Serial",
    "category": "Camera / Lens",
    "description": "Camera Serial"
  },
  {
    "key": "lens_model",
    "label": "Lens Model",
    "category": "Camera / Lens",
    "description": "Lens Model"
  },
  {
    "key": "lens_make",
    "label": "Lens Make",
    "category": "Camera / Lens",
    "description": "Lens Make"
  },
  {
    "key": "lens_serial",
    "label": "Lens Serial",
    "category": "Camera / Lens",
    "description": "Lens Serial"
  },
  {
    "key": "lens_focal_length",
    "label": "Lens Focal Length",
    "category": "Camera / Lens",
    "description": "Lens Focal Length"
  },
  {
    "key": "lens_max_aperture",
    "label": "Lens Max Aperture",
    "category": "Camera / Lens",
    "description": "Lens Max Aperture"
  },
  {
    "key": "iso",
    "label": "ISO",
    "category": "Camera / Lens",
    "description": "ISO"
  },
  {
    "key": "exposure_time",
    "label": "Exposure Time",
    "category": "Camera / Lens",
    "description": "Exposure Time"
  },
  {
    "key": "f_stop",
    "label": "F-Stop",
    "category": "Camera / Lens",
    "description": "F-Stop"
  },
  {
    "key": "exposure_program",
    "label": "Exposure Program",
    "category": "Camera / Lens",
    "description": "Exposure Program"
  },
  {
    "key": "exposure_mode",
    "label": "Exposure Mode",
    "category": "Camera / Lens",
    "description": "Exposure Mode"
  },
  {
    "key": "exposure_compensation",
    "label": "Exposure Compensation",
    "category": "Camera / Lens",
    "description": "Exposure Compensation"
  },
  {
    "key": "metering_mode",
    "label": "Metering Mode",
    "category": "Camera / Lens",
    "description": "Metering Mode"
  },
  {
    "key": "flash",
    "label": "Flash",
    "category": "Camera / Lens",
    "description": "Flash"
  },
  {
    "key": "flash_mode",
    "label": "Flash Mode",
    "category": "Camera / Lens",
    "description": "Flash Mode"
  },
  {
    "key": "white_balance",
    "label": "White Balance",
    "category": "Camera / Lens",
    "description": "White Balance"
  },
  {
    "key": "focus_mode",
    "label": "Focus Mode",
    "category": "Camera / Lens",
    "description": "Focus Mode"
  },
  {
    "key": "focus_distance",
    "label": "Focus Distance",
    "category": "Camera / Lens",
    "description": "Focus Distance"
  },
  {
    "key": "scene_type",
    "label": "Scene Type",
    "category": "Camera / Lens",
    "description": "Scene Type"
  },
  {
    "key": "shutter_count",
    "label": "Shutter Count",
    "category": "Camera / Lens",
    "description": "Shutter Count"
  },
  {
    "key": "digital_zoom_ratio",
    "label": "Digital Zoom Ratio",
    "category": "Camera / Lens",
    "description": "Digital Zoom Ratio"
  },
  {
    "key": "gps_latitude",
    "label": "GPS Latitude",
    "category": "GPS / Location",
    "description": "GPS Latitude"
  },
  {
    "key": "gps_longitude",
    "label": "GPS Longitude",
    "category": "GPS / Location",
    "description": "GPS Longitude"
  },
  {
    "key": "gps_altitude",
    "label": "GPS Altitude",
    "category": "GPS / Location",
    "description": "GPS Altitude"
  },
  {
    "key": "gps_latitude_ref",
    "label": "GPS Latitude Ref",
    "category": "GPS / Location",
    "description": "GPS Latitude Ref"
  },
  {
    "key": "gps_longitude_ref",
    "label": "GPS Longitude Ref",
    "category": "GPS / Location",
    "description": "GPS Longitude Ref"
  },
  {
    "key": "gps_altitude_ref",
    "label": "GPS Altitude Ref",
    "category": "GPS / Location",
    "description": "GPS Altitude Ref"
  },
  {
    "key": "gps_speed",
    "label": "GPS Speed",
    "category": "GPS / Location",
    "description": "GPS Speed"
  },
  {
    "key": "gps_direction",
    "label": "GPS Direction",
    "category": "GPS / Location",
    "description": "GPS Direction"
  },
  {
    "key": "gps_timestamp",
    "label": "GPS Timestamp",
    "category": "GPS / Location",
    "description": "GPS Timestamp"
  },
  {
    "key": "gps_date",
    "label": "GPS Date",
    "category": "GPS / Location",
    "description": "GPS Date"
  },
  {
    "key": "gps_map_datum",
    "label": "GPS Map Datum",
    "category": "GPS / Location",
    "description": "GPS Map Datum"
  },
  {
    "key": "gps_coordinates_dms",
    "label": "GPS Coordinates (DMS)",
    "category": "GPS / Location",
    "description": "GPS Coordinates (DMS)"
  },
  {
    "key": "video_codec",
    "label": "Video Codec",
    "category": "Video",
    "description": "Video Codec"
  },
  {
    "key": "video_bitrate",
    "label": "Video Bitrate",
    "category": "Video",
    "description": "Video Bitrate"
  },
  {
    "key": "video_frame_rate",
    "label": "Video Frame Rate",
    "category": "Video",
    "description": "Video Frame Rate"
  },
  {
    "key": "video_duration",
    "label": "Video Duration",
    "category": "Video",
    "description": "Video Duration"
  },
  {
    "key": "video_width",
    "label": "Video Width",
    "category": "Video",
    "description": "Video Width"
  },
  {
    "key": "video_height",
    "label": "Video Height",
    "category": "Video",
    "description": "Video Height"
  },
  {
    "key": "aspect_ratio",
    "label": "Aspect Ratio",
    "category": "Video",
    "description": "Aspect Ratio"
  },
  {
    "key": "rotation",
    "label": "Rotation",
    "category": "Video",
    "description": "Rotation"
  },
  {
    "key": "audio_codec_video",
    "label": "Audio Codec (Video)",
    "category": "Video",
    "description": "Audio Codec (Video)"
  },
  {
    "key": "audio_channels_video",
    "label": "Audio Channels (Video)",
    "category": "Video",
    "description": "Audio Channels (Video)"
  },
  {
    "key": "audio_sample_rate_video",
    "label": "Audio Sample Rate (Video)",
    "category": "Video",
    "description": "Audio Sample Rate (Video)"
  },
  {
    "key": "audio_bitrate_video",
    "label": "Audio Bitrate (Video)",
    "category": "Video",
    "description": "Audio Bitrate (Video)"
  },
  {
    "key": "total_bitrate",
    "label": "Total Bitrate",
    "category": "Video",
    "description": "Total Bitrate"
  },
  {
    "key": "container_format",
    "label": "Container Format",
    "category": "Video",
    "description": "Container Format"
  },
  {
    "key": "encoder",
    "label": "Encoder",
    "category": "Video",
    "description": "Encoder"
  },
  {
    "key": "video_creation_date",
    "label": "Video Creation Date",
    "category": "Video",
    "description": "Video Creation Date"
  },
  {
    "key": "video_track_count",
    "label": "Video Track Count",
    "category": "Video",
    "description": "Video Track Count"
  },
  {
    "key": "subtitle_track_count",
    "label": "Subtitle Track Count",
    "category": "Video",
    "description": "Subtitle Track Count"
  },
  {
    "key": "chapter_count",
    "label": "Chapter Count",
    "category": "Video",
    "description": "Chapter Count"
  },
  {
    "key": "audio_title",
    "label": "Audio Title",
    "category": "Audio",
    "description": "Audio Title"
  },
  {
    "key": "audio_artist",
    "label": "Audio Artist",
    "category": "Audio",
    "description": "Audio Artist"
  },
  {
    "key": "audio_album",
    "label": "Audio Album",
    "category": "Audio",
    "description": "Audio Album"
  },
  {
    "key": "audio_album_artist",
    "label": "Audio Album Artist",
    "category": "Audio",
    "description": "Audio Album Artist"
  },
  {
    "key": "audio_genre",
    "label": "Audio Genre",
    "category": "Audio",
    "description": "Audio Genre"
  },
  {
    "key": "audio_year",
    "label": "Audio Year",
    "category": "Audio",
    "description": "Audio Year"
  },
  {
    "key": "audio_track_number",
    "label": "Audio Track Number",
    "category": "Audio",
    "description": "Audio Track Number"
  },
  {
    "key": "audio_disc_number",
    "label": "Audio Disc Number",
    "category": "Audio",
    "description": "Audio Disc Number"
  },
  {
    "key": "audio_composer",
    "label": "Audio Composer",
    "category": "Audio",
    "description": "Audio Composer"
  },
  {
    "key": "audio_duration",
    "label": "Audio Duration",
    "category": "Audio",
    "description": "Audio Duration"
  },
  {
    "key": "audio_bitrate",
    "label": "Audio Bitrate",
    "category": "Audio",
    "description": "Audio Bitrate"
  },
  {
    "key": "audio_sample_rate",
    "label": "Audio Sample Rate",
    "category": "Audio",
    "description": "Audio Sample Rate"
  },
  {
    "key": "audio_channels",
    "label": "Audio Channels",
    "category": "Audio",
    "description": "Audio Channels"
  },
  {
    "key": "audio_codec",
    "label": "Audio Codec",
    "category": "Audio",
    "description": "Audio Codec"
  },
  {
    "key": "audio_bit_depth",
    "label": "Audio Bit Depth",
    "category": "Audio",
    "description": "Audio Bit Depth"
  },
  {
    "key": "audio_bpm",
    "label": "Audio BPM",
    "category": "Audio",
    "description": "Audio BPM"
  },
  {
    "key": "audio_comment",
    "label": "Audio Comment",
    "category": "Audio",
    "description": "Audio Comment"
  },
  {
    "key": "audio_lyrics",
    "label": "Audio Lyrics",
    "category": "Audio",
    "description": "Audio Lyrics"
  },
  {
    "key": "audio_publisher_label",
    "label": "Audio Publisher / Label",
    "category": "Audio",
    "description": "Audio Publisher / Label"
  },
  {
    "key": "audio_encoder",
    "label": "Audio Encoder",
    "category": "Audio",
    "description": "Audio Encoder"
  },
  {
    "key": "has_album_art",
    "label": "Has Album Art",
    "category": "Audio",
    "description": "Has Album Art"
  },
  {
    "key": "album_art_size",
    "label": "Album Art Size",
    "category": "Audio",
    "description": "Album Art Size"
  },
  {
    "key": "audio_replaygain",
    "label": "Audio ReplayGain",
    "category": "Audio",
    "description": "Audio ReplayGain"
  },
  {
    "key": "document_title",
    "label": "Document Title",
    "category": "Documents",
    "description": "Document Title"
  },
  {
    "key": "document_author",
    "label": "Document Author",
    "category": "Documents",
    "description": "Document Author"
  },
  {
    "key": "document_subject",
    "label": "Document Subject",
    "category": "Documents",
    "description": "Document Subject"
  },
  {
    "key": "document_keywords",
    "label": "Document Keywords",
    "category": "Documents",
    "description": "Document Keywords"
  },
  {
    "key": "document_creator_app",
    "label": "Document Creator App",
    "category": "Documents",
    "description": "Document Creator App"
  },
  {
    "key": "document_producer",
    "label": "Document Producer",
    "category": "Documents",
    "description": "Document Producer"
  },
  {
    "key": "document_creation_date",
    "label": "Document Creation Date",
    "category": "Documents",
    "description": "Document Creation Date"
  },
  {
    "key": "document_modification_date",
    "label": "Document Modification Date",
    "category": "Documents",
    "description": "Document Modification Date"
  },
  {
    "key": "document_page_count",
    "label": "Document Page Count",
    "category": "Documents",
    "description": "Document Page Count"
  },
  {
    "key": "document_word_count",
    "label": "Document Word Count",
    "category": "Documents",
    "description": "Document Word Count"
  },
  {
    "key": "document_character_count",
    "label": "Document Character Count",
    "category": "Documents",
    "description": "Document Character Count"
  },
  {
    "key": "document_line_count",
    "label": "Document Line Count",
    "category": "Documents",
    "description": "Document Line Count"
  },
  {
    "key": "document_paragraph_count",
    "label": "Document Paragraph Count",
    "category": "Documents",
    "description": "Document Paragraph Count"
  },
  {
    "key": "document_slide_count",
    "label": "Document Slide Count",
    "category": "Documents",
    "description": "Document Slide Count"
  },
  {
    "key": "document_sheet_count",
    "label": "Document Sheet Count",
    "category": "Documents",
    "description": "Document Sheet Count"
  },
  {
    "key": "document_revision",
    "label": "Document Revision",
    "category": "Documents",
    "description": "Document Revision"
  },
  {
    "key": "document_last_author",
    "label": "Document Last Author",
    "category": "Documents",
    "description": "Document Last Author"
  },
  {
    "key": "document_company",
    "label": "Document Company",
    "category": "Documents",
    "description": "Document Company"
  },
  {
    "key": "document_manager",
    "label": "Document Manager",
    "category": "Documents",
    "description": "Document Manager"
  },
  {
    "key": "document_category",
    "label": "Document Category",
    "category": "Documents",
    "description": "Document Category"
  },
  {
    "key": "document_language",
    "label": "Document Language",
    "category": "Documents",
    "description": "Document Language"
  },
  {
    "key": "document_template",
    "label": "Document Template",
    "category": "Documents",
    "description": "Document Template"
  },
  {
    "key": "document_comments",
    "label": "Document Comments",
    "category": "Documents",
    "description": "Document Comments"
  },
  {
    "key": "pdf_version",
    "label": "PDF Version",
    "category": "PDF Specific",
    "description": "PDF Version"
  },
  {
    "key": "pdf_encrypted",
    "label": "PDF Encrypted",
    "category": "PDF Specific",
    "description": "PDF Encrypted"
  },
  {
    "key": "pdf_has_forms",
    "label": "PDF Has Forms",
    "category": "PDF Specific",
    "description": "PDF Has Forms"
  },
  {
    "key": "pdf_has_annotations",
    "label": "PDF Has Annotations",
    "category": "PDF Specific",
    "description": "PDF Has Annotations"
  },
  {
    "key": "pdf_has_embedded_files",
    "label": "PDF Has Embedded Files",
    "category": "PDF Specific",
    "description": "PDF Has Embedded Files"
  },
  {
    "key": "pdf_has_signatures",
    "label": "PDF Has Signatures",
    "category": "PDF Specific",
    "description": "PDF Has Signatures"
  },
  {
    "key": "pdf_page_size",
    "label": "PDF Page Size",
    "category": "PDF Specific",
    "description": "PDF Page Size"
  },
  {
    "key": "pdf_producer",
    "label": "PDF Producer",
    "category": "PDF Specific",
    "description": "PDF Producer"
  },
  {
    "key": "pdf_creator",
    "label": "PDF Creator",
    "category": "PDF Specific",
    "description": "PDF Creator"
  },
  {
    "key": "pdf_linearized",
    "label": "PDF Linearized",
    "category": "PDF Specific",
    "description": "PDF Linearized"
  },
  {
    "key": "pdf_tagged",
    "label": "PDF Tagged",
    "category": "PDF Specific",
    "description": "PDF Tagged"
  },
  {
    "key": "file_entropy",
    "label": "File Entropy",
    "category": "Forensics / PE",
    "description": "File Entropy"
  },
  {
    "key": "magic_bytes_header",
    "label": "Magic Bytes (Header)",
    "category": "Forensics / PE",
    "description": "Magic Bytes (Header)"
  },
  {
    "key": "pe_architecture",
    "label": "PE Architecture",
    "category": "Forensics / PE",
    "description": "PE Architecture"
  },
  {
    "key": "pe_compile_date",
    "label": "PE Compile Date",
    "category": "Forensics / PE",
    "description": "PE Compile Date"
  },
  {
    "key": "pe_import_count",
    "label": "PE Import Count",
    "category": "Forensics / PE",
    "description": "PE Import Count"
  },
  {
    "key": "pe_section_count",
    "label": "PE Section Count",
    "category": "Forensics / PE",
    "description": "PE Section Count"
  },
  {
    "key": "pe_signed",
    "label": "PE Signed",
    "category": "Forensics / PE",
    "description": "PE Signed"
  },
  {
    "key": "pe_original_filename",
    "label": "PE Original Filename",
    "category": "Forensics / PE",
    "description": "PE Original Filename"
  },
  {
    "key": "pe_product_name",
    "label": "PE Product Name",
    "category": "Forensics / PE",
    "description": "PE Product Name"
  },
  {
    "key": "pe_product_version",
    "label": "PE Product Version",
    "category": "Forensics / PE",
    "description": "PE Product Version"
  },
  {
    "key": "pe_company_name",
    "label": "PE Company Name",
    "category": "Forensics / PE",
    "description": "PE Company Name"
  },
  {
    "key": "pe_file_version",
    "label": "PE File Version",
    "category": "Forensics / PE",
    "description": "PE File Version"
  },
  {
    "key": "pe_description",
    "label": "PE Description",
    "category": "Forensics / PE",
    "description": "PE Description"
  }
];
