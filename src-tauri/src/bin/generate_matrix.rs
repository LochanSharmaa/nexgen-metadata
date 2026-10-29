//! generate_matrix.rs — Golden Matrix Generator for NexGen Metadata
//!
//! Standalone binary that outputs the pre-compiled `mapping_matrix.json` file
//! containing exhaustive mappings from known ExifTool / lopdf / goblin variant
//! keys to canonical FileMetadata struct field names.
//!
//! Usage:
//!   cargo run --bin generate-matrix [--output path/to/mapping_matrix.json]
//!
//! If `--output` is not specified, writes to `../mapping_matrix.json` relative
//! to the binary (the `src-tauri/` directory).

use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn main() {
    let output_path = std::env::args()
        .skip_while(|a| a != "--output")
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()))
                .unwrap_or_else(|| PathBuf::from("."))
                .join("mapping_matrix.json")
        });

    // Using BTreeMap for deterministic (sorted) JSON output
    let mut matrix = BTreeMap::<String, String>::new();

    // ── Helper macro: register multiple source keys for one canonical target ──
    macro_rules! map_keys {
        ($target:expr, $($key:expr),+ $(,)?) => {
            $(matrix.insert($key.to_string(), $target.to_string());)+
        };
    }

    // ─────────────────────────────────────────────────────────────────────
    // § EXIF Camera Identification
    // ─────────────────────────────────────────────────────────────────────
    map_keys!("Make", "Make", "EXIF:Make", "XMP:Make", "IFD0:Make",
              "QuickTime:Make", "MakerNotes:Make");
    map_keys!("Model", "Model", "EXIF:Model", "XMP:Model", "IFD0:Model",
              "QuickTime:Model");
    map_keys!("SerialNumber", "SerialNumber", "EXIF:SerialNumber",
              "EXIF:BodySerialNumber", "MakerNotes:SerialNumber",
              "MakerNotes:InternalSerialNumber", "XMP:SerialNumber");
    map_keys!("LensModel", "LensModel", "EXIF:LensModel", "XMP:LensModel",
              "XMP:Lens", "MakerNotes:LensType", "Composite:LensID");

    // ─────────────────────────────────────────────────────────────────────
    // § EXIF Exposure & Optics
    // ─────────────────────────────────────────────────────────────────────
    map_keys!("FocalLength", "FocalLength", "EXIF:FocalLength",
              "XMP:FocalLength", "Composite:FocalLength", "MakerNotes:FocalLength");
    map_keys!("FocalLengthIn35mmFormat", "FocalLengthIn35mmFormat",
              "EXIF:FocalLengthIn35mmFormat", "Composite:FocalLength35efl",
              "FocalLengthIn35mmFilm");
    map_keys!("FNumber", "FNumber", "EXIF:FNumber", "XMP:FNumber",
              "Composite:Aperture");
    map_keys!("ExposureTime", "ExposureTime", "EXIF:ExposureTime",
              "XMP:ExposureTime", "Composite:ShutterSpeed");
    map_keys!("ISO", "ISO", "EXIF:ISO", "XMP:ISO", "EXIF:ISOSpeedRatings",
              "ISOSpeedRatings", "MakerNotes:ISO");
    map_keys!("ExposureProgram", "ExposureProgram", "EXIF:ExposureProgram");
    map_keys!("MeteringMode", "MeteringMode", "EXIF:MeteringMode");
    map_keys!("Flash", "Flash", "EXIF:Flash");
    map_keys!("WhiteBalance", "WhiteBalance", "EXIF:WhiteBalance",
              "XMP:WhiteBalance");

    // ─────────────────────────────────────────────────────────────────────
    // § EXIF Color & Resolution
    // ─────────────────────────────────────────────────────────────────────
    map_keys!("ColorSpace", "ColorSpace", "EXIF:ColorSpace",
              "ICC_Profile:ColorSpaceData");
    map_keys!("Orientation", "Orientation", "EXIF:Orientation",
              "XMP:Orientation");
    map_keys!("XResolution", "XResolution", "EXIF:XResolution",
              "IFD0:XResolution");
    map_keys!("YResolution", "YResolution", "EXIF:YResolution",
              "IFD0:YResolution");
    map_keys!("BitsPerSample", "BitsPerSample", "EXIF:BitsPerSample",
              "IFD0:BitsPerSample");
    map_keys!("Compression", "Compression", "EXIF:Compression",
              "IFD1:Compression");

    // ─────────────────────────────────────────────────────────────────────
    // § EXIF Date/Time
    // ─────────────────────────────────────────────────────────────────────
    map_keys!("DateTimeOriginal", "DateTimeOriginal", "EXIF:DateTimeOriginal",
              "XMP:DateTimeOriginal", "XMP:DateCreated",
              "QuickTime:CreateDate", "QuickTime:MediaCreateDate");
    map_keys!("CreateDate", "CreateDate", "EXIF:CreateDate", "XMP:CreateDate",
              "Composite:SubSecCreateDate");

    // ─────────────────────────────────────────────────────────────────────
    // § EXIF Software & Author
    // ─────────────────────────────────────────────────────────────────────
    map_keys!("Software", "Software", "EXIF:Software", "IFD0:Software",
              "XMP:CreatorTool", "XMP:Software");
    map_keys!("Artist", "Artist", "EXIF:Artist", "IFD0:Artist", "XMP:Creator");
    map_keys!("Copyright", "Copyright", "EXIF:Copyright", "IFD0:Copyright",
              "XMP:Rights");

    // ─────────────────────────────────────────────────────────────────────
    // § Image Dimensions & Thumbnail
    // ─────────────────────────────────────────────────────────────────────
    map_keys!("ImageWidth", "ImageWidth", "EXIF:ImageWidth",
              "EXIF:ExifImageWidth", "File:ImageWidth",
              "QuickTime:ImageWidth", "QuickTime:SourceImageWidth");
    map_keys!("ImageHeight", "ImageHeight", "EXIF:ImageHeight",
              "EXIF:ExifImageHeight", "File:ImageHeight",
              "QuickTime:ImageHeight", "QuickTime:SourceImageHeight");
    map_keys!("ThumbnailOffset", "ThumbnailOffset", "EXIF:ThumbnailOffset",
              "IFD1:ThumbnailOffset");
    map_keys!("ThumbnailLength", "ThumbnailLength", "EXIF:ThumbnailLength",
              "IFD1:ThumbnailLength");
    map_keys!("ProfileDescription", "ProfileDescription",
              "ICC_Profile:ProfileDescription");
    map_keys!("SubjectDistance", "SubjectDistance", "EXIF:SubjectDistance");

    // ─────────────────────────────────────────────────────────────────────
    // § GPS
    // ─────────────────────────────────────────────────────────────────────
    map_keys!("GPSLatitude", "GPSLatitude", "GPS:GPSLatitude",
              "EXIF:GPSLatitude", "Composite:GPSLatitude", "XMP:GPSLatitude");
    map_keys!("GPSLongitude", "GPSLongitude", "GPS:GPSLongitude",
              "EXIF:GPSLongitude", "Composite:GPSLongitude", "XMP:GPSLongitude");
    map_keys!("GPSAltitude", "GPSAltitude", "GPS:GPSAltitude",
              "EXIF:GPSAltitude", "XMP:GPSAltitude");
    map_keys!("GPSAltitudeRef", "GPSAltitudeRef", "GPS:GPSAltitudeRef");
    map_keys!("GPSSpeed", "GPSSpeed", "GPS:GPSSpeed");
    map_keys!("GPSSpeedRef", "GPSSpeedRef", "GPS:GPSSpeedRef");
    map_keys!("GPSImgDirection", "GPSImgDirection", "GPS:GPSImgDirection");
    map_keys!("GPSImgDirectionRef", "GPSImgDirectionRef",
              "GPS:GPSImgDirectionRef");
    map_keys!("GPSTimeStamp", "GPSTimeStamp", "GPS:GPSTimeStamp");
    map_keys!("GPSDateStamp", "GPSDateStamp", "GPS:GPSDateStamp");
    map_keys!("GPSDOP", "GPSDOP", "GPS:GPSDOP");
    map_keys!("GPSSatellites", "GPSSatellites", "GPS:GPSSatellites");

    // ─────────────────────────────────────────────────────────────────────
    // § Video & Audio
    // ─────────────────────────────────────────────────────────────────────
    map_keys!("Duration", "Duration", "QuickTime:Duration",
              "Composite:Duration", "MediaDuration",
              "QuickTime:MediaDuration");
    map_keys!("VideoCodec", "VideoCodec", "QuickTime:CompressorID",
              "QuickTime:CompressorName", "Track1:CodecID", "Video:Codec");
    map_keys!("VideoFrameRate", "VideoFrameRate", "QuickTime:VideoFrameRate",
              "Track1:FrameRate", "Composite:VideoFrameRate");
    map_keys!("BitDepth", "BitDepth", "QuickTime:BitDepth", "Track1:BitDepth");
    map_keys!("ColorPrimaries", "ColorPrimaries", "QuickTime:ColorPrimaries");
    map_keys!("TransferCharacteristics", "TransferCharacteristics",
              "QuickTime:TransferCharacteristics");
    map_keys!("AvgBitrate", "AvgBitrate", "QuickTime:AvgBitrate",
              "Composite:AvgBitrate");
    map_keys!("AudioCodec", "AudioCodec", "QuickTime:AudioFormat",
              "Track2:CodecID");
    map_keys!("AudioSampleRate", "AudioSampleRate",
              "QuickTime:AudioSampleRate", "Track2:SampleRate");
    map_keys!("AudioChannels", "AudioChannels", "QuickTime:AudioChannels",
              "Track2:Channels");
    map_keys!("AudioBitrate", "AudioBitrate", "QuickTime:AudioBitrate",
              "Track2:AvgBitrate");
    map_keys!("AudioBitsPerSample", "AudioBitsPerSample",
              "QuickTime:AudioBitsPerSample", "Track2:BitsPerSample");
    map_keys!("Encoder", "Encoder", "QuickTime:Encoder", "XMP:Encoder");
    map_keys!("Rotation", "Rotation", "QuickTime:Rotation",
              "Composite:Rotation");
    map_keys!("MajorBrand", "MajorBrand", "QuickTime:MajorBrand",
              "File:FileType");

    // ─────────────────────────────────────────────────────────────────────
    // § Office Document Metadata
    // ─────────────────────────────────────────────────────────────────────
    map_keys!("Author", "Author", "XMP:Author", "XMP-dc:Creator",
              "FlashPix:Author");
    map_keys!("LastModifiedBy", "LastModifiedBy", "FlashPix:LastModifiedBy",
              "XMP:LastModifiedBy");
    map_keys!("Title", "Title", "XMP:Title", "XMP-dc:Title", "FlashPix:Title");
    map_keys!("Subject", "Subject", "XMP:Subject", "XMP-dc:Subject",
              "XMP-dc:Description");
    map_keys!("Keywords", "Keywords", "XMP:Keywords", "IPTC:Keywords");
    map_keys!("Category", "Category", "FlashPix:Category", "XMP:Category");
    map_keys!("Company", "Company", "FlashPix:Company", "XMP:Company");
    map_keys!("RevisionNumber", "RevisionNumber", "FlashPix:RevisionNumber");
    map_keys!("TotalEditTime", "TotalEditTime", "FlashPix:TotalEditTime");
    map_keys!("Pages", "Pages", "FlashPix:Pages", "XMP:Pages", "PDF:PageCount");
    map_keys!("Words", "Words", "FlashPix:Words");
    map_keys!("Characters", "Characters", "FlashPix:Characters");
    map_keys!("Lines", "Lines", "FlashPix:Lines");
    map_keys!("Paragraphs", "Paragraphs", "FlashPix:Paragraphs");
    map_keys!("Slides", "Slides", "FlashPix:Slides");

    // ─────────────────────────────────────────────────────────────────────
    // § PDF
    // ─────────────────────────────────────────────────────────────────────
    map_keys!("PDFVersion", "PDFVersion", "PDF:PDFVersion");
    map_keys!("Producer", "Producer", "PDF:Producer", "XMP:Producer");
    map_keys!("Creator", "Creator", "PDF:Creator", "XMP:CreatorTool");
    map_keys!("Linearized", "Linearized", "PDF:Linearized", "PDF_Linearized");

    // ─────────────────────────────────────────────────────────────────────
    // § PE / Executable
    // ─────────────────────────────────────────────────────────────────────
    map_keys!("MachineType", "MachineType", "EXE:MachineType", "Machine",
              "PE:Machine");

    // ─────────────────────────────────────────────────────────────────────
    // § MIME & FileType
    // ─────────────────────────────────────────────────────────────────────
    map_keys!("MIMEType", "MIMEType", "File:MIMEType");
    map_keys!("FileType", "FileType", "File:FileType", "File:FileTypeExtension");

    // ── Serialise to JSON ────────────────────────────────────────────────
    let output = json!({ "mappings": matrix });
    let pretty = serde_json::to_string_pretty(&output).expect("JSON serialisation failed");

    std::fs::write(&output_path, &pretty).unwrap_or_else(|e| {
        eprintln!("ERROR: Failed to write {}: {}", output_path.display(), e);
        std::process::exit(1);
    });

    println!("✓ Golden Matrix written to: {}", output_path.display());
    println!("  Total mappings: {} source keys", matrix.len());

    // Count unique canonical targets
    let unique_targets: std::collections::HashSet<&String> = matrix.values().collect();
    println!("  Unique canonical fields: {}", unique_targets.len());
}
