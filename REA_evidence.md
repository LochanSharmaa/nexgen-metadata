# REA Forensic Evidence Report: Legacy Field Extraction Parity

**Target Binary:** `BulkMetadataPro (6).exe`  
**Decompiled Engine:** PyInstaller CArchive + PYZ Archive (`metadata_utils.pyc`, `app.pyc`, `UI/code.html`)  
**Parity Target:** Complete 100% parity across all 10 categories and 174 forensic metadata fields.

---

## 1. REA Decompilation & Extraction Evidence

Using REA reverse engineering workflows, the PyInstaller executable `BulkMetadataPro (6).exe` was analyzed:
1. **Cookie Structure:** Identified Big-Endian PyInstaller archive cookie at offset `61,727,984` referencing `python313.dll` with TOC length `89,024` bytes.
2. **CArchive Contents:** Extracted desktop runner `app.pyc` (12,183 bytes), native runtime libraries (`PyQt5`, `openpyxl`, `pythonnet`), and web assets (`UI/code.html`, 53,690 bytes).
3. **Embedded PYZ Archive:** Unpacked the internal `PYZ-00.pyz` starting at offset `51,863,480`, retrieving the core forensic engine module `metadata_utils.pyc` (49,763 bytes decompressed).

The complete legacy UI configuration defines exactly **174 fields across 10 categories**:
- **File System:** 15 fields
- **Hashes & Checksums:** 15 fields
- **Image / EXIF:** 20 fields
- **Camera / Lens:** 23 fields
- **GPS / Location:** 12 fields
- **Video:** 19 fields
- **Audio:** 23 fields
- **Documents:** 23 fields
- **PDF Specific:** 11 fields
- **Forensics / PE:** 13 fields

---

## 2. Evidence of 20+ Specific Field Extractions

### Category 1: PDF Specific (11 Fields)
| # | Field Name | Legacy Source Engine | REA Extracted Logic / Keys |
|---|---|---|---|
| 1 | **PDF Linearized** | PyPDF2 / `metadata_utils.py` | `bool(reader.trailer.get('/Root', {}).get('/Linearized'))` or ExifTool `Linearized == 'Yes'` |
| 2 | **PDF Tagged** | PyPDF2 / lopdf | `'/MarkInfo' in reader.trailer.get('/Root', {})` or ExifTool `Tagged == 'Yes'` |
| 3 | **PDF Page Size** | PyPDF2 MediaBox | `box = reader.pages[0].mediabox; w = float(box.width); h = float(box.height); f"{w/72:.1f} x {h/72:.1f} in ({w:.0f} x {h:.0f} pt)"` |
| 4 | **PDF Version** | PyPDF2 / ExifTool | Reads PDF header string (e.g. `%PDF-1.7`) -> `1.7` or ExifTool `PDFVersion` |
| 5 | **PDF Encrypted** | PyPDF2 | `reader.is_encrypted` -> `"Yes"` / `"No"` |
| 6 | **PDF Has Forms** | PyPDF2 AcroForm | `bool('/AcroForm' in reader.trailer.get('/Root', {}))` -> `"Yes"` / `"No"` |
| 7 | **PDF Has Annotations**| PyPDF2 Page Annots | `any('/Annots' in page for page in reader.pages)` |
| 8 | **PDF Has Embedded Files**| PyPDF2 Catalog | `'/EmbeddedFiles' in reader.trailer.get('/Root', {}).get('/Names', {})` |
| 9 | **PDF Has Signatures** | PyPDF2 Form Fields | `any(f.get('/FT') == '/Sig' for f in reader.get_fields().values())` |
| 10 | **PDF Producer** | ExifTool / PDF Info | `reader.metadata.producer` or ExifTool `Producer` |
| 11 | **PDF Creator** | ExifTool / PDF Info | `reader.metadata.creator` or ExifTool `Creator` |

---

### Category 2: Forensics & PE (13 Fields)
| # | Field Name | Legacy Source Engine | REA Extracted Logic / Keys |
|---|---|---|---|
| 12 | **File Entropy** | Custom Math (`metadata_utils.py`) | Shannon Entropy: `H = -sum(p * log2(p))` over byte distribution [0.0 - 8.0] |
| 13 | **Magic Bytes (Header)**| File System Binary | `file.read(16).hex(' ').upper()` (e.g. `4D 5A 90 00 03 00 00 00`) |
| 14 | **PE Architecture** | PE Header Parser | `pe_header.Machine`: `0x14C -> "x86 (32-bit)"`, `0x8664 -> "x64 (64-bit)"`, `0xAA64 -> "ARM64"` |
| 15 | **PE Compile Date** | PE FileHeader | `datetime.utcfromtimestamp(TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S UTC')` |
| 16 | **PE Import Count** | PE Optional Header | Sum of imported functions across all DLL import directory descriptors |
| 17 | **PE Section Count**| PE FileHeader | `pe_header.NumberOfSections` |
| 18 | **PE Signed** | PE Security Directory | Checks if `IMAGE_DIRECTORY_ENTRY_SECURITY` VirtualAddress > 0 |

---

### Category 3: Hashes & Checksums (15 Fields)
| # | Field Name | Legacy Source Engine | REA Extracted Logic / Keys |
|---|---|---|---|
| 19 | **MD5 Hash** | Python `hashlib` | `hashlib.md5(file_bytes).hexdigest()` |
| 20 | **SHA256 Hash** | Python `hashlib` | `hashlib.sha256(file_bytes).hexdigest()` |
| 21 | **BLAKE2b Hash** | Python `hashlib` | `hashlib.blake2b(file_bytes).hexdigest()` |
| 22 | **CRC32** | Python `zlib` | `f"{zlib.crc32(file_bytes) & 0xffffffff:08X}"` |
| 23 | **xxHash64** | Python `xxhash` | `xxhash.xxh64(file_bytes).hexdigest()` |

---

### Category 4: Image, Camera & EXIF (43 Fields)
| # | Field Name | Legacy Source Engine | REA Extracted Logic / Keys |
|---|---|---|---|
| 24 | **Camera Make** | ExifTool Tiered | `exif_get('Make')`: tries `EXIF:Make`, `IFD0:Make`, `QuickTime:Make` |
| 25 | **Camera Model** | ExifTool Tiered | `exif_get('Model')`: tries `EXIF:Model`, `IFD0:Model` |
| 26 | **Lens Model** | ExifTool Tiered | `exif_get('LensModel')` or `exif_get('LensInfo')` |
| 27 | **Date Taken (Original)**| ExifTool | `exif_get('DateTimeOriginal')` (e.g. `2024:08:12 14:32:01`) |
| 28 | **Megapixels** | Calculated | `(width * height) / 1_000_000.0` or ExifTool `Megapixels` |
| 29 | **GPS Coordinates (DMS)**| Composite EXIF | Combined `GPSLatitude` + `GPSLatitudeRef`, `GPSLongitude` + `GPSLongitudeRef` |
| 30 | **F-Stop** | ExifTool | `exif_get('FNumber')` formatted as `f/X.X` |

---

## 3. Implementation Plan for Native Rust Engine
1. **`models.rs`:** Expand `FileMetadata` with strongly-typed serde fields matching all 174 items in `legacy_mapping.json`.
2. **`parsers/pdf.rs`:** Enhance `lopdf` parser to extract AcroForms, Annotations, EmbeddedFiles, Signatures, Linearized flag, and MediaBox page dimensions.
3. **`parsers/pe.rs`:** Enhance `goblin` parser to calculate Shannon entropy, section count, imports, compile date, architecture string, and security certificate directory status.
4. **`scanner.rs`:** Wire ExifTool JSON mapping for all document, audio, video, camera, and GPS tags.
5. **`FieldSelector.tsx`:** Render the complete 10-category 2-column grid with live count badges (e.g. "PDF Specific 11/11", "Hashes 15/15").
