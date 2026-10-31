import React, { useState, useEffect, useMemo, useRef } from "react";
import { api, selectFolderApi, triggerExportDownload } from "./api";
import { LoginView } from "./LoginView";
import { useScan } from "./hooks/useScan";
import { ShieldCheck } from "lucide-react";

// ═══════════════════════════════════════════════════════════
// DATA: All 174 fields organized across 10 categories
// ═══════════════════════════════════════════════════════════
export const FIELD_CATEGORIES: Record<
  string,
  { icon: string; emoji: string; fields: string[] }
> = {
  "File System": {
    icon: "folder",
    emoji: "📁",
    fields: [
      "File Name", "File Extension", "File Path", "Parent Directory",
      "File Size (Bytes)", "File Size (Human)", "Creation Date", "Modification Date",
      "Access Date", "MIME Type", "File Permissions", "Is Hidden",
      "Is Read-Only", "Is Symlink", "Owner (Windows)"
    ]
  },
  "Hashes & Checksums": {
    icon: "tag",
    emoji: "🔒",
    fields: [
      "MD5 Hash", "SHA1 Hash", "SHA224 Hash", "SHA256 Hash", "SHA384 Hash", "SHA512 Hash",
      "SHA3-224 Hash", "SHA3-256 Hash", "SHA3-384 Hash", "SHA3-512 Hash",
      "BLAKE2b Hash", "BLAKE2s Hash", "CRC32", "Adler32", "xxHash64"
    ]
  },
  "Image / EXIF": {
    icon: "photo_camera",
    emoji: "📷",
    fields: [
      "Image Width", "Image Height", "Resolution (DPI)", "Bit Depth",
      "Color Space", "Color Profile", "Orientation", "Compression",
      "Has Alpha Channel", "Megapixels", "EXIF Version", "Date Taken (Original)",
      "Date Digitized", "Software", "Host Computer", "Description / Caption",
      "User Comment", "Copyright", "Artist / Author", "Rating"
    ]
  },
  "Camera / Lens": {
    icon: "camera",
    emoji: "📸",
    fields: [
      "Camera Make", "Camera Model", "Camera Serial", "Lens Model",
      "Lens Make", "Lens Serial", "Lens Focal Length", "Lens Max Aperture",
      "ISO", "Exposure Time", "F-Stop", "Exposure Program",
      "Exposure Mode", "Exposure Compensation", "Metering Mode", "Flash",
      "Flash Mode", "White Balance", "Focus Mode", "Focus Distance",
      "Scene Type", "Shutter Count", "Digital Zoom Ratio"
    ]
  },
  "GPS / Location": {
    icon: "location_on",
    emoji: "🌍",
    fields: [
      "GPS Latitude", "GPS Longitude", "GPS Altitude", "GPS Latitude Ref",
      "GPS Longitude Ref", "GPS Altitude Ref", "GPS Speed", "GPS Direction",
      "GPS Timestamp", "GPS Date", "GPS Map Datum", "GPS Coordinates (DMS)"
    ]
  },
  "Video": {
    icon: "videocam",
    emoji: "🎬",
    fields: [
      "Video Codec", "Video Bitrate", "Video Frame Rate", "Video Duration",
      "Video Width", "Video Height", "Aspect Ratio", "Rotation",
      "Audio Codec (Video)", "Audio Channels (Video)", "Audio Sample Rate (Video)",
      "Audio Bitrate (Video)", "Total Bitrate", "Container Format",
      "Encoder", "Video Creation Date", "Video Track Count",
      "Subtitle Track Count", "Chapter Count"
    ]
  },
  "Audio": {
    icon: "music_note",
    emoji: "🎵",
    fields: [
      "Audio Title", "Audio Artist", "Audio Album", "Audio Album Artist",
      "Audio Genre", "Audio Year", "Audio Track Number", "Audio Disc Number",
      "Audio Composer", "Audio Duration", "Audio Bitrate", "Audio Sample Rate",
      "Audio Channels", "Audio Codec", "Audio Bit Depth", "Audio BPM",
      "Audio Comment", "Audio Lyrics", "Audio Publisher / Label", "Audio Encoder",
      "Has Album Art", "Album Art Size", "Audio ReplayGain"
    ]
  },
  "Documents": {
    icon: "description",
    emoji: "📄",
    fields: [
      "Document Title", "Document Author", "Document Subject", "Document Keywords",
      "Document Creator App", "Document Producer", "Document Creation Date",
      "Document Modification Date", "Document Page Count", "Document Word Count",
      "Document Character Count", "Document Line Count", "Document Paragraph Count",
      "Document Slide Count", "Document Sheet Count", "Document Revision",
      "Document Last Author", "Document Company", "Document Manager",
      "Document Category", "Document Language", "Document Template", "Document Comments"
    ]
  },
  "PDF Specific": {
    icon: "picture_as_pdf",
    emoji: "📑",
    fields: [
      "PDF Version", "PDF Encrypted", "PDF Has Forms", "PDF Has Annotations",
      "PDF Has Embedded Files", "PDF Has Signatures", "PDF Page Size",
      "PDF Producer", "PDF Creator", "PDF Linearized", "PDF Tagged"
    ]
  },
  "Forensics / PE": {
    icon: "shield",
    emoji: "🔐",
    fields: [
      "File Entropy", "Magic Bytes (Header)", "PE Architecture", "PE Compile Date",
      "PE Import Count", "PE Section Count", "PE Signed", "PE Original Filename",
      "PE Product Name", "PE Product Version", "PE Company Name",
      "PE File Version", "PE Description"
    ]
  }
};

// Flattened list and category mapping
export const ALL_FIELDS: string[] = [];
export const FIELD_TO_CATEGORY: Record<string, string> = {};
for (const [cat, data] of Object.entries(FIELD_CATEGORIES)) {
  for (const f of data.fields) {
    ALL_FIELDS.push(f);
    FIELD_TO_CATEGORY[f] = cat;
  }
}

// File type filters
const FILE_FILTERS = [
  "All Files (*.*)",
  "Images (JPG, PNG, TIFF, RAW, HEIC…)",
  "Videos (MP4, MKV, MOV, AVI…)",
  "Audio (MP3, FLAC, WAV, AAC…)",
  "Documents (PDF, DOCX, XLSX, PPTX…)",
  "PDFs Only (.pdf)",
  "Word Documents (.doc, .docx)",
  "Excel Spreadsheets (.xls, .xlsx)",
  "PowerPoint (.ppt, .pptx)",
  "Archives (ZIP, RAR, 7z, TAR…)",
  "Executables (.exe, .dll, .msi…)",
  "Code / Scripts (.py, .js, .html…)",
  "Fonts (.ttf, .otf, .woff…)",
  "3D Models (.obj, .fbx, .stl…)",
  "Databases (.db, .sqlite…)",
  "Images + Videos",
  "Media — All (Image+Video+Audio)"
];

// Built-in presets
const BUILTIN_PRESETS: Record<string, string[]> = {
  "Quick Scan (Basic)": [
    "File Name", "File Extension", "File Size (Human)",
    "Creation Date", "Modification Date", "MIME Type"
  ],
  "Forensics & Hashing": [
    "File Name", "File Path", "File Size (Bytes)", "File Size (Human)",
    "Creation Date", "Modification Date", "Access Date", "MD5 Hash",
    "SHA1 Hash", "SHA256 Hash", "File Entropy", "Magic Bytes (Header)", "MIME Type"
  ],
  "Photo Metadata (EXIF + GPS)": [
    "File Name", "File Size (Human)", "Date Taken (Original)", "Camera Make",
    "Camera Model", "Lens Model", "ISO", "Exposure Time", "F-Stop",
    "Image Width", "Image Height", "Megapixels", "GPS Latitude", "GPS Longitude", "GPS Altitude"
  ],
  "Video Analysis & Codecs": [
    "File Name", "File Size (Human)", "Video Duration", "Video Codec",
    "Video Bitrate", "Video Frame Rate", "Video Width", "Video Height",
    "Aspect Ratio", "Audio Codec (Video)", "Audio Channels (Video)", "Container Format", "Encoder"
  ],
  "Audio Library (ID3 Tags)": [
    "File Name", "Audio Title", "Audio Artist", "Audio Album", "Audio Album Artist",
    "Audio Genre", "Audio Year", "Audio Track Number", "Audio Duration", "Audio Bitrate",
    "Audio Sample Rate", "Audio Codec", "Has Album Art"
  ],
  "Document Index": [
    "File Name", "File Path", "File Size (Human)", "Document Title", "Document Author",
    "Document Subject", "Document Keywords", "Document Page Count", "Document Creation Date",
    "Document Modification Date", "MIME Type"
  ],
  "All Hashes (15 algorithms)": [
    "File Name", "File Path", "MD5 Hash", "SHA1 Hash", "SHA224 Hash", "SHA256 Hash",
    "SHA384 Hash", "SHA512 Hash", "SHA3-224 Hash", "SHA3-256 Hash", "SHA3-384 Hash",
    "SHA3-512 Hash", "BLAKE2b Hash", "BLAKE2s Hash", "CRC32", "Adler32", "xxHash64"
  ],
  "Everything (All 160+ fields)": [...ALL_FIELDS]
};

export const App: React.FC = () => {
  // Authentication & Verification
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [isVerifying, setIsVerifying] = useState<boolean>(true);

  // Core scan states
  const [folderPath, setFolderPath] = useState<string>("");
  const [folderStats, setFolderStats] = useState<string>("");
  const [hasSelectedFolder, setHasSelectedFolder] = useState<boolean>(false);
  const [fileFilter, setFileFilter] = useState<string>("All Files (*.*)");
  const [selectedPreset, setSelectedPreset] = useState<string>("builtin:Everything (All 160+ fields)");
  const [isRecursive, setIsRecursive] = useState<boolean>(true);
  const [includeHidden, setIncludeHidden] = useState<boolean>(false);
  const [exportFormat, setExportFormat] = useState<string>("excel_csv");

  // Field selection and sequence (defaults to all 174 fields)
  const [checkedFields, setCheckedFields] = useState<Set<string>>(new Set(ALL_FIELDS));
  const [sequence, setSequence] = useState<string[]>([...ALL_FIELDS]);
  const [activeCategory, setActiveCategory] = useState<string>("File System");
  const [fieldSearch, setFieldSearch] = useState<string>("");
  const [collapsedCategories, setCollapsedCategories] = useState<Set<string>>(new Set());

  // User custom presets
  const [userPresets, setUserPresets] = useState<Record<string, string[]>>({});

  // Drag and drop index tracker
  const [draggedIdx, setDraggedIdx] = useState<number | null>(null);

  // Scan hook
  const {
    scanId,
    isScanning,
    progress,
    results,
    startScan,
    cancelScan
  } = useScan();

  const fieldContainerRef = useRef<HTMLDivElement>(null);

  // Load custom presets from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem("bmep_user_presets") || localStorage.getItem("nexgen_user_presets");
      if (saved) setUserPresets(JSON.parse(saved));
    } catch (e) {
      console.warn("Could not read saved presets", e);
    }
  }, []);

  // Validate session on mount
  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem("nexgen_jwt");
      if (!token) {
        setIsAuthenticated(false);
        setIsVerifying(false);
        return;
      }

      try {
        const res = await api.get("/api/verify");
        if (res.data && res.data.sub) {
          setIsAuthenticated(true);
        } else {
          setIsAuthenticated(false);
        }
      } catch {
        setIsAuthenticated(false);
        localStorage.removeItem("nexgen_jwt");
      } finally {
        setIsVerifying(false);
      }
    };

    checkAuth();

    const handleAuthReset = () => setIsAuthenticated(false);
    window.addEventListener("nexgen_auth_reset", handleAuthReset);
    return () => window.removeEventListener("nexgen_auth_reset", handleAuthReset);
  }, []);

  // Auto-download export when scan completes
  useEffect(() => {
    if (progress && progress.status === "Completed" && scanId) {
      const fmt = exportFormat === "excel_csv" || exportFormat === "excel" ? "xlsx" : (exportFormat === "json" ? "json" : "csv");
      triggerExportDownload(scanId, fmt);
    }
  }, [progress?.status, scanId, exportFormat]);

  // Folder selection handler
  const handleSelectFolder = async () => {
    try {
      const data = await selectFolderApi();
      if (data && data.path) {
        setFolderPath(data.path);
        setFolderStats(`${data.files} files • ${data.size}`);
        setHasSelectedFolder(true);
      }
    } catch {
      // Fallback: prompt for evidence directory path if native dialog fails
      const path = prompt("Enter or paste target evidence directory:", "C:\\Evidence\\Case_2026_01");
      if (path && path.trim()) {
        setFolderPath(path.trim());
        setFolderStats("Directory configured");
        setHasSelectedFolder(true);
      }
    }
  };

  // Toggle single field
  const toggleField = (field: string) => {
    setCheckedFields((prev) => {
      const next = new Set(prev);
      if (next.has(field)) {
        next.delete(field);
        setSequence((seq) => seq.filter((f) => f !== field));
      } else {
        next.add(field);
        setSequence((seq) => (seq.includes(field) ? seq : [...seq, field]));
      }
      return next;
    });
  };

  // Select all fields in category
  const selectAllCategory = (cat: string) => {
    const catFields = FIELD_CATEGORIES[cat]?.fields || [];
    setCheckedFields((prev) => {
      const next = new Set(prev);
      catFields.forEach((f) => next.add(f));
      return next;
    });
    setSequence((prev) => {
      const added = catFields.filter((f) => !prev.includes(f));
      return [...prev, ...added];
    });
  };

  // Deselect all fields in category
  const selectNoneCategory = (cat: string) => {
    const catFields = FIELD_CATEGORIES[cat]?.fields || [];
    setCheckedFields((prev) => {
      const next = new Set(prev);
      catFields.forEach((f) => next.delete(f));
      return next;
    });
    setSequence((prev) => prev.filter((f) => !catFields.includes(f)));
  };

  // Toggle collapse state of category
  const toggleCategoryCollapse = (cat: string) => {
    setCollapsedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  };

  // Scroll to category section
  const scrollToCategorySection = (cat: string) => {
    setActiveCategory(cat);
    setCollapsedCategories((prev) => {
      const next = new Set(prev);
      next.delete(cat);
      return next;
    });
    setTimeout(() => {
      const section = document.querySelector(`[data-cat-section="${cat}"]`);
      if (section && fieldContainerRef.current) {
        section.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }, 50);
  };

  // Preset selection handler
  const handlePresetChange = (val: string) => {
    setSelectedPreset(val);
    if (!val) return;
    let fields: string[] = [];
    if (val.startsWith("builtin:")) {
      const name = val.substring(8);
      fields = BUILTIN_PRESETS[name] || [];
    } else if (val.startsWith("user:")) {
      const name = val.substring(5);
      fields = userPresets[name] || [];
    }
    setCheckedFields(new Set(fields));
    setSequence([...fields]);
  };

  // Save custom preset
  const handleSavePreset = () => {
    if (sequence.length === 0) {
      alert("Select some fields first before saving a preset.");
      return;
    }
    const name = prompt("Enter a name for this preset:");
    if (name && name.trim()) {
      const trimmed = name.trim();
      const updated = { ...userPresets, [trimmed]: [...sequence] };
      setUserPresets(updated);
      try {
        localStorage.setItem("nexgen_user_presets", JSON.stringify(updated));
        localStorage.setItem("bmep_user_presets", JSON.stringify(updated));
      } catch (e) {
        console.warn(e);
      }
      setSelectedPreset(`user:${trimmed}`);
      alert(`Preset "${trimmed}" saved!`);
    }
  };

  // Reset all
  const handleReset = () => {
    setCheckedFields(new Set());
    setSequence([]);
    setCollapsedCategories(new Set());
    setFieldSearch("");
    setSelectedPreset("");
  };

  // Select all 174+
  const handleSelectAllGlobally = () => {
    setCheckedFields(new Set(ALL_FIELDS));
    setSequence([...ALL_FIELDS]);
  };

  // Clear all
  const handleClearAllGlobally = () => {
    setCheckedFields(new Set());
    setSequence([]);
  };

  // Alphabetical sort for sequence
  const handleSortAlphabetical = () => {
    setSequence((prev) => [...prev].sort((a, b) => a.localeCompare(b)));
  };

  // Sequence item move
  const moveSequenceItem = (idx: number, delta: number) => {
    const target = idx + delta;
    if (target < 0 || target >= sequence.length) return;
    setSequence((prev) => {
      const copy = [...prev];
      const temp = copy[idx];
      copy[idx] = copy[target];
      copy[target] = temp;
      return copy;
    });
  };

  // Remove sequence item
  const removeSequenceItem = (field: string) => {
    setCheckedFields((prev) => {
      const next = new Set(prev);
      next.delete(field);
      return next;
    });
    setSequence((prev) => prev.filter((f) => f !== field));
  };

  // Drag and drop handlers
  const handleDragStart = (idx: number) => {
    setDraggedIdx(idx);
  };
  const handleDrop = (dropIdx: number) => {
    if (draggedIdx === null || draggedIdx === dropIdx) return;
    setSequence((prev) => {
      const copy = [...prev];
      const [moved] = copy.splice(draggedIdx, 1);
      copy.splice(dropIdx, 0, moved);
      return copy;
    });
    setDraggedIdx(null);
  };

  // Start extraction / scan
  const handleStartExtraction = async () => {
    if (!hasSelectedFolder || sequence.length === 0 || isScanning) return;
    try {
      await startScan({
        root_path: folderPath,
        recursive: isRecursive,
        include_hidden: includeHidden,
        selected_fields: sequence,
      });
    } catch (e) {
      console.error("Extraction start failed", e);
    }
  };

  // Compute active categories count
  const activeCategoryCount = useMemo(() => {
    let count = 0;
    for (const data of Object.values(FIELD_CATEGORIES)) {
      if (data.fields.some((f) => checkedFields.has(f))) count++;
    }
    return count;
  }, [checkedFields]);

  if (isVerifying) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-[#FFFDF5] text-amber-900 font-mono text-xs">
        <div className="w-12 h-12 rounded-2xl bg-amber-100 border border-amber-200 flex items-center justify-center animate-pulse mb-3">
          <ShieldCheck className="w-6 h-6 text-amber-800" />
        </div>
        <span className="font-semibold tracking-wider text-amber-950">
          VERIFYING AIR-GAPPED CRYPTOGRAPHIC LICENSE...
        </span>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <LoginView
        onAuthenticated={() => {
          setIsAuthenticated(true);
        }}
      />
    );
  }

  const currentPercent = progress ? Math.round(progress.percentage || 0) : 0;
  const currentStatusMsg = isScanning
    ? `Processing: ${progress?.current_file || "Extracting forensic artifacts..."}`
    : progress?.status === "Completed"
    ? `Completed successfully — ${progress?.scanned_files || 0} forensic files extracted`
    : hasSelectedFolder
    ? `Evidence directory selected — ${sequence.length} fields queued`
    : "Ready — select evidence directory and fields to begin";

  return (
    <div className="macos-mesh-bg font-body-md text-stone-900 antialiased select-none min-h-screen bg-[#FFFDF5]">
      {/* ═══════════════════ TOP HEADER ═══════════════════ */}
      <header className="fixed top-0 left-0 right-0 z-50 apple-glass shadow-[0_2px_16px_rgba(217,119,6,0.06)] border-b border-amber-200/70">
        {/* Row 1: Window Controls + Title + Evidence Directory Picker + Engine Status */}
        <div className="h-12 px-space-lg flex items-center justify-between border-b border-amber-100/60">
          <div className="flex items-center gap-space-md">
            <div className="flex items-center gap-2 pr-1">
              <div className="w-3 h-3 rounded-full bg-[#ff5f57] shadow-sm"></div>
              <div className="w-3 h-3 rounded-full bg-[#febc2e] shadow-sm"></div>
              <div className="w-3 h-3 rounded-full bg-[#28c840] shadow-sm"></div>
            </div>
            <div className="h-5 w-px bg-amber-200/60"></div>
            <div className="flex flex-col">
              <span className="font-headline-sm text-[15px] text-stone-900 font-bold tracking-tight leading-none">
                NexGen Metadata
              </span>
              <span className="text-[10px] text-amber-800 font-bold uppercase tracking-wider mt-0.5">
                Forensic Intelligence Suite
              </span>
            </div>
          </div>

          {/* Center: Evidence Directory Selection */}
          <div className="flex items-center gap-2 flex-1 max-w-xl mx-space-lg">
            <button
              id="btnSelectFolder"
              onClick={handleSelectFolder}
              className="h-8 px-3 rounded-lg bg-amber-200 text-amber-950 font-label-sm text-[12px] flex items-center gap-1.5 shadow-sm hover:bg-amber-300 transition-all apple-press font-semibold shrink-0 cursor-pointer border border-amber-300/80"
            >
              <span className="material-symbols-outlined text-[16px] text-amber-950">folder_open</span>
              Select Evidence Directory
            </button>
            <div
              className="flex items-center gap-2 bg-white/70 border border-amber-200/60 px-3 py-1 rounded-lg flex-1 min-w-0 shadow-[inset_0_1px_2px_rgba(0,0,0,0.02)]"
            >
              <span className="material-symbols-outlined text-amber-700 text-[16px] shrink-0">
                folder
              </span>
              <input
                type="text"
                value={hasSelectedFolder ? folderPath : ""}
                onChange={(e) => {
                  setFolderPath(e.target.value);
                  setHasSelectedFolder(!!e.target.value.trim());
                }}
                placeholder="e.g., C:\Evidence\Case_2026_01"
                aria-label="Target Directory"
                className="w-full bg-transparent font-mono-data text-[12px] text-stone-900 placeholder:text-stone-400 placeholder:italic outline-none"
              />
              {folderStats && (
                <span className="px-2 py-0.5 rounded bg-amber-100 text-amber-900 font-mono-data text-[11px] shrink-0 font-medium border border-amber-200">
                  {folderStats}
                </span>
              )}
            </div>
          </div>

          {/* Right: Engine Ready Badge */}
          <div className="flex items-center gap-3">
            <span className="px-2.5 py-1 rounded-full bg-amber-100 border border-amber-300 text-amber-900 font-label-sm text-[11px] flex items-center gap-1.5 font-semibold">
              <span className="w-2 h-2 rounded-full bg-amber-500 animate-pulse"></span>
              {isScanning ? "Extracting..." : "Engine Ready"}
            </span>
          </div>
        </div>

        {/* Row 2: File Filter + Preset + Toggles */}
        <div className="h-11 px-space-lg flex items-center justify-between gap-space-md bg-amber-50/40">
          <div className="flex items-center gap-space-md">
            <div className="flex items-center gap-1.5">
              <span className="font-label-sm text-[11px] text-stone-600 font-medium">
                Filter:
              </span>
              <select
                value={fileFilter}
                onChange={(e) => setFileFilter(e.target.value)}
                className="py-1 px-2 rounded-md bg-white/90 border border-amber-200 text-stone-800 font-body-sm text-[12px] outline-none focus:ring-1 focus:ring-amber-400 shadow-sm cursor-pointer"
              >
                {FILE_FILTERS.map((f) => (
                  <option key={f} value={f}>
                    {f}
                  </option>
                ))}
              </select>
            </div>
            <div className="h-4 w-px bg-amber-200/50"></div>
            <div className="flex items-center gap-1.5">
              <span className="font-label-sm text-[11px] text-stone-600 font-medium">
                Preset:
              </span>
              <select
                value={selectedPreset}
                onChange={(e) => handlePresetChange(e.target.value)}
                className="py-1 px-2.5 rounded-md bg-white/90 border border-amber-200 text-stone-800 font-body-sm text-[12px] font-medium outline-none focus:ring-1 focus:ring-amber-400 shadow-sm cursor-pointer"
              >
                <option value="">Select Preset...</option>
                <optgroup label="Built-in Presets">
                  {Object.keys(BUILTIN_PRESETS).map((name) => (
                    <option key={name} value={`builtin:${name}`}>
                      {name}
                    </option>
                  ))}
                </optgroup>
                {Object.keys(userPresets).length > 0 && (
                  <optgroup label="Custom Presets">
                    {Object.keys(userPresets).map((name) => (
                      <option key={name} value={`user:${name}`}>
                        {name}
                      </option>
                    ))}
                  </optgroup>
                )}
              </select>
              <button
                onClick={handleSavePreset}
                className="h-7 px-2.5 rounded-md bg-amber-100 border border-amber-300 text-amber-950 font-label-sm text-[11px] flex items-center gap-1 hover:bg-amber-200 transition-all shadow-sm apple-press font-semibold cursor-pointer"
              >
                <span className="material-symbols-outlined text-[14px]">bookmark_add</span>
                Save
              </button>
            </div>
            <div className="h-4 w-px bg-amber-200/50"></div>
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-1.5 cursor-pointer text-stone-800 font-label-sm text-[11px] font-medium select-none">
                <input
                  type="checkbox"
                  checked={isRecursive}
                  onChange={(e) => setIsRecursive(e.target.checked)}
                  className="w-3.5 h-3.5 rounded accent-amber-500 text-amber-600 focus:ring-amber-400 border-stone-300 cursor-pointer"
                />
                Recursive
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer text-stone-600 font-label-sm text-[11px] font-medium select-none">
                <input
                  type="checkbox"
                  checked={includeHidden}
                  onChange={(e) => setIncludeHidden(e.target.checked)}
                  className="w-3.5 h-3.5 rounded accent-amber-500 text-amber-600 focus:ring-amber-400 border-stone-300 cursor-pointer"
                />
                Hidden Files
              </label>
            </div>
          </div>
        </div>
      </header>

      {/* ═══════════════════ MAIN WORKSPACE ═══════════════════ */}
      <main className="w-full pt-28 pb-24 px-space-lg">
        <div className="max-w-[1680px] mx-auto grid grid-cols-1 xl:grid-cols-12 gap-space-lg items-start">
          {/* ═══ LEFT: METADATA FIELD SELECTOR (8 Cols) ═══ */}
          <section className="xl:col-span-8 flex flex-col apple-glass rounded-2xl overflow-hidden shadow-sm border border-amber-200/60">
            {/* Header: Title + Search + Controls */}
            <div className="px-4 py-3.5 border-b border-amber-200/60 flex flex-wrap items-center justify-between gap-3 bg-amber-50/30">
              <div className="flex items-center gap-2.5">
                <h2 className="font-headline-md text-headline-md text-stone-900 font-bold">
                  Metadata Fields
                </h2>
                <span className="font-label-sm text-[11px] font-bold text-amber-950 px-2.5 py-0.5 rounded-full bg-yellow-200 border border-yellow-300">
                  {ALL_FIELDS.length} fields • {Object.keys(FIELD_CATEGORIES).length} categories
                </span>
              </div>
              <div className="flex items-center gap-2 flex-1 max-w-md ml-auto">
                <div className="relative w-full">
                  <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-stone-400 text-[16px]">
                    search
                  </span>
                  <input
                    value={fieldSearch}
                    onChange={(e) => setFieldSearch(e.target.value)}
                    placeholder="Search 174+ fields..."
                    className="w-full pl-9 pr-4 py-1.5 rounded-xl bg-white/80 border border-amber-200/70 text-stone-900 font-body-sm text-[12px] placeholder:text-stone-400 outline-none focus:bg-white focus:ring-2 focus:ring-amber-300 shadow-[inset_0_1px_2px_rgba(0,0,0,0.02)] transition-all"
                    type="text"
                  />
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <button
                    onClick={() => setCollapsedCategories(new Set())}
                    className="px-2.5 py-1 rounded-lg bg-white/80 hover:bg-white text-stone-700 font-label-sm text-[11px] border border-amber-200 shadow-sm apple-press cursor-pointer"
                    title="Expand All"
                  >
                    <span className="material-symbols-outlined text-[14px]">unfold_more</span>
                  </button>
                  <button
                    onClick={() => setCollapsedCategories(new Set(Object.keys(FIELD_CATEGORIES)))}
                    className="px-2.5 py-1 rounded-lg bg-white/80 hover:bg-white text-stone-700 font-label-sm text-[11px] border border-amber-200 shadow-sm apple-press cursor-pointer"
                    title="Collapse All"
                  >
                    <span className="material-symbols-outlined text-[14px]">unfold_less</span>
                  </button>
                  <button
                    onClick={handleReset}
                    className="px-2.5 py-1 rounded-lg bg-red-50 hover:bg-red-100 text-red-700 font-label-sm text-[11px] border border-red-200 shadow-sm apple-press flex items-center gap-1 cursor-pointer"
                  >
                    <span className="material-symbols-outlined text-[14px]">restart_alt</span>
                    Reset
                  </button>
                </div>
              </div>
            </div>

            {/* Split Pane: Category Rail + Field Cards */}
            <div className="flex flex-col lg:flex-row min-h-[580px]">
              {/* Category Rail (w-56) */}
              <div className="w-full lg:w-56 p-3 bg-stone-50/60 border-b lg:border-b-0 lg:border-r border-amber-200/60 flex flex-col shrink-0">
                <div className="flex items-center justify-between px-2 pb-2 mb-1 border-b border-amber-200/50">
                  <span className="font-label-sm text-[10px] uppercase tracking-wider text-stone-500 font-bold">
                    Categories
                  </span>
                  <span className="font-mono-data text-[10px] text-amber-950 font-bold px-1.5 py-0.5 rounded bg-yellow-200 border border-yellow-300">
                    {activeCategoryCount} Active
                  </span>
                </div>
                <nav className="flex flex-col gap-1">
                  {Object.entries(FIELD_CATEGORIES).map(([cat, data]) => {
                    const checkedCount = data.fields.filter((f) => checkedFields.has(f)).length;
                    const totalCount = data.fields.length;
                    const isActive = cat === activeCategory;
                    return (
                      <button
                        key={cat}
                        onClick={() => scrollToCategorySection(cat)}
                        className={`flex items-center justify-between px-2.5 py-2 rounded-xl font-label-sm text-[12px] font-medium transition-all text-left cursor-pointer ${
                          isActive
                            ? "cat-nav-active bg-yellow-200 text-slate-900 shadow-sm border border-yellow-300 font-semibold"
                            : "text-stone-700 bg-white/60 hover:bg-white border border-stone-200/60"
                        }`}
                      >
                        <span className="flex items-center gap-2 truncate">
                          <span
                            className={`material-symbols-outlined text-[16px] cat-icon ${
                              isActive ? "text-amber-800" : "text-stone-500"
                            }`}
                          >
                            {data.icon}
                          </span>
                          <span className="truncate">{cat}</span>
                        </span>
                        <span
                          className={`font-mono-data text-[10px] px-1.5 py-0.5 rounded-md cat-count-badge shrink-0 ${
                            isActive
                              ? "bg-amber-100/90 text-amber-950 border border-amber-300/60"
                              : "bg-stone-100 text-stone-600"
                          } font-semibold`}
                        >
                          {checkedCount}/{totalCount}
                        </span>
                      </button>
                    );
                  })}
                </nav>
                <div className="pt-2 mt-auto border-t border-amber-200/50 flex flex-col gap-1.5">
                  <button
                    onClick={handleSelectAllGlobally}
                    className="w-full py-1.5 rounded-lg bg-yellow-100 hover:bg-yellow-200 text-amber-950 font-label-sm text-[11px] font-semibold border border-yellow-300/70 transition-all flex items-center justify-center gap-1 cursor-pointer"
                  >
                    <span className="material-symbols-outlined text-[14px]">done_all</span>
                    Select All {ALL_FIELDS.length}+
                  </button>
                  <button
                    onClick={handleClearAllGlobally}
                    className="w-full py-1.5 rounded-lg bg-white hover:bg-stone-50 text-stone-700 font-label-sm text-[11px] border border-stone-200 transition-all cursor-pointer"
                  >
                    Clear Selection
                  </button>
                </div>
              </div>

              {/* Middle Sub-Pane: Field Cards Container */}
              <div
                ref={fieldContainerRef}
                className="flex-1 p-4 overflow-y-auto max-h-[640px] flex flex-col gap-4 bg-white/40"
              >
                {Object.entries(FIELD_CATEGORIES).map(([cat, data]) => {
                  const query = fieldSearch.toLowerCase().trim();
                  const visibleFields = query
                    ? data.fields.filter((f) => f.toLowerCase().includes(query))
                    : data.fields;

                  if (query && visibleFields.length === 0) return null;

                  const checkedCount = data.fields.filter((f) => checkedFields.has(f)).length;
                  const totalCount = data.fields.length;
                  const isCollapsed = collapsedCategories.has(cat);

                  return (
                    <div
                      key={cat}
                      data-cat-section={cat}
                      className="rounded-xl apple-glass-subtle p-3.5 border border-amber-200/50 shadow-sm"
                    >
                      <div className="flex items-center justify-between pb-2.5 mb-2.5 border-b border-amber-200/40">
                        <div className="flex items-center gap-2">
                          <span className="text-[16px]">{data.emoji}</span>
                          <span className="font-headline-sm text-[14px] text-stone-900 font-bold">
                            {cat}
                          </span>
                          <span className="px-2 py-0.5 rounded-full bg-yellow-100 text-amber-950 font-mono-data text-[10px] font-bold border border-yellow-200">
                            {checkedCount}/{totalCount} active
                          </span>
                        </div>
                        <div className="flex items-center gap-2 text-[11px]">
                          <button
                            type="button"
                            onClick={() => selectAllCategory(cat)}
                            className="text-amber-800 hover:text-amber-950 hover:underline font-semibold cursor-pointer"
                          >
                            All
                          </button>
                          <span className="text-stone-300">•</span>
                          <button
                            type="button"
                            onClick={() => selectNoneCategory(cat)}
                            className="text-stone-500 hover:text-stone-700 hover:underline cursor-pointer"
                          >
                            None
                          </button>
                          <span
                            onClick={() => toggleCategoryCollapse(cat)}
                            className={`material-symbols-outlined text-[16px] text-stone-500 cursor-pointer transition-transform ${
                              isCollapsed ? "rotate-180" : ""
                            }`}
                          >
                            expand_less
                          </span>
                        </div>
                      </div>

                      {/* 2-Column Grid of Field Cards */}
                      <div
                        className={`grid grid-cols-1 md:grid-cols-2 gap-2 ${
                          isCollapsed ? "category-fields-hidden" : ""
                        }`}
                      >
                        {visibleFields.map((field) => {
                          const isChecked = checkedFields.has(field);
                          return (
                            <div
                              key={field}
                              onClick={() => toggleField(field)}
                              className={`apple-glass-card flex items-center justify-between p-2.5 rounded-xl cursor-pointer hover:bg-white transition-all ${
                                isChecked ? "field-checked border-amber-300/80 bg-yellow-50/50" : "border-stone-200/70"
                              }`}
                            >
                              <div className="flex items-center gap-2.5 min-w-0">
                                <div
                                  className={`w-4 h-4 rounded flex items-center justify-center shrink-0 shadow-sm cb-box ${
                                    isChecked
                                      ? "bg-yellow-200 border border-amber-400 text-slate-900"
                                      : "border border-stone-300 bg-white/90"
                                  }`}
                                >
                                  {isChecked && (
                                    <span className="material-symbols-outlined text-[13px] font-bold text-slate-900 cb-check">
                                      check
                                    </span>
                                  )}
                                </div>
                                <span
                                  className={`font-body-md text-[12.5px] truncate field-name ${
                                    isChecked ? "font-semibold text-slate-900" : "font-medium text-stone-700"
                                  }`}
                                >
                                  {field}
                                </span>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </section>

          {/* ═══ RIGHT: COLUMN SEQUENCE + PREVIEW (4 Cols) ═══ */}
          <section className="xl:col-span-4 flex flex-col gap-space-md">
            {/* Column Sequence Card */}
            <div className="apple-glass rounded-2xl p-space-lg flex flex-col gap-3 shadow-sm border border-amber-200/60">
              <div className="flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="font-headline-md text-headline-md text-stone-900 font-bold">
                      Column Sequence
                    </h2>
                    <span className="px-2.5 py-0.5 rounded-full bg-yellow-200 text-slate-900 border border-yellow-300 font-mono-data text-[11px] font-bold shadow-sm">
                      {sequence.length} selected
                    </span>
                  </div>
                  <p className="font-body-sm text-body-sm text-stone-500 mt-0.5">
                    Drag to rearrange output columns.
                  </p>
                </div>
                <button
                  onClick={handleSortAlphabetical}
                  className="w-8 h-8 rounded-xl bg-white/80 border border-amber-200/80 flex items-center justify-center text-stone-600 hover:text-amber-800 hover:bg-white shadow-sm transition-all apple-press cursor-pointer"
                  title="Alphabetical Sort"
                >
                  <span className="material-symbols-outlined text-[17px]">
                    sort_by_alpha
                  </span>
                </button>
              </div>

              {/* Draggable Sequence List */}
              <ul className="flex flex-col gap-2 max-h-[580px] overflow-y-auto pr-1 select-none">
                {sequence.length === 0 ? (
                  <li className="text-center py-8 text-stone-400 font-body-sm text-[12px]">
                    <span className="material-symbols-outlined text-[28px] block mb-2 opacity-40">
                      playlist_add
                    </span>
                    Check fields on the left to add columns
                  </li>
                ) : (
                  sequence.map((field, idx) => {
                    const cat = FIELD_TO_CATEGORY[field] || "";
                    return (
                      <li
                        key={field}
                        draggable
                        onDragStart={() => handleDragStart(idx)}
                        onDragOver={(e) => e.preventDefault()}
                        onDrop={() => handleDrop(idx)}
                        className={`apple-glass-card flex items-center justify-between p-2.5 rounded-xl cursor-grab active:cursor-grabbing group shadow-sm seq-item border border-stone-200/70 hover:border-amber-300 ${
                          draggedIdx === idx ? "drag-ghost" : ""
                        }`}
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="material-symbols-outlined text-stone-400 text-[18px] group-hover:text-amber-600 transition-colors">
                            drag_indicator
                          </span>
                          <span className="font-mono-data text-mono-data text-amber-800 font-bold w-5">
                            {idx + 1}.
                          </span>
                          <span className="font-body-md text-body-md text-stone-800 font-semibold truncate">
                            {field}
                          </span>
                          <span className="px-2 py-0.5 rounded-md bg-stone-100 border border-stone-200 text-stone-600 font-label-sm text-[10px] font-medium hidden md:inline">
                            {cat}
                          </span>
                        </div>
                        <div className="flex items-center gap-0.5">
                          <button
                            onClick={() => moveSequenceItem(idx, -1)}
                            className="text-stone-400 hover:text-amber-700 p-1 rounded hover:bg-stone-100 cursor-pointer"
                            title="Move Up"
                          >
                            <span className="material-symbols-outlined text-[15px]">
                              arrow_upward
                            </span>
                          </button>
                          <button
                            onClick={() => moveSequenceItem(idx, 1)}
                            className="text-stone-400 hover:text-amber-700 p-1 rounded hover:bg-stone-100 cursor-pointer"
                            title="Move Down"
                          >
                            <span className="material-symbols-outlined text-[15px]">
                              arrow_downward
                            </span>
                          </button>
                          <button
                            onClick={() => removeSequenceItem(field)}
                            className="text-stone-400 hover:text-red-600 p-1 rounded hover:bg-red-50 cursor-pointer"
                            title="Remove"
                          >
                            <span className="material-symbols-outlined text-[15px]">
                              close
                            </span>
                          </button>
                        </div>
                      </li>
                    );
                  })
                )}
              </ul>

              <div className="pt-2 flex items-center justify-end border-t border-amber-200/40">
                <button
                  onClick={handleClearAllGlobally}
                  className="text-red-600 hover:underline flex items-center gap-1 text-[11px] cursor-pointer"
                >
                  <span className="material-symbols-outlined text-[14px]">
                    delete_sweep
                  </span>
                  Clear Sequence
                </button>
              </div>
            </div>

          </section>
        </div>
      </main>

      {/* ═══════════════════ BOTTOM FOOTER ═══════════════════ */}
      <footer className="fixed bottom-0 left-0 right-0 h-16 apple-glass z-50 flex items-center px-space-lg justify-between shadow-[0_-4px_24px_rgba(217,119,6,0.05)] border-t border-amber-200/70">
        {/* Status + Progress */}
        <div className="flex flex-col gap-1 flex-1 max-w-xl">
          <div className="flex items-center justify-between font-body-sm text-[12px]">
            <span className="text-stone-800 font-medium flex items-center gap-2 truncate">
              <span
                className={`w-2 h-2 rounded-full ${
                  isScanning
                    ? "bg-amber-500 animate-pulse shadow-[0_0_8px_rgba(245,158,11,0.7)]"
                    : progress?.status === "Completed"
                    ? "bg-emerald-500 shadow-[0_0_8px_rgba(40,200,64,0.5)]"
                    : "bg-emerald-500 shadow-[0_0_8px_rgba(40,200,64,0.5)]"
                }`}
              ></span>
              <span className="truncate">{currentStatusMsg}</span>
            </span>
            <span className="font-mono-data text-mono-data font-bold text-amber-900 ml-2">
              {currentPercent}%
            </span>
          </div>
          <div className="w-full h-1.5 rounded-full bg-stone-200/80 overflow-hidden border border-amber-100">
            <div
              style={{ width: `${currentPercent}%` }}
              className="h-full bg-gradient-to-r from-amber-400 to-yellow-300 rounded-full transition-all duration-300"
            ></div>
          </div>
        </div>

        {/* Format Select + Cancel + Begin Extraction + Export Forensic Manifest */}
        <div className="flex items-center gap-space-md pl-space-xl">
          <div className="flex items-center gap-1.5">
            <span className="font-label-sm text-[11px] text-stone-600 font-medium">
              Format:
            </span>
            <select
              value={exportFormat}
              onChange={(e) => setExportFormat(e.target.value)}
              className="py-1.5 px-2.5 rounded-lg bg-white/80 border border-stone-200 text-stone-800 font-body-sm text-[12px] outline-none focus:ring-1 focus:ring-amber-400 shadow-sm cursor-pointer"
            >
              <option value="excel_csv">Excel + CSV (.xlsx, .csv)</option>
              <option value="excel">Excel Only (.xlsx)</option>
              <option value="csv">CSV Only (.csv)</option>
              <option value="json">JSON Structured (.json)</option>
              <option value="tsv">TSV (.tsv)</option>
            </select>
          </div>

          <button
            onClick={() => cancelScan()}
            disabled={!isScanning}
            className={`h-8 px-3.5 rounded-lg bg-white/70 border border-stone-200 text-stone-700 hover:bg-red-50 hover:text-red-700 transition-all apple-press shadow-sm text-[12px] font-medium ${
              isScanning ? "cursor-pointer" : "opacity-50 pointer-events-none"
            }`}
          >
            Cancel
          </button>

          <button
            onClick={handleStartExtraction}
            disabled={!hasSelectedFolder || sequence.length === 0 || isScanning}
            className={`h-9 px-4 rounded-xl bg-yellow-200 hover:bg-yellow-300 text-slate-900 font-headline-sm text-[13px] font-bold flex items-center gap-1.5 shadow-[0_2px_8px_rgba(202,138,4,0.2)] border border-yellow-300 transition-all apple-press ${
              hasSelectedFolder && sequence.length > 0 && !isScanning
                ? "cursor-pointer"
                : "opacity-50 pointer-events-none"
            }`}
          >
            <span className="material-symbols-outlined text-[17px] text-slate-900">play_circle</span>
            Begin Extraction
          </button>

          <button
            onClick={handleStartExtraction}
            disabled={!hasSelectedFolder || sequence.length === 0 || isScanning}
            className={`h-9 px-4 rounded-xl bg-amber-200 hover:bg-amber-300 text-amber-950 font-headline-sm text-[13px] font-bold flex items-center gap-1.5 shadow-[0_2px_10px_rgba(217,119,6,0.25)] border border-amber-300 transition-all apple-press ${
              hasSelectedFolder && sequence.length > 0 && !isScanning
                ? "cursor-pointer"
                : "opacity-50 pointer-events-none"
            }`}
          >
            <span className="material-symbols-outlined text-[17px] text-amber-950">download</span>
            Export Forensic Manifest
          </button>
        </div>
      </footer>
    </div>
  );
};
