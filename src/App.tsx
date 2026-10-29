import React, { useState, useEffect, useMemo } from "react";
import { api, triggerExportDownload } from "./api";
import { LoginView } from "./LoginView";
import { useScan } from "./hooks/useScan";
import { ColumnSequencer } from "./components/ColumnSequencer";
import { PreviewTable } from "./components/PreviewTable";
import { FIELD_DEFINITIONS } from "./types";
import {
  Folder,
  Play,
  Square,
  ShieldCheck,
  Search,
  CheckSquare,
  Square as EmptySquare,
  RotateCcw,
  Download,
  FileSpreadsheet,
  FileText,
  FileCode,
  Lock,
  Layers,
  Database,
  Binary,
  Hash,
  Eye,
  Camera,
  FileBox,
} from "lucide-react";

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  "File System": <Folder className="w-4 h-4" />,
  "Hashes": <Hash className="w-4 h-4" />,
  "NTFS & Forensics": <Database className="w-4 h-4" />,
  "Entropy & Magic": <Binary className="w-4 h-4" />,
  "EXIF & GPS": <Camera className="w-4 h-4" />,
  "PE Binaries": <FileBox className="w-4 h-4" />,
  "PDF Documents": <FileText className="w-4 h-4" />,
};

const DEFAULT_FIELDS = [
  "file_name",
  "file_extension",
  "size_human",
  "hash_blake3",
  "hash_sha256",
  "shannon_entropy",
  "magic_bytes_hex",
  "timestomp_suspect",
];

export const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [isVerifying, setIsVerifying] = useState<boolean>(true);
  const [customerName, setCustomerName] = useState<string>("");

  const [folderPath, setFolderPath] = useState<string>("");
  const [recursive, setRecursive] = useState<boolean>(true);
  const [includeHidden, setIncludeHidden] = useState<boolean>(false);

  // Active Category in Pane 1
  const [activeCategory, setActiveCategory] = useState<string>("File System");
  const [fieldSearch, setFieldSearch] = useState<string>("");

  // Selected Fields Set & Column Sequencer Order
  const [selectedFields, setSelectedFields] = useState<Set<string>>(
    new Set(DEFAULT_FIELDS)
  );
  const [columnOrder, setColumnOrder] = useState<string[]>(DEFAULT_FIELDS);

  const {
    scanId,
    isScanning,
    progress,
    results,
    error,
    startScan,
    cancelScan,
  } = useScan();

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
          setCustomerName(res.data.sub);
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

  const categories = useMemo(() => {
    const set = new Set<string>();
    FIELD_DEFINITIONS.forEach((f) => set.add(f.category));
    return Array.from(set);
  }, []);

  const filteredFields = useMemo(() => {
    const query = fieldSearch.trim().toLowerCase();
    if (query) {
      return FIELD_DEFINITIONS.filter(
        (f) =>
          f.label.toLowerCase().includes(query) ||
          f.key.toLowerCase().includes(query) ||
          f.description.toLowerCase().includes(query) ||
          f.category.toLowerCase().includes(query)
      );
    }
    return FIELD_DEFINITIONS.filter((f) => f.category === activeCategory);
  }, [activeCategory, fieldSearch]);

  const handleLogout = () => {
    localStorage.removeItem("nexgen_jwt");
    localStorage.removeItem("nexgen_customer");
    setIsAuthenticated(false);
  };

  const handleToggleField = (key: string) => {
    setSelectedFields((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
        setColumnOrder((order) => order.filter((k) => k !== key));
      } else {
        next.add(key);
        setColumnOrder((order) => [...order, key]);
      }
      return next;
    });
  };

  const handleCategorySelectAll = (category: string, selectAll: boolean) => {
    const catKeys = FIELD_DEFINITIONS.filter((f) => f.category === category).map(
      (f) => f.key
    );

    setSelectedFields((prev) => {
      const next = new Set(prev);
      catKeys.forEach((k) => {
        if (selectAll) next.add(k);
        else next.delete(k);
      });
      return next;
    });

    setColumnOrder((prev) => {
      if (selectAll) {
        const added = catKeys.filter((k) => !prev.includes(k));
        return [...prev, ...added];
      } else {
        return prev.filter((k) => !catKeys.includes(k));
      }
    });
  };

  const handleResetDefaults = () => {
    setSelectedFields(new Set(DEFAULT_FIELDS));
    setColumnOrder([...DEFAULT_FIELDS]);
  };

  const handleSelectAllGlobally = () => {
    const allKeys = FIELD_DEFINITIONS.map((f) => f.key);
    setSelectedFields(new Set(allKeys));
    setColumnOrder([...allKeys]);
  };

  const handleClearAllGlobally = () => {
    setSelectedFields(new Set());
    setColumnOrder([]);
  };

  const handleStartScan = async () => {
    if (!folderPath.trim()) return;
    try {
      await startScan({
        root_path: folderPath.trim(),
        recursive,
        include_hidden: includeHidden,
        selected_fields: Array.from(selectedFields),
      });
    } catch (e) {
      console.error("Start scan failed", e);
    }
  };

  const handleExport = (format: "csv" | "xlsx" | "json") => {
    if (!scanId) {
      alert("No active or completed scan available to export.");
      return;
    }
    triggerExportDownload(scanId, format);
  };

  if (isVerifying) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-[#F8F7FC] text-[#8B5CF6] font-mono text-xs">
        <div className="w-12 h-12 rounded-2xl bg-[#8B5CF6]/10 flex items-center justify-center animate-pulse mb-3">
          <ShieldCheck className="w-6 h-6 text-[#8B5CF6]" />
        </div>
        <span className="font-semibold tracking-wider">
          VERIFYING ED25519 CRYPTOGRAPHIC SESSION...
        </span>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <LoginView
        onAuthenticated={() => {
          setIsAuthenticated(true);
          const saved = localStorage.getItem("nexgen_customer");
          if (saved) setCustomerName(saved);
        }}
      />
    );
  }

  return (
    <div className="flex flex-col h-screen w-screen bg-[#F8F7FC] text-gray-800 font-sans select-none overflow-hidden">
      {/* ── TOP HEADER BAR ── */}
      <header className="px-5 py-2.5 bg-white border-b border-[#EDE9FE] flex items-center justify-between shadow-sm shrink-0">
        {/* Brand identity */}
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-xl bg-[#8B5CF6] hover:bg-[#7C3AED] transition-colors flex items-center justify-center text-white font-black text-sm shadow-sm shadow-purple-300">
            NX
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="font-black text-sm tracking-wide text-gray-900">
                NEXGEN METADATA
              </h1>
              <span className="px-2 py-0.5 rounded-full text-[9px] bg-emerald-50 text-emerald-700 font-bold border border-emerald-200">
                AIR-GAPPED LICENSE ACTIVE
              </span>
            </div>
            <p className="text-[10px] text-[#8B5CF6] font-semibold tracking-wider uppercase">
              {customerName ? `Licensed to: ${customerName}` : "Forensic Deep Inspection Suite"}
            </p>
          </div>
        </div>

        {/* Directory Input & Scan Execution */}
        <div className="flex items-center space-x-3 text-xs">
          <div className="relative">
            <input
              type="text"
              value={folderPath}
              onChange={(e) => setFolderPath(e.target.value)}
              placeholder="Target Directory (e.g. C:\Evidence or /data/cases)"
              disabled={isScanning}
              className="w-80 pl-8 pr-3 py-1.5 bg-[#F8F7FC] border border-[#DDD6FE] focus:border-[#8B5CF6] focus:bg-white focus:outline-none focus:ring-2 focus:ring-[#8B5CF6]/20 rounded-lg text-xs font-mono text-gray-800 shadow-inner transition-all"
            />
            <Folder className="w-3.5 h-3.5 text-gray-400 absolute left-2.5 top-2.5 pointer-events-none" />
          </div>

          <label className="flex items-center space-x-1.5 text-gray-600 hover:text-gray-900 cursor-pointer text-xs font-medium">
            <input
              type="checkbox"
              checked={recursive}
              disabled={isScanning}
              onChange={(e) => setRecursive(e.target.checked)}
              className="w-3.5 h-3.5 rounded text-[#8B5CF6] focus:ring-[#8B5CF6] accent-[#8B5CF6]"
            />
            <span>Recursive</span>
          </label>

          <label className="flex items-center space-x-1.5 text-gray-600 hover:text-gray-900 cursor-pointer text-xs font-medium">
            <input
              type="checkbox"
              checked={includeHidden}
              disabled={isScanning}
              onChange={(e) => setIncludeHidden(e.target.checked)}
              className="w-3.5 h-3.5 rounded text-[#8B5CF6] focus:ring-[#8B5CF6] accent-[#8B5CF6]"
            />
            <span>Hidden Files</span>
          </label>

          {isScanning ? (
            <button
              onClick={cancelScan}
              className="flex items-center space-x-1.5 px-4 py-1.5 bg-rose-600 hover:bg-rose-700 text-white font-bold rounded-lg shadow-sm transition-all cursor-pointer animate-pulse"
            >
              <Square className="w-3 h-3 fill-current" />
              <span>Cancel Scan</span>
            </button>
          ) : (
            <button
              onClick={handleStartScan}
              disabled={!folderPath.trim()}
              className={`flex items-center space-x-1.5 px-5 py-1.5 font-bold rounded-lg shadow-sm transition-all text-white ${
                folderPath.trim()
                  ? "bg-[#8B5CF6] hover:bg-[#7C3AED] shadow-purple-200 cursor-pointer active:scale-95"
                  : "bg-gray-300 cursor-not-allowed"
              }`}
            >
              <Play className="w-3 h-3 fill-current" />
              <span>Start Scan</span>
            </button>
          )}

          <button
            onClick={handleLogout}
            title="Deactivate / Change License Key"
            className="p-1.5 text-gray-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors"
          >
            <Lock className="w-3.5 h-3.5" />
          </button>
        </div>
      </header>

      {/* ── REAL-TIME SCAN PROGRESS BANNER ── */}
      {isScanning && progress && (
        <div className="bg-purple-50/70 border-b border-purple-100 px-5 py-2 flex items-center justify-between text-xs text-purple-950 shrink-0">
          <div className="flex items-center space-x-3 w-1/2">
            <div className="w-3.5 h-3.5 border-2 border-[#8B5CF6] border-t-transparent rounded-full animate-spin shrink-0" />
            <span className="font-mono text-[11px] truncate text-purple-900">
              {progress.current_file || "Traversing disk..."}
            </span>
          </div>

          <div className="flex items-center space-x-4 font-mono text-[11px]">
            <div className="w-32 bg-purple-200 rounded-full h-2 overflow-hidden">
              <div
                className="bg-[#8B5CF6] h-full transition-all duration-300 rounded-full"
                style={{ width: `${Math.min(100, Math.max(0, progress.percentage))}%` }}
              />
            </div>
            <span>
              {progress.scanned_files} / {progress.total_files} ({progress.percentage.toFixed(1)}%)
            </span>
            <span>Errors: {progress.errors}</span>
            <span>{(progress.elapsed_ms / 1000).toFixed(1)}s</span>
          </div>
        </div>
      )}

      {/* ── MAIN 3-PANE CONFIGURATION & SEQUENCER ── */}
      <main className="flex-1 flex px-5 py-3 gap-3 min-h-0 overflow-hidden">
        {/* PANE 1: Categories Navigator (20% width) */}
        <section className="w-[20%] flex flex-col bg-white rounded-xl border border-[#EDE9FE] shadow-sm overflow-hidden">
          <div className="p-2.5 border-b border-[#EDE9FE] bg-[#F8F7FC] flex items-center justify-between">
            <div className="flex items-center space-x-1.5 text-xs font-bold text-gray-800">
              <Layers className="w-3.5 h-3.5 text-[#8B5CF6]" />
              <span>Categories</span>
            </div>
            <span className="px-2 py-0.5 rounded-full text-[10px] bg-purple-100 text-[#8B5CF6] font-bold">
              {selectedFields.size} active
            </span>
          </div>

          {/* Master bulk toggles */}
          <div className="p-2 border-b border-[#EDE9FE] bg-white flex justify-between text-[11px] text-gray-500">
            <button
              onClick={handleSelectAllGlobally}
              className="text-[#8B5CF6] hover:underline font-semibold"
            >
              Select All (200+)
            </button>
            <span className="text-gray-300">•</span>
            <button
              onClick={handleClearAllGlobally}
              className="hover:text-rose-600 font-semibold"
            >
              Clear All
            </button>
            <span className="text-gray-300">•</span>
            <button
              onClick={handleResetDefaults}
              className="hover:text-[#8B5CF6] font-semibold"
            >
              Default (8)
            </button>
          </div>

          {/* Category List */}
          <div className="flex-1 overflow-y-auto p-1.5 space-y-1">
            {categories.map((cat) => {
              const catTotal = FIELD_DEFINITIONS.filter((f) => f.category === cat).length;
              const catSelected = FIELD_DEFINITIONS.filter(
                (f) => f.category === cat && selectedFields.has(f.key)
              ).length;
              const isActive = activeCategory === cat && !fieldSearch;

              return (
                <div
                  key={cat}
                  onClick={() => {
                    setActiveCategory(cat);
                    setFieldSearch("");
                  }}
                  className={`flex items-center justify-between p-2 rounded-lg cursor-pointer transition-all text-xs font-medium ${
                    isActive
                      ? "bg-[#8B5CF6] text-white shadow-sm font-semibold"
                      : "text-gray-700 hover:bg-[#F8F7FC]"
                  }`}
                >
                  <div className="flex items-center space-x-2 truncate">
                    <span className={isActive ? "text-white" : "text-[#8B5CF6]"}>
                      {CATEGORY_ICONS[cat] || <Folder className="w-4 h-4" />}
                    </span>
                    <span className="truncate">{cat}</span>
                  </div>

                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                      isActive
                        ? "bg-white/20 text-white font-bold"
                        : catSelected > 0
                        ? "bg-purple-100 text-[#8B5CF6] font-bold"
                        : "text-gray-400"
                    }`}
                  >
                    {catSelected}/{catTotal}
                  </span>
                </div>
              );
            })}
          </div>
        </section>

        {/* PANE 2: Available Fields Checklist (45% width) */}
        <section className="w-[45%] flex flex-col bg-white rounded-xl border border-[#EDE9FE] shadow-sm overflow-hidden">
          {/* Header & Search */}
          <div className="p-2.5 border-b border-[#EDE9FE] bg-[#F8F7FC] flex items-center justify-between gap-2">
            <div className="flex items-center space-x-2">
              <span className="text-xs font-bold text-gray-800">
                {fieldSearch ? "Search Results" : activeCategory}
              </span>
              <span className="text-[11px] text-gray-400">
                ({filteredFields.length} available)
              </span>
            </div>

            <div className="relative w-48">
              <input
                type="text"
                placeholder="Search 200+ fields..."
                value={fieldSearch}
                onChange={(e) => setFieldSearch(e.target.value)}
                className="w-full pl-7 pr-2.5 py-1 text-xs bg-white border border-[#DDD6FE] rounded-lg focus:outline-none focus:ring-1 focus:ring-[#8B5CF6] focus:border-[#8B5CF6] shadow-inner text-gray-800"
              />
              <Search className="w-3 h-3 text-gray-400 absolute left-2 top-2 pointer-events-none" />
            </div>
          </div>

          {/* Quick Select Actions for current view */}
          {!fieldSearch && (
            <div className="px-3 py-1.5 border-b border-[#EDE9FE] bg-white flex justify-between items-center text-[11px] text-gray-500">
              <span>Toggle fields for active category:</span>
              <div className="space-x-2">
                <button
                  onClick={() => handleCategorySelectAll(activeCategory, true)}
                  className="text-[#8B5CF6] hover:underline font-semibold"
                >
                  Select All
                </button>
                <span>•</span>
                <button
                  onClick={() => handleCategorySelectAll(activeCategory, false)}
                  className="text-gray-400 hover:text-gray-700 font-semibold"
                >
                  Clear Category
                </button>
              </div>
            </div>
          )}

          {/* Fields Checklist */}
          <div className="flex-1 overflow-y-auto p-2 space-y-1 divide-y divide-gray-50">
            {filteredFields.map((field) => {
              const isChecked = selectedFields.has(field.key);
              return (
                <div
                  key={field.key}
                  onClick={() => handleToggleField(field.key)}
                  className={`p-2 rounded-lg cursor-pointer transition-all flex items-start space-x-2.5 ${
                    isChecked
                      ? "bg-purple-50/50 border border-[#EDE9FE]"
                      : "hover:bg-[#F8F7FC] border border-transparent"
                  }`}
                >
                  <div className="mt-0.5 text-[#8B5CF6]">
                    {isChecked ? (
                      <CheckSquare className="w-4 h-4 fill-[#8B5CF6] text-white" />
                    ) : (
                      <EmptySquare className="w-4 h-4 text-gray-300" />
                    )}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <span
                        className={`text-xs font-semibold ${
                          isChecked ? "text-gray-900" : "text-gray-700"
                        }`}
                      >
                        {field.label}
                      </span>
                      <span className="font-mono text-[9px] text-gray-400 px-1 bg-gray-100 rounded">
                        {field.key}
                      </span>
                    </div>
                    <p className="text-[11px] text-gray-500 leading-tight mt-0.5 truncate">
                      {field.description}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* PANE 3: Column Sequencer & Active Export Schema (35% width) */}
        <section className="w-[35%] flex flex-col bg-white rounded-xl border border-[#EDE9FE] shadow-sm overflow-hidden">
          <ColumnSequencer
            columns={columnOrder}
            onReorder={setColumnOrder}
            onRemove={handleToggleField}
            onReset={handleResetDefaults}
          />
        </section>
      </main>

      {/* ── BOTTOM LIVE PREVIEW & EXPORT DOCK ── */}
      <section className="h-[32vh] px-5 pb-2 min-h-[190px] flex flex-col shrink-0">
        <PreviewTable
          data={results}
          columns={columnOrder}
          isLoading={isScanning}
          scanId={scanId || undefined}
        />
      </section>

      {/* ── FOOTER STATUS & EXPORT CONTROLS ── */}
      <footer className="px-5 py-2 bg-white border-t border-[#EDE9FE] flex items-center justify-between text-xs shrink-0 shadow-sm">
        <div className="flex items-center space-x-3 text-gray-500">
          <div className="flex items-center space-x-1.5">
            <span
              className={`w-2 h-2 rounded-full ${
                isScanning
                  ? "bg-[#8B5CF6] animate-ping"
                  : results.length > 0
                  ? "bg-emerald-500"
                  : "bg-gray-300"
              }`}
            />
            <span className="font-bold text-gray-800">
              {isScanning
                ? "Scan in progress..."
                : results.length > 0
                ? `${results.length.toLocaleString()} files indexed`
                : "Engine ready"}
            </span>
          </div>

          {scanId && (
            <span className="font-mono text-[10px] text-[#8B5CF6] bg-purple-50 px-2 py-0.5 rounded border border-purple-100">
              SCAN-ID: {scanId}
            </span>
          )}

          {error && (
            <span className="text-rose-600 font-semibold text-xs">
              ⚠️ {error}
            </span>
          )}
        </div>

        {/* Export Buttons */}
        <div className="flex items-center space-x-2">
          <span className="text-xs font-bold text-gray-600 mr-1 flex items-center space-x-1">
            <Download className="w-3.5 h-3.5 text-[#8B5CF6]" />
            <span>Export Dataset:</span>
          </span>

          <button
            onClick={() => handleExport("csv")}
            disabled={!scanId || results.length === 0}
            className="flex items-center space-x-1 px-3 py-1 bg-white hover:bg-[#F8F7FC] text-gray-700 hover:text-[#8B5CF6] font-semibold rounded-lg border border-[#EDE9FE] hover:border-[#8B5CF6] transition-all disabled:opacity-40 disabled:cursor-not-allowed shadow-2xs"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-600" />
            <span>CSV</span>
          </button>

          <button
            onClick={() => handleExport("xlsx")}
            disabled={!scanId || results.length === 0}
            className="flex items-center space-x-1 px-3 py-1 bg-white hover:bg-[#F8F7FC] text-gray-700 hover:text-[#8B5CF6] font-semibold rounded-lg border border-[#EDE9FE] hover:border-[#8B5CF6] transition-all disabled:opacity-40 disabled:cursor-not-allowed shadow-2xs"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-blue-600" />
            <span>Excel (.xlsx)</span>
          </button>

          <button
            onClick={() => handleExport("json")}
            disabled={!scanId || results.length === 0}
            className="flex items-center space-x-1 px-3 py-1 bg-white hover:bg-[#F8F7FC] text-gray-700 hover:text-[#8B5CF6] font-semibold rounded-lg border border-[#EDE9FE] hover:border-[#8B5CF6] transition-all disabled:opacity-40 disabled:cursor-not-allowed shadow-2xs"
          >
            <FileCode className="w-3.5 h-3.5 text-amber-600" />
            <span>JSON + Manifest</span>
          </button>
        </div>
      </footer>
    </div>
  );
};
