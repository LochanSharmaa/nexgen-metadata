import React, { useState, useEffect } from "react";
import { api, triggerExportDownload } from "./api";
import { LoginView } from "./LoginView";
import { useScan } from "./hooks/useScan";
import { FieldSelector } from "./components/FieldSelector";
import { ColumnSequencer } from "./components/ColumnSequencer";
import { PreviewTable } from "./components/PreviewTable";
import { FIELD_DEFINITIONS } from "./types";

export const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [isVerifying, setIsVerifying] = useState<boolean>(true);
  const [customerName, setCustomerName] = useState<string>("");

  const [folderPath, setFolderPath] = useState<string>("");
  const [recursive, setRecursive] = useState<boolean>(true);
  const [includeHidden, setIncludeHidden] = useState<boolean>(false);

  // Default selected fields
  const [selectedFields, setSelectedFields] = useState<Set<string>>(
    new Set([
      "file_name",
      "file_extension",
      "size_human",
      "hash_blake3",
      "hash_sha256",
      "shannon_entropy",
      "magic_bytes_hex",
      "timestomp_suspect",
    ])
  );

  const [columnOrder, setColumnOrder] = useState<string[]>([
    "file_name",
    "file_extension",
    "size_human",
    "hash_blake3",
    "hash_sha256",
    "shannon_entropy",
    "magic_bytes_hex",
    "timestomp_suspect",
  ]);

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

    // Listen for 401 unauth resets
    const handleAuthReset = () => setIsAuthenticated(false);
    window.addEventListener("nexgen_auth_reset", handleAuthReset);
    return () => window.removeEventListener("nexgen_auth_reset", handleAuthReset);
  }, []);

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

  const handleSelectCategory = (category: string, selectAll: boolean) => {
    const catKeys = FIELD_DEFINITIONS.filter(
      (f) => f.category === category
    ).map((f) => f.key);

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
        return prev.filter((k) => !catKeys.includes(k as any));
      }
    });
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

  // If loading session state, show loading spinner
  if (isVerifying) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-[#0d0914] text-purple-300 font-mono text-xs">
        <span className="animate-pulse">VERIFYING ED25519 CRYPTOGRAPHIC SESSION...</span>
      </div>
    );
  }

  // License Key Gate
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
    <div className="flex flex-col h-screen w-screen bg-gradient-to-br from-purple-50 via-white to-indigo-50 text-gray-800 font-sans select-none overflow-hidden">
      {/* Top Header Bar */}
      <header className="px-6 py-3 bg-white/70 backdrop-blur-md border-b border-purple-100 flex items-center justify-between shadow-sm">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-lg bg-[#630ed4] flex items-center justify-center text-white font-extrabold text-sm shadow">
            NX
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="font-extrabold text-sm tracking-wide text-gray-900">
                NEXGEN METADATA
              </h1>
              <span className="px-2 py-0.5 rounded-full text-[9px] bg-green-100 text-green-700 font-bold border border-green-200">
                AIR-GAPPED LICENSE ACTIVE
              </span>
            </div>
            <p className="text-[10px] text-purple-700 font-semibold tracking-wider uppercase">
              {customerName ? `Licensed to: ${customerName}` : "Forensic Deep Inspection Suite"}
            </p>
          </div>
        </div>

        {/* Directory Input & Controls */}
        <div className="flex items-center space-x-3 text-xs">
          <input
            type="text"
            value={folderPath}
            onChange={(e) => setFolderPath(e.target.value)}
            placeholder="Target Path (e.g. C:\Cases\Evidence01 or /Volumes/Case1)"
            disabled={isScanning}
            className="w-72 px-3 py-1.5 bg-white border border-purple-200 focus:outline-none focus:ring-2 focus:ring-[#630ed4] rounded-lg text-xs font-mono text-gray-800 shadow-inner"
          />

          <label className="flex items-center space-x-1 text-gray-600 cursor-pointer">
            <input
              type="checkbox"
              checked={recursive}
              disabled={isScanning}
              onChange={(e) => setRecursive(e.target.checked)}
              className="rounded text-[#630ed4] focus:ring-[#630ed4]"
            />
            <span>Recursive</span>
          </label>

          <label className="flex items-center space-x-1 text-gray-600 cursor-pointer">
            <input
              type="checkbox"
              checked={includeHidden}
              disabled={isScanning}
              onChange={(e) => setIncludeHidden(e.target.checked)}
              className="rounded text-[#630ed4] focus:ring-[#630ed4]"
            />
            <span>Hidden Files</span>
          </label>

          {isScanning ? (
            <button
              onClick={cancelScan}
              className="px-4 py-1.5 bg-red-600 hover:bg-red-700 text-white font-bold rounded-lg shadow-sm transition-all cursor-pointer animate-pulse"
            >
              Cancel Scan
            </button>
          ) : (
            <button
              onClick={handleStartScan}
              disabled={!folderPath.trim()}
              className={`px-5 py-1.5 font-bold rounded-lg shadow-sm transition-all text-white ${
                folderPath.trim()
                  ? "bg-[#630ed4] hover:bg-[#5209b5] cursor-pointer"
                  : "bg-gray-300 cursor-not-allowed"
              }`}
            >
              Start Scan
            </button>
          )}

          <button
            onClick={handleLogout}
            title="Deactivate / Change License Key"
            className="px-2.5 py-1.5 text-gray-400 hover:text-red-500 font-bold border border-transparent hover:border-gray-200 rounded-lg transition-all"
          >
            🔒
          </button>
        </div>
      </header>

      {/* Progress Bar (Visible during scan via SSE) */}
      {isScanning && progress && (
        <div className="bg-purple-50 px-6 py-2 border-b border-purple-100 flex items-center justify-between text-xs text-purple-900">
          <div className="flex items-center space-x-3 w-1/2">
            <span className="font-semibold truncate">{progress.current_file}</span>
          </div>
          <div className="flex items-center space-x-4">
            <span>
              {progress.scanned_files} / {progress.total_files} Files ({progress.percentage.toFixed(1)}%)
            </span>
            <span>Errors: {progress.errors}</span>
            <span>Time: {(progress.elapsed_ms / 1000).toFixed(1)}s</span>
          </div>
        </div>
      )}

      {/* Main 3-Pane Config & Sequencer */}
      <main className="flex-1 flex px-6 py-3 gap-4 min-h-0">
        <div className="w-[70%] h-full">
          <FieldSelector
            selectedFields={selectedFields}
            onToggle={handleToggleField}
            onSelectCategory={handleSelectCategory}
          />
        </div>

        <div className="w-[30%] h-full">
          <ColumnSequencer
            columns={columnOrder}
            onReorder={setColumnOrder}
            onRemove={handleToggleField}
            onReset={() =>
              setColumnOrder([
                "file_name",
                "file_extension",
                "size_human",
                "hash_blake3",
                "hash_sha256",
                "shannon_entropy",
                "magic_bytes_hex",
                "timestomp_suspect",
              ])
            }
          />
        </div>
      </main>

      {/* Virtual Live Preview Table */}
      <section className="h-[35vh] px-6 pb-2 min-h-[200px]">
        <PreviewTable
          data={results}
          columns={columnOrder}
          isLoading={isScanning}
        />
      </section>

      {/* Bottom Export Bar */}
      <footer className="px-6 py-2.5 bg-white/80 backdrop-blur-md border-t border-purple-100 flex items-center justify-between text-xs">
        <div className="text-gray-500">
          Engine:{" "}
          <span className="font-bold text-gray-800">
            {isScanning
              ? "Scanning Active..."
              : results.length > 0
              ? `Ready (${results.length} files parsed)`
              : "Idle"}
          </span>
          {scanId && <span className="ml-2 font-mono text-[10px] text-purple-600">ID: {scanId}</span>}
          {error && <span className="ml-2 text-red-500 font-semibold">{error}</span>}
        </div>

        <div className="flex items-center space-x-2">
          <span className="font-bold text-gray-600 mr-1">Export:</span>
          <button
            onClick={() => handleExport("csv")}
            disabled={!scanId || results.length === 0}
            className="px-3 py-1 bg-white hover:bg-purple-50 text-gray-700 font-semibold rounded border border-gray-200 transition-all disabled:opacity-50 cursor-pointer"
          >
            CSV
          </button>
          <button
            onClick={() => handleExport("xlsx")}
            disabled={!scanId || results.length === 0}
            className="px-3 py-1 bg-white hover:bg-purple-50 text-gray-700 font-semibold rounded border border-gray-200 transition-all disabled:opacity-50 cursor-pointer"
          >
            Excel (.xlsx)
          </button>
          <button
            onClick={() => handleExport("json")}
            disabled={!scanId || results.length === 0}
            className="px-3 py-1 bg-white hover:bg-purple-50 text-gray-700 font-semibold rounded border border-gray-200 transition-all disabled:opacity-50 cursor-pointer"
          >
            JSON
          </button>
        </div>
      </footer>
    </div>
  );
};
