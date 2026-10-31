import React, { useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { FIELD_DEFINITIONS } from "../types";
import { api } from "../api";

interface PreviewTableProps {
  data: Record<string, any>[];
  columns: string[];
  isLoading: boolean;
}

export const PreviewTable: React.FC<PreviewTableProps> = ({
  data,
  columns,
  isLoading,
}) => {
  const parentRef = useRef<HTMLDivElement>(null);
  const [reportingRow, setReportingRow] = useState<number | null>(null);
  const [reportSuccess, setReportSuccess] = useState<string | null>(null);

  const rowVirtualizer = useVirtualizer({
    count: data.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 36,
    overscan: 10,
  });

  const getHeaderLabel = (key: string) => {
    const def = FIELD_DEFINITIONS.find((f) => f.key === key);
    return def ? def.label : key;
  };

  const handleReportIssue = async (rowIndex: number, fileName: string) => {
    setReportingRow(rowIndex);
    setReportSuccess(null);
    try {
      const res = await api.post("/api/report-issue", {
        file_path: fileName,
        issue_type: "FIELD_EXTRACTION_FAILURE",
        description: `Manual operator audit report from preview table row #${rowIndex + 1}`,
      });
      if (res.data?.success) {
        setReportSuccess(`Logged #${rowIndex + 1}`);
        setTimeout(() => setReportSuccess(null), 3000);
      }
    } catch (e) {
      console.error("Failed to report issue", e);
    } finally {
      setReportingRow(null);
    }
  };

  const formatCellValue = (val: any) => {
    if (val === null || val === undefined || val === "") {
      return <span className="text-stone-300 italic">—</span>;
    }
    if (typeof val === "boolean") {
      return (
        <span
          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
            val ? "bg-emerald-100 text-emerald-800" : "bg-stone-100 text-stone-500"
          }`}
        >
          {val ? "TRUE" : "FALSE"}
        </span>
      );
    }
    if (typeof val === "object") {
      return (
        <span className="font-mono text-[10px] text-stone-500">
          {JSON.stringify(val)}
        </span>
      );
    }
    if (typeof val === "number") {
      return <span>{val.toLocaleString()}</span>;
    }
    return <span className="truncate">{String(val)}</span>;
  };

  return (
    <div className="flex flex-col h-full bg-white/80 backdrop-blur-md rounded-xl border border-amber-200 shadow-sm overflow-hidden">
      <div className="px-4 py-2 border-b border-amber-200/60 bg-amber-50/50 flex justify-between items-center text-xs">
        <span className="font-bold text-stone-800">
          Live Preview ({data.length.toLocaleString()} records ingested)
        </span>
        {isLoading && (
          <span className="text-amber-800 font-semibold animate-pulse">
            Extracting files...
          </span>
        )}
      </div>

      <div ref={parentRef} className="overflow-auto flex-1 text-xs">
        {data.length === 0 ? (
          <div className="flex items-center justify-center h-full text-stone-400">
            No data yet. Select an evidence directory and click "Begin Extraction" to begin.
          </div>
        ) : (
          <table className="w-full border-collapse">
            <thead className="sticky top-0 bg-amber-100/90 backdrop-blur border-b border-amber-200 z-10">
              <tr>
                <th className="p-2 text-left text-stone-600 font-bold border-r border-amber-200 w-12">
                  #
                </th>
                <th className="p-2 text-center text-stone-600 font-bold border-r border-amber-200 w-24">
                  Audit
                </th>
                {columns.map((col) => (
                  <th
                    key={col}
                    className="p-2 text-left text-stone-700 font-bold border-r border-amber-200 whitespace-nowrap"
                  >
                    {getHeaderLabel(col)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                const row = data[virtualRow.index];
                const isReporting = reportingRow === virtualRow.index;
                return (
                  <tr
                    key={virtualRow.index}
                    className={`border-b border-stone-100 transition-colors ${
                      virtualRow.index % 2 === 0 ? "bg-white" : "bg-amber-50/20"
                    } hover:bg-amber-100/40`}
                    style={{ height: `${virtualRow.size}px` }}
                  >
                    <td className="p-2 text-stone-400 font-mono text-[10px] border-r border-stone-100">
                      {virtualRow.index + 1}
                    </td>
                    <td className="p-1 text-center border-r border-stone-100">
                      <button
                        onClick={() => handleReportIssue(virtualRow.index, row.file_name || `row_${virtualRow.index + 1}`)}
                        disabled={isReporting}
                        title="Flag anomalous extraction for cryptographic diagnostics container"
                        className="text-[10px] px-1.5 py-0.5 rounded bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-200 transition-all cursor-pointer font-medium"
                      >
                        {isReporting ? "..." : "Audit"}
                      </button>
                    </td>
                    {columns.map((col) => (
                      <td
                        key={col}
                        className="p-2 border-r border-stone-100 max-w-xs truncate font-mono text-[11px] text-stone-800"
                        title={String(row[col] ?? "")}
                      >
                        {formatCellValue(row[col])}
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div className="p-2.5 bg-amber-50/40 border-t border-amber-200/50 flex justify-between items-center text-xs">
        <span className="text-stone-500">
          Showing <strong>{columns.length}</strong> columns of forensic metadata
        </span>
        {reportSuccess && (
          <span className="text-emerald-700 font-semibold text-[11px] animate-fade">
            ✓ {reportSuccess} appended to AES-256 diagnostics buffer
          </span>
        )}
      </div>
    </div>
  );
};
