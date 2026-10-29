import React, { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { FileMetadata, FIELD_DEFINITIONS } from "../types";

interface PreviewTableProps {
  data: FileMetadata[];
  columns: string[];
  isLoading: boolean;
}

export const PreviewTable: React.FC<PreviewTableProps> = ({
  data,
  columns,
  isLoading,
}) => {
  const parentRef = useRef<HTMLDivElement>(null);

  const rowVirtualizer = useVirtualizer({
    count: data.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 32,
    overscan: 10,
  });

  const getHeaderLabel = (key: string) => {
    const def = FIELD_DEFINITIONS.find((f) => f.key === key);
    return def ? def.label : key;
  };

  const renderCellValue = (row: FileMetadata, key: string) => {
    const val = (row as Record<string, unknown>)[key];
    if (val === null || val === undefined || val === "") {
      return <span className="text-gray-300 font-mono">--</span>;
    }
    if (typeof val === "boolean") {
      return (
        <span
          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
            val ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"
          }`}
        >
          {val ? "TRUE" : "FALSE"}
        </span>
      );
    }
    if (typeof val === "number") {
      return <span>{val.toLocaleString()}</span>;
    }
    return <span className="truncate">{String(val)}</span>;
  };

  return (
    <div className="flex flex-col h-full bg-white/80 backdrop-blur-md rounded-xl border border-purple-100 shadow-sm overflow-hidden">
      <div className="px-4 py-2 border-b border-purple-100 bg-purple-50/50 flex justify-between items-center text-xs">
        <span className="font-bold text-gray-800">
          Live Preview ({data.length.toLocaleString()} records ingested)
        </span>
        {isLoading && (
          <span className="text-[#630ed4] font-semibold animate-pulse">
            Scanning files...
          </span>
        )}
      </div>

      <div ref={parentRef} className="overflow-auto flex-1 text-xs">
        {data.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-400">
            No data yet. Select a folder and click "Start Scan" to begin.
          </div>
        ) : (
          <table className="w-full border-collapse">
            <thead className="sticky top-0 bg-purple-100/90 backdrop-blur border-b border-purple-200 z-10">
              <tr>
                <th className="p-2 text-left text-gray-600 font-bold border-r border-purple-200 w-12">
                  #
                </th>
                {columns.map((col) => (
                  <th
                    key={col}
                    className="p-2 text-left text-gray-700 font-bold border-r border-purple-200 whitespace-nowrap"
                  >
                    {getHeaderLabel(col)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                const row = data[virtualRow.index];
                return (
                  <tr
                    key={virtualRow.index}
                    className={`border-b border-gray-100 transition-colors ${
                      virtualRow.index % 2 === 0 ? "bg-white" : "bg-purple-50/20"
                    } hover:bg-purple-100/40`}
                    style={{ height: `${virtualRow.size}px` }}
                  >
                    <td className="p-2 text-gray-400 font-mono text-[10px] border-r border-gray-100">
                      {virtualRow.index + 1}
                    </td>
                    {columns.map((col) => (
                      <td
                        key={col}
                        className="p-2 text-gray-700 border-r border-gray-100 max-w-[200px] truncate"
                      >
                        {renderCellValue(row, col)}
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
