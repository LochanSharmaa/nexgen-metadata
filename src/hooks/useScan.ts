import { useState, useCallback, useRef, useEffect } from "react";
import { api, API_BASE_URL, startScanApi, cancelScanApi, getRecordsApi } from "../api";
import { FileMetadata, ScanConfig, ScanProgress } from "../types";

export function useScan(scanIdProp?: string | null) {
  const [scanId, setScanId] = useState<string | null>(scanIdProp || null);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [results, setResults] = useState<FileMetadata[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [totalCount, setTotalCount] = useState(0);

  const eventSourceRef = useRef<EventSource | null>(null);
  const pollIntervalRef = useRef<number | null>(null);

  // Synchronize internal scanId if prop changes
  useEffect(() => {
    if (scanIdProp && scanIdProp !== scanId) {
      setScanId(scanIdProp);
    }
  }, [scanIdProp]);

  // Clean up SSE stream and polling when component unmounts
  useEffect(() => {
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, []);

  // Fetch paginated records from the active scan
  const fetchRecords = useCallback(
    async (idToFetch?: string) => {
      const activeId = idToFetch || scanId;
      if (!activeId) return;

      try {
        const data = await getRecordsApi(activeId, 0, 500);
        if (data && data.records) {
          setResults(data.records);
          setTotalCount(data.total);
        }
      } catch (e) {
        console.error("Failed to fetch viewport records", e);
      }
    },
    [scanId]
  );

  // Hook into SSE stream when a valid scan_id exists and scanning is active
  const connectSse = useCallback(
    (id: string) => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }

      const sseUrl = `${API_BASE_URL}/api/scan/status/${id}`;
      const sse = new EventSource(sseUrl);
      eventSourceRef.current = sse;

      sse.onmessage = (event) => {
        try {
          const data: ScanProgress = JSON.parse(event.data);
          setProgress(data);

          if (data.status === "Completed" || data.status === "Cancelled") {
            setIsScanning(false);
            sse.close();
            fetchRecords(id);
            if (pollIntervalRef.current) {
              clearInterval(pollIntervalRef.current);
            }
          }
        } catch (err) {
          console.error("Error parsing SSE data", err);
        }
      };

      sse.onerror = (err) => {
        console.warn("SSE connection closed or reset", err);
      };
    },
    [fetchRecords]
  );

  const startScan = useCallback(
    async (config: ScanConfig) => {
      setResults([]);
      setError(null);
      setProgress(null);
      setIsScanning(true);

      try {
        const res = await startScanApi({
          folder_path: config.root_path,
          recursive: config.recursive,
          include_hidden: config.include_hidden,
          fields: config.selected_fields,
        });

        const newScanId = res.scan_id;
        setScanId(newScanId);

        // Connect SSE stream to /api/scan/status/:scan_id
        connectSse(newScanId);

        // Periodically refresh preview table during active scan
        pollIntervalRef.current = window.setInterval(() => {
          fetchRecords(newScanId);
        }, 800);

        return newScanId;
      } catch (err: any) {
        const msg =
          err.response?.data?.details ||
          err.response?.data?.error ||
          String(err);
        setError(msg);
        setIsScanning(false);
        throw err;
      }
    },
    [connectSse, fetchRecords]
  );

  const cancelScan = useCallback(async () => {
    if (!scanId) return;

    try {
      await cancelScanApi(scanId);
      setIsScanning(false);
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
      fetchRecords(scanId);
    } catch (err: any) {
      setError(String(err));
    }
  }, [scanId, fetchRecords]);

  return {
    scanId,
    isScanning,
    progress,
    results,
    error,
    totalCount,
    startScan,
    cancelScan,
    refreshRecords: fetchRecords,
  };
}
