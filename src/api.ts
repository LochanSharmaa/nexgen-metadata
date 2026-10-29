import axios from "axios";

// Base API pointing to local Axum instance (uses relative path in production, fallback to 127.0.0.1:8080)
export const API_BASE_URL =
  typeof window !== "undefined" && window.location.origin.includes("localhost:5173")
    ? "http://127.0.0.1:8080"
    : "";

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Request Interceptor: Injects Authorization Bearer JWT
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("nexgen_jwt");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response Interceptor: Catches 401 Unauthorized, clears token, and triggers logout event
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      console.warn("Session expired or unauthorized. Logging out...");
      localStorage.removeItem("nexgen_jwt");
      localStorage.removeItem("nexgen_customer");
      window.dispatchEvent(new Event("nexgen_auth_reset"));
    }
    return Promise.reject(error);
  }
);

// Scan API Helpers
export interface StartScanPayload {
  folder_path: string;
  recursive?: boolean;
  include_hidden?: boolean;
  fields?: string[];
}

export const startScanApi = async (payload: StartScanPayload): Promise<{ scan_id: string; status: string }> => {
  const res = await api.post("/api/scan/start", payload);
  return res.data;
};

export const cancelScanApi = async (scanId: string): Promise<{ scan_id: string; status: string }> => {
  const res = await api.post("/api/scan/cancel", { scan_id: scanId });
  return res.data;
};

export const getRecordsApi = async (scanId: string, page = 0, pageSize = 100) => {
  const res = await api.get(`/api/scan/records/${scanId}`, {
    params: { page, page_size: pageSize },
  });
  return res.data;
};

export const triggerExportDownload = (scanId: string, format = "csv") => {
  const token = localStorage.getItem("nexgen_jwt") || "";
  // Direct file download URL via GET /api/scan/export/:scan_id?format=...
  const downloadUrl = `${API_BASE_URL}/api/scan/export/${scanId}?format=${format}`;
  
  // Use invisible link trigger to prompt browser native Save As dialog
  const link = document.createElement("a");
  link.href = downloadUrl;
  link.setAttribute("download", `nexgen_export_${scanId}.${format}`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};
