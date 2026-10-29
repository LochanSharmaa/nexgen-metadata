import React, { useState } from "react";
import { api } from "./api";

interface LoginViewProps {
  onAuthenticated: () => void;
}

export const LoginView: React.FC<LoginViewProps> = ({ onAuthenticated }) => {
  const [licenseKey, setLicenseKey] = useState("");
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleActivate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!licenseKey.trim()) {
      setErrorMsg("Please enter your NexGen license key.");
      return;
    }

    setLoading(true);
    setErrorMsg(null);

    try {
      const res = await api.post("/api/activate", {
        license_key: licenseKey.trim(),
      });

      const { token, customer } = res.data;
      if (token) {
        localStorage.setItem("nexgen_jwt", token);
        if (customer) {
          localStorage.setItem("nexgen_customer", customer);
        }
        onAuthenticated();
      } else {
        setErrorMsg("Failed to obtain session token.");
      }
    } catch (err: any) {
      const msg =
        err.response?.data?.details ||
        err.response?.data?.error ||
        "Invalid or Expired License Key.";
      setErrorMsg(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen w-screen bg-[#0d0914] text-gray-100 font-sans select-none p-4">
      {/* Background ambient lighting */}
      <div className="absolute w-[500px] h-[500px] bg-[#630ed4]/20 rounded-full blur-[140px] pointer-events-none" />

      {/* Glassmorphism Auth Card */}
      <div className="relative z-10 w-full max-w-md p-8 bg-white/[0.04] backdrop-blur-2xl border border-white/[0.1] rounded-2xl shadow-2xl shadow-purple-950/40">
        {/* Header Branding */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-[#630ed4] to-[#a855f7] flex items-center justify-center text-white font-black text-2xl shadow-lg shadow-purple-900/60 mb-4">
            NX
          </div>
          <h1 className="text-xl font-black tracking-wider text-white">
            NEXGEN METADATA
          </h1>
          <p className="text-xs uppercase tracking-widest text-purple-400 font-bold mt-1">
            Forensic Deep Inspection Suite
          </p>
          <div className="mt-3 px-3 py-1 bg-purple-900/40 border border-purple-500/30 rounded-full text-[10px] text-purple-300 font-medium">
            🔒 Offline Air-Gapped License Gate
          </div>
        </div>

        {/* Form */}
        <form onSubmit={handleActivate} className="space-y-5">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">
              Cryptographic License Key
            </label>
            <div className="relative">
              <input
                type="text"
                value={licenseKey}
                onChange={(e) => setLicenseKey(e.target.value)}
                placeholder="NEXGEN-XXXX-XXXX-XXXX"
                disabled={loading}
                className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-xs font-mono text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-[#a855f7] focus:border-transparent transition-all shadow-inner"
              />
            </div>
            <p className="mt-2 text-[10px] text-gray-500 leading-relaxed">
              Your license key is cryptographically signed with Ed25519. No
              internet connection or external activation server is required.
            </p>
          </div>

          {/* Error Banner */}
          {errorMsg && (
            <div className="p-3 bg-red-950/60 border border-red-500/40 rounded-xl text-red-300 text-xs flex items-center space-x-2 animate-shake">
              <span className="text-sm">⚠️</span>
              <span className="font-medium">{errorMsg}</span>
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={loading}
            className={`w-full py-3 px-4 rounded-xl font-bold text-xs uppercase tracking-wider shadow-lg transition-all ${
              loading
                ? "bg-purple-900 text-purple-300 cursor-wait"
                : "bg-gradient-to-r from-[#630ed4] to-[#8b5cf6] hover:from-[#5209b5] hover:to-[#7c3aed] text-white shadow-purple-900/50 hover:shadow-purple-700/60 cursor-pointer active:scale-[0.98]"
            }`}
          >
            {loading ? "Validating Cryptographic Key..." : "Activate & Launch Engine"}
          </button>
        </form>

        {/* Security Footer Notice */}
        <div className="mt-8 pt-6 border-t border-white/[0.06] text-center">
          <p className="text-[10px] text-gray-500">
            NexGen Forensics LLC • Localhost Binding: 127.0.0.1:8080
          </p>
        </div>
      </div>
    </div>
  );
};
