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
    <div className="flex items-center justify-center min-h-screen w-screen bg-[#1c1917] text-amber-50 font-sans select-none p-4">
      {/* Background ambient lighting */}
      <div className="absolute w-[500px] h-[500px] bg-amber-500/15 rounded-full blur-[140px] pointer-events-none" />

      {/* Glassmorphism Auth Card */}
      <div className="relative z-10 w-full max-w-md p-8 bg-stone-900/80 backdrop-blur-2xl border border-amber-500/20 rounded-2xl shadow-2xl shadow-amber-950/40">
        {/* Header Branding */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-amber-400 to-yellow-200 flex items-center justify-center text-amber-950 font-black text-2xl shadow-lg shadow-amber-900/40 mb-4">
            NX
          </div>
          <h1 className="text-xl font-black tracking-wider text-amber-100">
            NEXGEN METADATA
          </h1>
          <p className="text-xs uppercase tracking-widest text-amber-300 font-bold mt-1">
            Forensic Intelligence Suite
          </p>
          <div className="mt-3 px-3 py-1 bg-amber-950/50 border border-amber-500/30 rounded-full text-[10px] text-amber-200 font-medium">
            🔒 Offline Air-Gapped License Gate
          </div>
        </div>

        {/* Form */}
        <form onSubmit={handleActivate} className="space-y-5">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-amber-200/80 mb-2">
              Cryptographic License Key
            </label>
            <div className="relative">
              <textarea
                rows={3}
                value={licenseKey}
                onChange={(e) => setLicenseKey(e.target.value)}
                placeholder="Paste full NEXGEN-eyJ... key"
                disabled={loading}
                spellCheck={false}
                autoComplete="off"
                className="w-full px-4 py-3 bg-black/50 border border-amber-500/20 rounded-xl text-xs font-mono text-amber-100 placeholder-amber-700/50 focus:outline-none focus:ring-2 focus:ring-amber-400 focus:border-transparent transition-all shadow-inner resize-none break-all"
              />
            </div>
            <p className="mt-2 text-[10px] text-stone-400 leading-relaxed">
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
                ? "bg-amber-900/60 text-amber-300/60 cursor-wait"
                : "bg-gradient-to-r from-yellow-300 to-amber-300 hover:from-yellow-400 hover:to-amber-400 text-amber-950 shadow-amber-900/40 cursor-pointer active:scale-[0.98]"
            }`}
          >
            {loading ? "Validating Cryptographic Key..." : "Activate & Launch Engine"}
          </button>
        </form>

        {/* Security Footer Notice */}
        <div className="mt-8 pt-6 border-t border-amber-500/10 text-center">
          <p className="text-[10px] text-stone-400">
            NexGen Forensics LLC • Localhost Binding: 127.0.0.1:8080
          </p>
        </div>
      </div>
    </div>
  );
};
