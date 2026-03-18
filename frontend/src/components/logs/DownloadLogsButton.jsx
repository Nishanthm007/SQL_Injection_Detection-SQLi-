import React, { useState } from "react";
import { getRecentAttacks } from "../../services/logsApi";
import { ArrowDownTrayIcon } from "@heroicons/react/24/outline"; // heroicons
// Install heroicons if needed: npm install @heroicons/react

export default function DownloadLogsButton({
  limit = 100,
  label = null,
  filenamePrefix = "sqli_logs",
  darkMode = false,
}) {
  const [loading, setLoading] = useState(false);
  const [format, setFormat] = useState("csv");

  const safeValue = (v) => {
    if (v === null || typeof v === "undefined") return "";
    if (typeof v === "object") return JSON.stringify(v);
    return String(v);
  };

  const toCSV = (arr) => {
    if (!Array.isArray(arr) || arr.length === 0) return "";

    const headerSet = new Set();
    arr.forEach((r) => Object.keys(r).forEach((k) => headerSet.add(k)));
    const headers = Array.from(headerSet);

    const rows = arr.map((r) =>
      headers
        .map((h) => {
          const v = safeValue(r[h]);
          return `"${String(v).replace(/"/g, '""')}"`;
        })
        .join(",")
    );

    return [headers.join(","), ...rows].join("\r\n");
  };

  const triggerDownload = (dataStr, fileName, type) => {
    const blob = new Blob([dataStr], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const handleDownload = async () => {
    setLoading(true);
    try {
      const data = await getRecentAttacks({ limit, label });
      const items = Array.isArray(data.attacks)
        ? data.attacks
        : Array.isArray(data)
        ? data
        : data.attacks ?? [];

      const ts = new Date().toISOString().replace(/[:.]/g, "-");
      const base = `${filenamePrefix}_${ts}`;

      if (format === "json") {
        triggerDownload(
          JSON.stringify(items, null, 2),
          `${base}.json`,
          "application/json;charset=utf-8"
        );
      } else {
        const csv = toCSV(items);
        triggerDownload(csv, `${base}.csv`, "text/csv;charset=utf-8");
      }
    } catch (err) {
      alert("Failed to download logs: " + (err?.message || err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center gap-2">
      {/* Dropdown */}
      <select
        value={format}
        onChange={(e) => setFormat(e.target.value)}
        disabled={loading}
        className={`px-3 py-1.5 text-sm rounded-md border shadow-sm cursor-pointer focus:ring-2 focus:outline-none hover:border-gray-400 transition-all ${
          darkMode 
            ? "bg-gray-700 border-gray-600 text-gray-200 focus:ring-blue-500 hover:bg-gray-600" 
            : "bg-white border-gray-300 text-gray-900 focus:ring-blue-500"
        }`}
      >
        <option value="csv">CSV</option>
        <option value="json">JSON</option>
      </select>

      {/* Download button */}
      <button
        onClick={handleDownload}
        disabled={loading}
        className="inline-flex items-center gap-2 px-4 py-1.5 rounded-md text-sm font-medium bg-blue-600 text-white hover:bg-blue-700 active:bg-blue-800 disabled:opacity-50 disabled:cursor-not-allowed shadow-md hover:shadow-lg transition-all"
      >
        <ArrowDownTrayIcon className="h-4 w-4" />
        <span className="font-semibold">{loading ? "Preparing..." : "Download"}</span>
      </button>
    </div>
  );
}
