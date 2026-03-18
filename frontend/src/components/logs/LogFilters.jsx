import React from "react";

export default function LogFilters({ label, setLabel, refresh, darkMode = false }) {
  return (
    <div className="flex flex-wrap items-center gap-4">
      <div className="flex items-center gap-2">
        <label className={`text-sm font-medium ${darkMode ? "text-gray-300" : "text-gray-700"}`}>Filter by:</label>
        <select
          value={label === null ? "all" : label}
          onChange={(e) => {
            const val = e.target.value;
            setLabel(val === "all" ? null : Number(val));
          }}
          className={`px-4 py-2 border-2 rounded-lg text-sm font-medium cursor-pointer transition-all ${
            darkMode 
              ? "bg-gray-700 border-gray-600 text-gray-200 hover:border-blue-500 focus:border-blue-400 focus:ring-2 focus:ring-blue-500/20" 
              : "bg-white border-gray-300 text-gray-900 hover:border-blue-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
          }`}
        >
          <option value="all">🔍 All Logs</option>
          <option value="1">🚨 Malicious Only</option>
          <option value="0">✅ Benign Only</option>
        </select>
      </div>

      <button
        onClick={refresh}
        className="px-5 py-2 bg-gradient-to-r from-blue-600 to-blue-700 text-white rounded-lg text-sm font-semibold hover:from-blue-700 hover:to-blue-800 focus:ring-4 focus:ring-blue-200 transition-all shadow-md hover:shadow-lg flex items-center gap-2"
      >
        <span className="text-base">🔄</span>
        Refresh Now
      </button>

      <div className={`ml-auto flex items-center gap-2 border rounded-lg px-4 py-2 transition-colors ${
        darkMode 
          ? "bg-green-900/20 border-green-700" 
          : "bg-green-50 border-green-200"
      }`}>
        <span className="relative flex h-3 w-3">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
        </span>
        <span className={`text-sm font-medium ${darkMode ? "text-green-300" : "text-green-800"}`}>Auto-refresh every 5s</span>
      </div>
    </div>
  );
}
