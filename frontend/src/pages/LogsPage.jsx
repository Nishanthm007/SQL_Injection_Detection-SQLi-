import React, { useState, useEffect } from "react";
import useRecentLogs from "../hooks/useRecentLogs";
import LogsTable from "../components/logs/LogsTable";
import LogFilters from "../components/logs/LogFilters";
import DownloadLogsButton from "../components/logs/DownloadLogsButton";

export default function LogsPage({ darkMode = false }) {
  const [label, setLabel] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const logsPerPage = 50;
  const offset = (currentPage - 1) * logsPerPage;
  
  const { logs, total, loading, error, refresh } = useRecentLogs({
    limit: logsPerPage,
    offset: offset,
    label,
    pollIntervalMs: 0, // Disable auto-refresh with pagination
  });

  const totalPages = Math.ceil(total / logsPerPage);

  // when label changes, reset to page 1 and refresh
  useEffect(() => {
    setCurrentPage(1);
    refresh();
  }, [label]);

  // when page changes, refresh
  useEffect(() => {
    refresh();
  }, [currentPage]);

  // Calculate statistics
  const maliciousCount = logs?.filter(log => log.label === 1).length || 0;
  const benignCount = logs?.filter(log => log.label === 0).length || 0;
  const avgLatency = logs?.length > 0 
    ? Math.round(logs.reduce((sum, log) => sum + (Number(log.latency_ms) || 0), 0) / logs.length)
    : 0;
  const recentCount = logs?.filter(log => {
    const detectedAt = new Date(log.detected_at);
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    return detectedAt > fiveMinutesAgo;
  }).length || 0;

  return (
    <div className="space-y-6">
      {/* Header Section */}
      <div className={`rounded-xl shadow-lg p-6 transition-colors ${
        darkMode 
          ? "bg-gradient-to-r from-gray-800 to-gray-700 text-white" 
          : "bg-white border-2 border-gray-300"
      }`}>
        <div className="flex items-center justify-between">
          <div>
            <h2 className={`text-3xl font-bold mb-2 flex items-center gap-3 ${darkMode ? "text-white" : "text-gray-900"}`}>
              <span className="text-4xl">📋</span>
              Recent Logs
            </h2>
            <p className={`text-sm ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
              Monitor and analyze SQL injection detection logs in real-time
            </p>
          </div>
          <div className="hidden md:block">
            <div className={`backdrop-blur-sm rounded-lg px-6 py-4 text-center border ${
              darkMode ? "bg-white/10 border-white/20" : "bg-gray-100 border-gray-300"
            }`}>
              <div className={`text-4xl font-bold ${darkMode ? "text-white" : "text-gray-900"}`}>{total}</div>
              <div className={`text-sm mt-1 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>Total Logs</div>
            </div>
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className={`rounded-xl shadow-md border-2 p-5 hover:shadow-lg transition-all ${
          darkMode 
            ? "bg-black border-gray-800" 
            : "bg-white border-gray-200"
        }`}>
          <div className="flex items-center justify-between">
            <div>
              <p className={`text-sm mb-1 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Total Detections</p>
              <p className={`text-3xl font-bold ${darkMode ? "text-gray-100" : "text-gray-900"}`}>{total}</p>
            </div>
            <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
              darkMode ? "bg-blue-900/50" : "bg-blue-100"
            }`}>
              <span className="text-2xl">📊</span>
            </div>
          </div>
          <div className={`mt-3 flex items-center text-xs ${darkMode ? "text-gray-400" : "text-gray-500"}`}>
            <span className="inline-block w-2 h-2 bg-blue-600 rounded-full mr-2"></span>
            All queries analyzed
          </div>
        </div>

        <div className={`rounded-xl shadow-md border-2 p-5 hover:shadow-lg transition-all ${
          darkMode 
            ? "bg-black border-red-900/50" 
            : "bg-white border-red-200"
        }`}>
          <div className="flex items-center justify-between">
            <div>
              <p className={`text-sm mb-1 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Malicious</p>
              <p className={`text-3xl font-bold ${darkMode ? "text-red-400" : "text-red-600"}`}>{maliciousCount}</p>
            </div>
            <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
              darkMode ? "bg-red-900/50" : "bg-red-100"
            }`}>
              <span className="text-2xl">🚨</span>
            </div>
          </div>
          <div className={`mt-3 flex items-center text-xs ${darkMode ? "text-red-400" : "text-red-600"}`}>
            <span className={`inline-block w-2 h-2 rounded-full mr-2 ${darkMode ? "bg-red-400" : "bg-red-600"}`}></span>
            {total > 0 ? Math.round((maliciousCount / total) * 100) : 0}% of total
          </div>
        </div>

        <div className={`rounded-xl shadow-md border-2 p-5 hover:shadow-lg transition-all ${
          darkMode 
            ? "bg-black border-green-900/50" 
            : "bg-white border-green-200"
        }`}>
          <div className="flex items-center justify-between">
            <div>
              <p className={`text-sm mb-1 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Benign</p>
              <p className={`text-3xl font-bold ${darkMode ? "text-green-400" : "text-green-600"}`}>{benignCount}</p>
            </div>
            <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
              darkMode ? "bg-green-900/50" : "bg-green-100"
            }`}>
              <span className="text-2xl">✅</span>
            </div>
          </div>
          <div className={`mt-3 flex items-center text-xs ${darkMode ? "text-green-400" : "text-green-600"}`}>
            <span className={`inline-block w-2 h-2 rounded-full mr-2 ${darkMode ? "bg-green-400" : "bg-green-600"}`}></span>
            {total > 0 ? Math.round((benignCount / total) * 100) : 0}% of total
          </div>
        </div>

        <div className={`rounded-xl shadow-md border-2 p-5 hover:shadow-lg transition-all ${
          darkMode 
            ? "bg-black border-purple-900/50" 
            : "bg-white border-purple-200"
        }`}>
          <div className="flex items-center justify-between">
            <div>
              <p className={`text-sm mb-1 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Avg Latency</p>
              <p className={`text-3xl font-bold ${darkMode ? "text-purple-400" : "text-purple-600"}`}>{avgLatency}<span className="text-lg">ms</span></p>
            </div>
            <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
              darkMode ? "bg-purple-900/50" : "bg-purple-100"
            }`}>
              <span className="text-2xl">⚡</span>
            </div>
          </div>
          <div className={`mt-3 flex items-center text-xs ${darkMode ? "text-purple-400" : "text-purple-600"}`}>
            <span className={`inline-block w-2 h-2 rounded-full mr-2 ${darkMode ? "bg-purple-400" : "bg-purple-600"}`}></span>
            {recentCount} in last 5 min
          </div>
        </div>
      </div>

      {/* Filters and Actions */}
      <div className={`rounded-xl shadow-md border-2 p-5 transition-colors ${
        darkMode 
          ? "bg-black border-gray-800" 
          : "bg-white border-gray-200"
      }`}>
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🔍</span>
            <div>
              <h3 className={`text-lg font-semibold ${darkMode ? "text-gray-100" : "text-gray-900"}`}>Filter & Export</h3>
              <p className={`text-sm ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Refine your view and download data</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <DownloadLogsButton
              limit={100}
              label={label}
              filenamePrefix="sqli_logs"
              darkMode={darkMode}
            />
          </div>
        </div>
        <div className={`mt-4 border-t pt-4 ${darkMode ? "border-gray-700" : "border-gray-100"}`}>
          <LogFilters label={label} setLabel={setLabel} refresh={refresh} darkMode={darkMode} />
        </div>
      </div>

      {/* Loading and Error States */}
      {loading && (
        <div className={`border rounded-xl p-6 flex items-center gap-3 transition-colors ${
          darkMode 
            ? "bg-blue-900/20 border-blue-700" 
            : "bg-blue-50 border-blue-200"
        }`}>
          <div className={`animate-spin rounded-full h-6 w-6 border-b-2 ${darkMode ? "border-blue-400" : "border-blue-600"}`}></div>
          <span className={`font-medium ${darkMode ? "text-blue-300" : "text-blue-800"}`}>Loading logs...</span>
        </div>
      )}
      
      {error && (
        <div className={`border-2 rounded-xl p-6 flex items-center gap-3 transition-colors ${
          darkMode 
            ? "bg-red-900/20 border-red-700" 
            : "bg-red-50 border-red-300"
        }`}>
          <span className="text-3xl">⚠️</span>
          <div>
            <p className={`font-semibold ${darkMode ? "text-red-300" : "text-red-900"}`}>Error Loading Logs</p>
            <p className={`text-sm mt-1 ${darkMode ? "text-red-400" : "text-red-700"}`}>{error}</p>
          </div>
        </div>
      )}

      {/* Logs Table */}
      <div className={`rounded-xl shadow-lg border-2 overflow-hidden transition-colors ${
        darkMode 
          ? "bg-black border-gray-800" 
          : "bg-white border-gray-200"
      }`}>
        <div className={`px-6 py-4 border-b transition-colors ${
          darkMode 
            ? "bg-gray-900/50 border-gray-700" 
            : "bg-gradient-to-r from-gray-50 to-gray-100 border-gray-200"
        }`}>
          <div className="flex items-center justify-between">
            <div>
              <h3 className={`text-lg font-semibold flex items-center gap-2 ${darkMode ? "text-gray-100" : "text-gray-900"}`}>
                <span className="text-xl">📝</span>
                Detection History
              </h3>
              <p className={`text-sm mt-1 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>
                Showing {offset + 1}-{Math.min(offset + logsPerPage, total)} of {total} logs
              </p>
            </div>
            {totalPages > 1 && (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  className={`px-3 py-2 rounded-lg font-semibold transition-all ${
                    currentPage === 1
                      ? darkMode ? "bg-gray-700 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-400 cursor-not-allowed"
                      : darkMode ? "bg-blue-600 text-white hover:bg-blue-500" : "bg-blue-600 text-white hover:bg-blue-700"
                  }`}
                >
                  ← Prev
                </button>
                <span className={`px-4 py-2 ${darkMode ? "text-gray-300" : "text-gray-700"} font-semibold`}>
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                  className={`px-3 py-2 rounded-lg font-semibold transition-all ${
                    currentPage === totalPages
                      ? darkMode ? "bg-gray-700 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-400 cursor-not-allowed"
                      : darkMode ? "bg-blue-600 text-white hover:bg-blue-500" : "bg-blue-600 text-white hover:bg-blue-700"
                  }`}
                >
                  Next →
                </button>
              </div>
            )}
          </div>
        </div>
        <LogsTable logs={logs} darkMode={darkMode} />
        
        {/* Pagination Controls - Bottom */}
        <div className={`px-6 py-4 border-t transition-colors ${
          darkMode 
            ? "bg-gray-900/50 border-gray-700" 
            : "bg-gradient-to-r from-gray-50 to-gray-100 border-gray-200"
        }`}>
          <div className="flex items-center justify-between">
            <p className={`text-sm ${darkMode ? "text-gray-400" : "text-gray-600"}`}>
              Showing {offset + 1}-{Math.min(offset + logsPerPage, total)} of {total} total logs
            </p>
            <div className="flex items-center gap-3">
              <button
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                className={`px-4 py-2 rounded-lg font-semibold transition-all text-sm ${
                  currentPage === 1
                    ? darkMode ? "bg-gray-700 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-400 cursor-not-allowed"
                    : darkMode ? "bg-blue-600 text-white hover:bg-blue-500" : "bg-blue-600 text-white hover:bg-blue-700"
                }`}
              >
                ← Previous
              </button>
              <span className={`px-3 py-2 rounded-lg ${darkMode ? "bg-gray-800 text-gray-300" : "bg-gray-100 text-gray-700"} font-semibold text-sm`}>
                Page {currentPage} of {totalPages || 1}
              </span>
              <button
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                disabled={currentPage >= totalPages}
                className={`px-4 py-2 rounded-lg font-semibold transition-all text-sm ${
                  currentPage >= totalPages
                    ? darkMode ? "bg-gray-700 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-400 cursor-not-allowed"
                    : darkMode ? "bg-blue-600 text-white hover:bg-blue-500" : "bg-blue-600 text-white hover:bg-blue-700"
                }`}
              >
                Next →
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
