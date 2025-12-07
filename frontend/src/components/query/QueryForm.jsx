import React, { useState } from "react";
import { detectQuery } from "../../services/detectionApi";
import DetectionResultCard from "./DetectionResultCard";

export default function QueryForm({ darkMode = false }) {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const examples = [
    "SELECT * FROM users WHERE id = 1",
    "SELECT id, name FROM products UNION SELECT 1, 'x' --",
    "SELECT * FROM users WHERE username = 'admin' OR '1'='1'"
  ];

  const onSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setResult(null);
    if (!query || !query.trim()) {
      setError("Please enter a SQL query to analyze.");
      return;
    }

    setLoading(true);
    try {
      const res = await detectQuery(query);
      setResult(res);
    } catch (err) {
      setError(err.message || "Failed to analyze query.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={`p-8 rounded-2xl shadow-xl border-2 hover:shadow-2xl transition-all ${
      darkMode 
        ? "bg-black border-gray-800" 
        : "bg-white border-gray-100"
    }`}>
      <form onSubmit={onSubmit} className="space-y-5">
        <div>
          <div className="flex items-center gap-2 mb-3">
            <span className="text-xl">🔍</span>
            <label className={`block text-lg font-bold ${darkMode ? "text-gray-100" : "text-gray-800"}`}>SQL Query Analysis</label>
          </div>
          <p className={`text-sm mb-3 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Enter your SQL query below for real-time security analysis</p>
        </div>

        <div className="relative">
          <textarea
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Enter SQL to analyze...

Example: SELECT * FROM users WHERE id = 1"
            className={`w-full min-h-[200px] p-4 border-2 rounded-xl focus:ring-4 outline-none resize-none font-mono text-sm transition-all ${
              darkMode 
                ? "bg-gray-900 border-gray-600 text-gray-100 placeholder-gray-500 focus:ring-blue-500/20 focus:border-blue-400 hover:bg-gray-900/80" 
                : "bg-gray-50 border-gray-200 text-gray-900 placeholder-gray-400 focus:ring-blue-500/20 focus:border-blue-500 hover:bg-white"
            }`}
          />
          {query.length > 0 && (
            <div className={`absolute bottom-3 right-3 text-xs px-2 py-1 rounded border ${
              darkMode 
                ? "bg-gray-800 text-gray-400 border-gray-700" 
                : "bg-white text-gray-400 border-gray-300"
            }`}>
              {query.length} characters
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-3 justify-between">
          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={loading}
              className={`px-6 py-3 rounded-xl font-semibold shadow-lg hover:shadow-xl transition-all flex items-center gap-2 disabled:opacity-60 disabled:cursor-not-allowed ${
                darkMode 
                  ? "bg-gradient-to-r from-blue-600 to-indigo-600 text-white hover:from-blue-500 hover:to-indigo-500 border-2 border-blue-500/50" 
                  : "bg-white text-gray-900 hover:bg-gray-50 border-2 border-gray-400"
              }`}
            >
              {loading ? (
                <>
                  <span className="animate-spin">⚙️</span>
                  <span>Analyzing...</span>
                </>
              ) : (
                <>
                  <span>🚀</span>
                  <span>Detect SQL Injection</span>
                </>
              )}
            </button>

            <button
              type="button"
              className={`px-5 py-3 border-2 rounded-xl text-sm font-semibold transition-all ${
                darkMode 
                  ? "border-gray-600 text-gray-300 hover:bg-gray-700 hover:border-gray-500" 
                  : "border-gray-300 text-gray-700 hover:bg-gray-50 hover:border-gray-400"
              }`}
              onClick={() => { setQuery(""); setResult(null); setError(null); }}
            >
              🗑️ Clear
            </button>
          </div>

          <div className="flex items-center gap-3">
            <span className={`text-sm font-medium ${darkMode ? "text-gray-400" : "text-gray-900"}`}>Quick Examples:</span>
            <div className="flex gap-2">
              {examples.map((ex, i) => (
                <button
                  key={i}
                  type="button"
                  onClick={() => setQuery(ex)}
                  className={`text-sm px-4 py-2 border-2 rounded-lg font-semibold transition-all shadow-sm hover:shadow-md ${
                    darkMode 
                      ? "bg-gradient-to-r from-blue-600/80 to-indigo-600/80 border-blue-500/50 text-white hover:from-blue-500 hover:to-indigo-500 hover:border-blue-400" 
                      : "bg-white border-gray-400 text-gray-900 hover:bg-gray-100 hover:border-gray-500"
                  }`}
                >
                  Try {i + 1}
                </button>
              ))}
            </div>
          </div>
        </div>
      </form>

      {error && (
        <div className={`mt-6 p-4 rounded-xl border-2 flex items-start gap-3 shadow-lg ${
          darkMode 
            ? "bg-gradient-to-r from-red-900/20 to-red-800/20 border-red-700 text-red-300" 
            : "bg-gradient-to-r from-red-50 to-red-100 border-red-300 text-red-800"
        }`}>
          <span className="text-2xl">⚠️</span>
          <div>
            <div className="font-bold mb-1">Error</div>
            <div className="text-sm">{error}</div>
          </div>
        </div>
      )}

      {result && (
        <div className="mt-8">
          <DetectionResultCard result={result} darkMode={darkMode} />
        </div>
      )}
    </div>
  );
}
