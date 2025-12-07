import React, { useState } from "react";
import { detectQuery } from "../../services/detectionApi";
import DetectionResultCard from "./DetectionResultCard";

export default function QueryForm() {
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
    <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-100">
      <form onSubmit={onSubmit} className="space-y-4">
        <label className="block text-sm font-medium text-gray-700">SQL Query</label>

        <textarea
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Enter SQL to analyze..."
          className="w-full min-h-[160px] p-3 border rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none resize-none bg-slate-50"
        />

        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={loading}
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-60"
          >
            {loading ? "Analyzing..." : "Detect SQL Injection"}
          </button>

          <button
            type="button"
            className="px-3 py-2 border rounded-md text-sm text-gray-700 hover:bg-gray-50"
            onClick={() => { setQuery(""); setResult(null); setError(null); }}
          >
            Clear
          </button>

          <div className="ml-auto text-sm text-gray-500">Examples:</div>
          <div className="flex gap-2">
            {examples.map((ex, i) => (
              <button
                key={i}
                type="button"
                onClick={() => setQuery(ex)}
                className="text-xs px-2 py-1 bg-gray-100 border rounded text-gray-700 hover:bg-gray-200"
              >
                Try {i + 1}
              </button>
            ))}
          </div>
        </div>
      </form>

      {error && (
        <div className="mt-4 p-3 bg-red-50 border border-red-100 rounded text-red-700">
          {error}
        </div>
      )}

      {result && (
        <div className="mt-6">
          <DetectionResultCard result={result} />
        </div>
      )}
    </div>
  );
}
