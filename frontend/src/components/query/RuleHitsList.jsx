import React from "react";

export default function RuleHitsList({ rules = [], darkMode = false }) {
  if (!rules || rules.length === 0) {
    return (
      <div className={`text-sm mt-3 p-4 rounded-lg border flex items-center gap-2 transition-colors ${
        darkMode 
          ? "bg-gray-800 border-gray-700 text-gray-400" 
          : "bg-gray-50 border-gray-200 text-gray-500"
      }`}>
        <span>✓</span>
        <span>No rules matched - Query appears safe</span>
      </div>
    );
  }

  return (
    <div className="mt-3 space-y-2">
      <div className={`text-xs font-medium mb-2 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>
        {rules.length} rule{rules.length !== 1 ? 's' : ''} triggered:
      </div>
      <div className="flex flex-wrap gap-2">
        {rules.map((r, i) => (
          <span 
            key={i} 
            className={`inline-flex items-center gap-2 px-3 py-1.5 border-2 rounded-lg text-sm font-semibold shadow-sm hover:shadow-md transition-all ${
              darkMode 
                ? "bg-gradient-to-r from-amber-900/30 to-yellow-900/30 text-amber-300 border-amber-700" 
                : "bg-gradient-to-r from-amber-100 to-yellow-100 text-amber-900 border-amber-300"
            }`}
          >
            <span className={darkMode ? "text-amber-400" : "text-amber-600"}>⚠</span>
            {r}
          </span>
        ))}
      </div>
    </div>
  );
}
