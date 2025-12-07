// frontend/src/components/explainability/ScoreBreakdownChart.jsx
import React from "react";
import { extractScores } from "../../utils/scoreUtils";

export default function ScoreBreakdownChart({ scores = {}, darkMode = false }) {
  // scores may be whole log object or a scores object
  const s = extractScores(scores);

  const pct = (v) => Math.round(Math.max(0, Math.min(1, v || 0)) * 100);

  const row = (label, val, colorClass) => {
    const percent = pct(val);
    return (
      <div className="mb-4">
        <div className="flex items-center justify-between mb-1">
          <div className={`text-sm font-medium ${darkMode ? "text-gray-300" : "text-gray-700"}`}>{label}</div>
          <div className={`text-sm font-semibold ${darkMode ? "text-gray-200" : "text-gray-900"}`}>{percent}%</div>
        </div>

        <div className={`w-full h-4 rounded overflow-hidden ${darkMode ? "bg-gray-700" : "bg-gray-100"}`}>
          <div style={{ width: `${percent}%` }} className={`h-4 ${colorClass} rounded`}></div>
        </div>
      </div>
    );
  };

  const debug = {
    normalized: s
  };

  return (
    <div>
      {row("CNN probability", s.p_cnn, "bg-blue-600")}
      {row("Rule score", s.p_rule, "bg-yellow-500")}
      {row("Fused score", s.fused, s.fused >= 0.7 ? "bg-red-600" : "bg-green-600")}

      <details className={`mt-2 text-xs ${darkMode ? "text-gray-400" : "text-gray-500"}`}>
        <summary className="cursor-pointer">Debug: normalized scores</summary>
        <pre className={`mt-2 text-xs ${darkMode ? "text-gray-400" : "text-gray-700"}`}>{JSON.stringify(debug, null, 2)}</pre>
      </details>
    </div>
  );
}
