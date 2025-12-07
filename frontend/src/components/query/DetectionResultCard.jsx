import React from "react";
import ScoreBar from "./ScoreBar";
import RuleHitsList from "./RuleHitsList";

export default function DetectionResultCard({ result, darkMode = false }) {
  const scores = result.scores || { p_cnn: result.p_cnn, p_rule: result.p_rule, fused: result.fused };

  const decisionBadge = (decision) => {
    if (!decision) return "bg-gray-100 text-gray-800";
    const d = String(decision).toLowerCase();
    if (d.startsWith("block") || d.includes("attack")) return "bg-red-100 text-red-700";
    if (d.includes("susp")) return "bg-yellow-100 text-yellow-800";
    return "bg-green-100 text-green-700";
  };

  return (
    <div className={`border-2 rounded-2xl shadow-xl p-6 hover:shadow-2xl transition-all ${
      darkMode 
        ? "bg-gradient-to-br from-gray-800 to-gray-900 border-gray-700" 
        : "bg-gradient-to-br from-white to-gray-50 border-gray-200"
    }`}>
      <div className="flex items-center justify-between mb-6">
        <div className="flex-1">
          <div className={`text-xs font-semibold uppercase tracking-wide mb-1 ${
            darkMode ? "text-gray-400" : "text-gray-500"
          }`}>Final Decision</div>
          <div className={`text-2xl font-bold flex items-center gap-2 ${
            darkMode ? "text-gray-100" : "text-gray-900"
          }`}>
            {result.label === 1 ? "🚨" : "✅"}
            {result.decision ?? result.label_str}
          </div>
        </div>

        <div className="text-right">
          <div className={`text-xs font-semibold uppercase tracking-wide mb-2 ${
            darkMode ? "text-gray-400" : "text-gray-500"
          }`}>Classification</div>
          <div className="text-sm font-semibold">
            {result.label === 1 ? (
              <span className="px-4 py-2 rounded-xl bg-gradient-to-r from-red-500 to-red-600 text-white shadow-lg text-base font-bold flex items-center gap-2">
                ⚠️ Malicious
              </span>
            ) : (
              <span className="px-4 py-2 rounded-xl bg-gradient-to-r from-green-500 to-green-600 text-white shadow-lg text-base font-bold flex items-center gap-2">
                ✓ Benign
              </span>
            )}
          </div>
        </div>
      </div>

      <div className={`mt-6 rounded-xl p-5 border transition-colors ${
        darkMode 
          ? "bg-gray-900/50 border-gray-700" 
          : "bg-white/50 border-gray-200"
      }`}>
        <h4 className={`text-sm font-bold mb-4 flex items-center gap-2 ${
          darkMode ? "text-gray-200" : "text-gray-700"
        }`}>
          <span>📊</span>
          <span>Detection Scores</span>
        </h4>
        <div className="space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className={`text-sm font-semibold flex items-center gap-2 ${
                darkMode ? "text-gray-200" : "text-gray-700"
              }`}>
                <span>🧠</span>
                <span>CNN Analysis</span>
              </div>
              <span className={`text-sm font-bold ${darkMode ? "text-gray-100" : "text-gray-900"}`}>{((scores.p_cnn ?? 0) * 100).toFixed(1)}%</span>
            </div>
            <ScoreBar value={scores.p_cnn ?? 0} darkMode={darkMode} />
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <div className={`text-sm font-semibold flex items-center gap-2 ${
                darkMode ? "text-gray-200" : "text-gray-700"
              }`}>
                <span>📋</span>
                <span>Rule Engine</span>
              </div>
              <span className={`text-sm font-bold ${darkMode ? "text-gray-100" : "text-gray-900"}`}>{((scores.p_rule ?? 0) * 100).toFixed(1)}%</span>
            </div>
            <ScoreBar value={scores.p_rule ?? 0} darkMode={darkMode} />
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <div className={`text-sm font-semibold flex items-center gap-2 ${
                darkMode ? "text-gray-200" : "text-gray-700"
              }`}>
                <span>⚡</span>
                <span>Fused Score</span>
              </div>
              <span className={`text-sm font-bold ${darkMode ? "text-gray-100" : "text-gray-900"}`}>{((scores.fused ?? 0) * 100).toFixed(1)}%</span>
            </div>
            <ScoreBar value={scores.fused ?? 0} darkMode={darkMode} />
          </div>
        </div>
      </div>

      <div className={`mt-6 rounded-xl p-5 border transition-colors ${
        darkMode 
          ? "bg-gray-900/50 border-gray-700" 
          : "bg-white/50 border-gray-200"
      }`}>
        <div className="flex items-center justify-between mb-4">
          <div className={`text-sm font-bold flex items-center gap-2 ${
            darkMode ? "text-gray-200" : "text-gray-700"
          }`}>
            <span>🎯</span>
            <span>Matched Rules</span>
          </div>
          <div className={`text-xs px-3 py-1 rounded-lg font-bold ${decisionBadge(result.decision)}`}>{result.decision ?? "N/A"}</div>
        </div>

        <RuleHitsList rules={result.rule_matches || []} darkMode={darkMode} />
      </div>

      <div className={`mt-6 rounded-xl p-4 border-2 transition-colors ${
        darkMode 
          ? "bg-gray-800/50 border-gray-700" 
          : "bg-gradient-to-r from-blue-50 to-purple-50 border-blue-200"
      }`}>
        <div className="flex items-center gap-2 mb-3">
          <span className="text-lg">⚡</span>
          <span className={`text-sm font-bold ${darkMode ? "text-gray-200" : "text-gray-700"}`}>Performance Metrics</span>
        </div>
        <div className="grid grid-cols-3 gap-4 text-center">
          <div className={`rounded-lg p-3 border transition-colors ${
            darkMode 
              ? "bg-gray-700/50 border-gray-600" 
              : "bg-white/60 border-blue-200"
          }`}>
            <div className={`text-xs mb-1 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Total Latency</div>
            <div className={`text-lg font-bold ${darkMode ? "text-gray-200" : "text-blue-700"}`}>{result.latency_ms ?? "-"}<span className="text-xs ml-1">ms</span></div>
          </div>
          <div className={`rounded-lg p-3 border transition-colors ${
            darkMode 
              ? "bg-gray-700/50 border-gray-600" 
              : "bg-white/60 border-purple-200"
          }`}>
            <div className={`text-xs mb-1 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>CNN Time</div>
            <div className={`text-lg font-bold ${darkMode ? "text-gray-200" : "text-purple-700"}`}>{result.details?.cnn_latency_ms ?? "-"}<span className="text-xs ml-1">ms</span></div>
          </div>
          <div className={`rounded-lg p-3 border transition-colors ${
            darkMode 
              ? "bg-gray-700/50 border-gray-600" 
              : "bg-white/60 border-pink-200"
          }`}>
            <div className={`text-xs mb-1 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Rules Time</div>
            <div className={`text-lg font-bold ${darkMode ? "text-gray-200" : "text-pink-700"}`}>{result.details?.rule_latency_ms ?? "-"}<span className="text-xs ml-1">ms</span></div>
          </div>
        </div>
      </div>

      <details className={`mt-6 p-4 rounded-xl border-2 transition-colors ${
        darkMode 
          ? "bg-black text-gray-100 border-gray-700 hover:border-gray-600" 
          : "bg-gray-900 text-gray-100 border-gray-700 hover:border-gray-600"
      }`}>
        <summary className="text-sm font-bold cursor-pointer hover:text-white flex items-center gap-2">
          <span>🔧</span>
          <span>Raw Response (Debug)</span>
        </summary>
        <pre className={`mt-3 text-xs overflow-auto max-h-64 p-3 rounded border font-mono ${
          darkMode 
            ? "bg-black/50 border-gray-800" 
            : "bg-black/30 border-gray-700"
        }`}>{JSON.stringify(result, null, 2)}</pre>
      </details>
    </div>
  );
}
