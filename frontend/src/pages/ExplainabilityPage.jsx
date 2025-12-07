import React, { useMemo } from "react";
import useRecentLogs from "../hooks/useRecentLogs";
import ScoreBreakdownChart from "../components/explainability/ScoreBreakdownChart";
import TimelineChart from "../components/explainability/TimelineChart";
import PredictionFlow from "../components/explainability/PredictionFlow";
import { extractScores } from "../utils/scoreUtils";

/**
 * Helper: try to parse a log's stored JSON fields (if any)
 */
function normalizeLogEntry(log) {
  if (!log || typeof log !== "object") return log || {};
  const out = { ...log };

  // If log.scores is a JSON string, parse it
  try {
    if (typeof out.scores === "string") {
      const parsed = JSON.parse(out.scores);
      if (parsed && typeof parsed === "object") out.scores = parsed;
    }
  } catch (e) {
    // ignore parse error
  }

  // Some logs may have a 'details' or 'metadata' stringified
  for (const f of ["details", "metadata", "meta"]) {
    try {
      if (typeof out[f] === "string") {
        const parsed = JSON.parse(out[f]);
        if (parsed && typeof parsed === "object") out[f] = parsed;
      }
    } catch (e) {}
  }

  return out;
}

export default function ExplainabilityPage({ darkMode = false }) {
  const { logs, total, loading, error } = useRecentLogs({ limit: 100, pollIntervalMs: 5000 });

  const cleanedLogs = useMemo(() => {
    if (!logs) return [];
    return logs.map((l) => normalizeLogEntry(l));
  }, [logs]);

  // latest entry
  const latest = cleanedLogs && cleanedLogs.length > 0 ? cleanedLogs[0] : null;

  const timelinePoints = useMemo(() => {
    if (!cleanedLogs || cleanedLogs.length === 0) return [];
    // take up to 40 most recent entries
    const slice = cleanedLogs.slice(0, 40).map((l) => {
      const s = extractScores(l);
      return {
        fused: s.fused,
        p_cnn: s.p_cnn,
        p_rule: s.p_rule,
        time: l.detected_at ?? l.created_at ?? l.timestamp ?? null,
        query: l.query ?? l.sql ?? ""
      };
    });

    return slice.reverse();
  }, [cleanedLogs]);

  // Compute normalized scores for the latest entry for debug display
  const latestNormalized = latest ? extractScores(latest) : null;

  // Print to console for debugging
  if (latest) {
    // eslint-disable-next-line no-console
    console.info("Explainability - latest log (raw):", latest);
    // eslint-disable-next-line no-console
    console.info("Explainability - latestNormalized:", latestNormalized);
  }

  return (
    <div>
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-2xl ${darkMode ? "bg-blue-500/20 text-blue-400" : "bg-blue-100 text-blue-600"}`}>
            📊
          </div>
          <h2 className={`text-3xl font-bold ${darkMode ? "text-gray-100" : "text-gray-900"}`}>Model Explainability</h2>
        </div>
        <p className={`text-base ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Visualize how CNN, rule-engine, and fusion layers contribute to detection decisions.</p>
      </div>

      {loading && <div className={darkMode ? "text-gray-400" : "text-gray-600"}>Loading explainability data...</div>}
      {error && (
        <div className={`p-3 rounded ${
          darkMode 
            ? "text-red-300 bg-red-900/20 border border-red-700" 
            : "text-red-600 bg-red-50 border border-red-200"
        }`}>{error}</div>
      )}

      {/* Prediction Flow - Shows detailed step-by-step analysis */}
      {latest && (
        <div className="mb-6">
          <PredictionFlow queryData={latest} darkMode={darkMode} />
        </div>
      )}

      <div className="grid grid-cols-1 gap-6">
        <div className={`p-4 rounded shadow-sm border-2 transition-colors ${
          darkMode 
            ? "bg-black border-gray-900" 
            : "bg-white border-gray-200"
        }`}>
          <h3 className={`text-lg font-semibold mb-3 ${darkMode ? "text-gray-100" : "text-gray-900"}`}>Latest Query Breakdown</h3>
          {latest ? (
            <>
              <div className={`text-sm mb-2 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Query:</div>
              <div className={`text-sm mb-3 break-words ${darkMode ? "text-gray-200" : "text-gray-800"}`}>{latest.query}</div>

              <ScoreBreakdownChart scores={latest} darkMode={darkMode} />
              <div className={`mt-3 text-xs ${darkMode ? "text-gray-400" : "text-gray-500"}`}>
                Decision: <span className="font-medium">{latest.decision ?? latest.label_str ?? "-"}</span>
                {" • "}Label: <span className="font-medium">{latest.label === 1 ? "Malicious" : latest.label === 0 ? "Benign" : "-"}</span>
              </div>

              <div className={`mt-4 p-3 rounded border text-xs transition-colors ${
                darkMode 
                  ? "bg-gray-900/50 border-gray-700" 
                  : "bg-gray-50 border-gray-100"
              }`}>
                <div className={`font-semibold mb-1 ${darkMode ? "text-gray-300" : "text-gray-900"}`}>Debug (latest entry)</div>
                <div className="mb-2">
                  <strong className={darkMode ? "text-gray-300" : "text-gray-900"}>Normalized scores:</strong>
                  <pre className={`mt-1.5 ${darkMode ? "text-gray-400" : "text-gray-700"}`} style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(latestNormalized, null, 2)}</pre>
                </div>

                <details>
                  <summary className={`cursor-pointer text-sm ${darkMode ? "text-blue-400" : "text-blue-600"}`}>Show raw log JSON</summary>
                  <pre className={darkMode ? "text-gray-400" : "text-gray-700"} style={{ maxHeight: 300, overflow: "auto", marginTop: 8, whiteSpace: "pre-wrap" }}>
                    {JSON.stringify(latest, null, 2)}
                  </pre>
                </details>
              </div>
            </>
          ) : (
            <div className={`text-sm ${darkMode ? "text-gray-400" : "text-gray-500"}`}>No recent detection available.</div>
          )}
        </div>

        <div className={`p-5 rounded shadow-sm border-2 transition-colors ${
          darkMode 
            ? "bg-black border-gray-900" 
            : "bg-white border-gray-200"
        }`}>
          <h3 className={`text-xl font-semibold mb-2 ${darkMode ? "text-gray-100" : "text-gray-900"}`}>Fused Score Timeline</h3>
          <p className={`text-sm mb-4 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>
            Interactive visualization of threat detection scores over the last {timelinePoints.length} queries
          </p>
          <TimelineChart points={timelinePoints} height={240} darkMode={darkMode} />
        </div>
      </div>
    </div>
  );
}
