import React, { useMemo } from "react";
import useRecentLogs from "../hooks/useRecentLogs";
import ScoreBreakdownChart from "../components/explainability/ScoreBreakdownChart";
import TimelineChart from "../components/explainability/TimelineChart";
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

export default function ExplainabilityPage() {
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
      <div className="mb-4">
        <h2 className="text-2xl font-semibold">Model Explainability</h2>
        <p className="text-sm text-gray-600">Visualize how CNN, Rule-engine and fusion contributed to decisions.</p>
      </div>

      {loading && <div className="text-gray-600">Loading explainability data...</div>}
      {error && <div className="text-red-600 bg-red-50 p-3 rounded">{error}</div>}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white p-4 rounded shadow-sm border border-gray-100">
          <h3 className="text-lg font-semibold mb-3">Latest Query Breakdown</h3>
          {latest ? (
            <>
              <div className="text-sm text-gray-600 mb-2">Query:</div>
              <div className="text-sm text-gray-800 mb-3 break-words">{latest.query}</div>

              <ScoreBreakdownChart scores={latest} />
              <div className="mt-3 text-xs text-gray-500">
                Decision: <span className="font-medium">{latest.decision ?? latest.label_str ?? "-"}</span>
                {" • "}Label: <span className="font-medium">{latest.label === 1 ? "Malicious" : latest.label === 0 ? "Benign" : "-"}</span>
              </div>

              <div className="mt-4 p-3 bg-gray-50 rounded border border-gray-100 text-xs">
                <div className="font-semibold mb-1">Debug (latest entry)</div>
                <div className="mb-2">
                  <strong>Normalized scores:</strong>
                  <pre style={{ whiteSpace: "pre-wrap", marginTop: 6 }}>{JSON.stringify(latestNormalized, null, 2)}</pre>
                </div>

                <details>
                  <summary className="cursor-pointer text-sm text-blue-600">Show raw log JSON</summary>
                  <pre style={{ maxHeight: 300, overflow: "auto", marginTop: 8, whiteSpace: "pre-wrap" }}>
                    {JSON.stringify(latest, null, 2)}
                  </pre>
                </details>
              </div>
            </>
          ) : (
            <div className="text-sm text-gray-500">No recent detection available.</div>
          )}
        </div>

        <div className="bg-white p-4 rounded shadow-sm border border-gray-100">
          <h3 className="text-lg font-semibold mb-3">Fused Score Timeline</h3>
          <div className="text-sm text-gray-600 mb-2">Last {timelinePoints.length} detections</div>
          <TimelineChart points={timelinePoints} height={180} />
          <div className="mt-3 text-xs text-gray-500">
            Note: timeline shows fused score (blend of CNN & rules) per detection.
          </div>
        </div>
      </div>
    </div>
  );
}
