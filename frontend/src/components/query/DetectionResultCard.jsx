import React from "react";
import ScoreBar from "./ScoreBar";
import RuleHitsList from "./RuleHitsList";

export default function DetectionResultCard({ result }) {
  const scores = result.scores || { p_cnn: result.p_cnn, p_rule: result.p_rule, fused: result.fused };

  const decisionBadge = (decision) => {
    if (!decision) return "bg-gray-100 text-gray-800";
    const d = String(decision).toLowerCase();
    if (d.startsWith("block") || d.includes("attack")) return "bg-red-100 text-red-700";
    if (d.includes("susp")) return "bg-yellow-100 text-yellow-800";
    return "bg-green-100 text-green-700";
  };

  return (
    <div className="bg-white border border-gray-100 rounded-lg shadow-sm p-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs text-gray-500">Decision</div>
          <div className="text-lg font-semibold">{result.decision ?? result.label_str}</div>
        </div>

        <div className="text-right">
          <div className="text-xs text-gray-500">Label</div>
          <div className="text-sm font-semibold">
            {result.label === 1 ? (
              <span className="px-2 py-1 rounded-full bg-red-50 text-red-700">Malicious</span>
            ) : (
              <span className="px-2 py-1 rounded-full bg-green-50 text-green-700">Benign</span>
            )}
          </div>
        </div>
      </div>

      <div className="mt-4 grid gap-3">
        <div>
          <div className="text-xs text-gray-500 mb-1">CNN</div>
          <ScoreBar value={scores.p_cnn ?? 0} />
        </div>

        <div>
          <div className="text-xs text-gray-500 mb-1">Rule Engine</div>
          <ScoreBar value={scores.p_rule ?? 0} />
        </div>

        <div>
          <div className="text-xs text-gray-500 mb-1">Fused</div>
          <ScoreBar value={scores.fused ?? 0} />
        </div>
      </div>

      <div className="mt-4">
        <div className="flex items-center justify-between">
          <div className="text-sm text-gray-600">Matched Rules</div>
          <div className={`text-xs px-2 py-1 rounded ${decisionBadge(result.decision)}`}>{result.decision ?? "N/A"}</div>
        </div>

        <RuleHitsList rules={result.rule_matches || []} />
      </div>

      <div className="mt-4 text-xs text-gray-500">
        Latency: <span className="font-medium">{result.latency_ms ?? "-"}</span> ms &nbsp;|&nbsp;
        CNN: <span className="font-medium">{result.details?.cnn_latency_ms ?? "-"}</span> ms &nbsp;|&nbsp;
        Rules: <span className="font-medium">{result.details?.rule_latency_ms ?? "-"}</span> ms
      </div>

      <details className="mt-4 bg-gray-50 p-3 rounded border border-gray-100">
        <summary className="text-sm font-medium text-gray-700 cursor-pointer">Raw response (debug)</summary>
        <pre className="mt-2 text-xs text-gray-700 overflow-auto max-h-48">{JSON.stringify(result, null, 2)}</pre>
      </details>
    </div>
  );
}
