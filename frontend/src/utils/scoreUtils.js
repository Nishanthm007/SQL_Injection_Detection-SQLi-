// frontend/src/utils/scoreUtils.js
// Robust extraction & normalization of scores across various backend shapes.
// Now includes 'confidence' and generic 'score' handling.

function tryParseJSON(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === "object") return v;
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (!s) return null;
  if ((s.startsWith("{") && s.endsWith("}")) || (s.startsWith("[") && s.endsWith("]"))) {
    try { return JSON.parse(s); } catch (e) { return null; }
  }
  return null;
}

function toNumberSafe(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "boolean") return v ? 1 : 0;
  if (typeof v === "string") {
    const trimmed = v.trim();
    if (trimmed === "") return null;
    const cleaned = trimmed.replace(/[,]+/g, "").replace("%", "");
    const n = Number(cleaned);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

function normalizeProb(x) {
  const n = toNumberSafe(x);
  if (n === null) return null;
  if (n >= 0 && n <= 1) return n;
  if (n > 1 && n <= 1000) return Math.max(0, Math.min(1, n <= 100 ? n / 100 : n / 100));
  return Math.max(0, Math.min(1, n));
}

function scanForScores(obj = {}) {
  if (!obj || typeof obj !== "object") return {};

  // try parse if obj is a stringified JSON
  const parsedRoot = tryParseJSON(obj) || obj;
  let root = parsedRoot;

  // if some keys contain stringified JSON, merge them (scores, details, metadata)
  const merged = { ...root };
  ["scores", "details", "metadata", "meta"].forEach((k) => {
    if (k in root) {
      const p = tryParseJSON(root[k]);
      if (p && typeof p === "object") {
        Object.assign(merged, p);
      } else if (typeof root[k] === "object") {
        Object.assign(merged, root[k]);
      }
    }
  });

  root = merged;

  // common aliases
  const raw_p_cnn = root.p_cnn ?? root.cnn ?? root.cnn_score ?? root.confidence ?? root.confidence_score ?? root.p_model ?? root.p_model_score ?? null;
  const raw_p_rule = root.p_rule ?? root.rule ?? root.rule_score ?? root.rules ?? null;
  const raw_fused = root.fused ?? root.p_fused ?? root.fused_score ?? root.p_fused_score ?? root.p_final ?? root.final_score ?? root.fusion ?? root.score ?? root.scored ?? null;

  return {
    raw_p_cnn,
    raw_p_rule,
    raw_fused
  };
}

/**
 * extractScores(obj) -> { p_cnn, p_rule, fused }
 * returns numbers in [0,1] defaulting to 0 if not found.
 */
export function extractScores(obj = {}) {
  try {
    const { raw_p_cnn, raw_p_rule, raw_fused } = scanForScores(obj);

    let p_cnn = normalizeProb(raw_p_cnn);
    let p_rule = normalizeProb(raw_p_rule);
    let fused = normalizeProb(raw_fused);

    // if nothing found but "confidence" exists at top-level, treat that as p_cnn/fused
    if ((p_cnn === null || p_cnn === undefined) && typeof obj.confidence !== "undefined") {
      p_cnn = normalizeProb(obj.confidence);
    }

    // fallback: if fused missing but p_cnn and p_rule present -> average
    if ((fused === null || fused === undefined) && p_cnn !== null && p_rule !== null) {
      fused = Math.max(0, Math.min(1, (p_cnn + p_rule) / 2));
    }

    // final fallback: if fused missing but p_cnn present -> use p_cnn
    if ((fused === null || fused === undefined) && p_cnn !== null) {
      fused = p_cnn;
    }

    return {
      p_cnn: p_cnn ?? 0,
      p_rule: p_rule ?? 0,
      fused: fused ?? 0
    };
  } catch (e) {
    return { p_cnn: 0, p_rule: 0, fused: 0 };
  }
}
