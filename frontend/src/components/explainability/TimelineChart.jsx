import React, { useMemo } from "react";
import { extractScores } from "../../utils/scoreUtils";

/**
 * TimelineChart visualizes fused scores from points[].
 * It normalizes values and ensures visibility even for near-zero data.
 */
export default function TimelineChart({ points = [], height = 140 }) {
  const w = 600;
  const h = height;

  const pts = useMemo(() => {
    if (!points || points.length === 0) return [];
    // map fused to y coordinate (invert since SVG y grows down)
    // ensure max points <= 100 for performance
    const limited = points.slice(0, 100);
    return limited.map((p, i) => {
      const scores = extractScores(p);
      const fused = scores.fused ?? 0;
      const x = (i / Math.max(1, limited.length - 1)) * w;
      const y = h - (Math.max(0, Math.min(1, fused)) * (h - 10)) - 5; // padding so it's not flush to bottom
      return { x, y, fused, time: p.time };
    });
  }, [points, h]);

  if (pts.length === 0) {
    return <div className="text-sm text-gray-500">No timeline data</div>;
  }

  const poly = pts.map((p) => `${p.x},${p.y}`).join(" ");

  // horizontal baseline grid
  const grids = [0, 0.25, 0.5, 0.75, 1].map((g) => ({
    y: h - g * (h - 10) - 5,
    label: `${Math.round(g * 100)}%`
  }));

  return (
    <div className="w-full overflow-auto">
      <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="w-full">
        {/* grid lines */}
        <g>
          {grids.map((g, idx) => (
            <line key={idx} x1="0" x2={w} y1={g.y} y2={g.y} stroke="#f3f4f6" strokeWidth="1" />
          ))}
        </g>

        {/* polyline */}
        <polyline points={poly} fill="none" stroke="#2563eb" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />

        {/* circles */}
        <g>
          {pts.map((p, i) => (
            <circle key={i} cx={p.x} cy={p.y} r="3" fill="#2563eb" />
          ))}
        </g>
      </svg>

      <div className="mt-2 text-xs text-gray-500">
        Points: {points.length} • Latest value: {Math.round((pts[pts.length - 1]?.fused ?? 0) * 100)}%
      </div>
    </div>
  );
}
