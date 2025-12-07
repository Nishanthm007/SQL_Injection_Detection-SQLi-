import React, { useMemo, useState } from "react";
import { extractScores } from "../../utils/scoreUtils";

/**
 * TimelineChart visualizes fused scores from points[] with enhanced interactivity.
 * Shows detailed information on hover and provides clear visual indicators.
 */
export default function TimelineChart({ points = [], height = 240, darkMode = false }) {
  const [hoveredPoint, setHoveredPoint] = useState(null);
  
  const w = 700;
  const h = height;
  const padding = { top: 20, right: 50, bottom: 40, left: 60 };
  const chartWidth = w - padding.left - padding.right;
  const chartHeight = h - padding.top - padding.bottom;

  const pts = useMemo(() => {
    if (!points || points.length === 0) return [];
    const limited = points.slice(0, 100);
    return limited.map((p, i) => {
      const scores = extractScores(p);
      const fused = scores.fused ?? 0;
      const x = padding.left + (i / Math.max(1, limited.length - 1)) * chartWidth;
      // In SVG: y=0 is top, y increases downward
      // For HIGH threat score (1.0 = 100%), we want LOW y value (top of chart) = padding.top
      // For LOW threat score (0.0 = 0%), we want HIGH y value (bottom of chart) = padding.top + chartHeight
      // Formula: y = top + (1 - score) * height
      // Example: score=1.0 → y = top + 0 = top (plots at top)
      // Example: score=0.0 → y = top + height (plots at bottom)
      const y = padding.top + (1 - Math.max(0, Math.min(1, fused))) * chartHeight;
      return { 
        x, 
        y, 
        fused, 
        p_cnn: scores.p_cnn ?? 0,
        p_rule: scores.p_rule ?? 0,
        time: p.time,
        query: p.query?.substring(0, 50) + (p.query?.length > 50 ? '...' : '') || 'N/A',
        index: i
      };
    });
  }, [points, chartHeight, chartWidth, padding]);

  if (pts.length === 0) {
    return <div className="text-sm text-gray-500">No timeline data</div>;
  }

  const poly = pts.map((p) => `${p.x},${p.y}`).join(" ");

  // Horizontal grid lines with labels
  const grids = [0, 0.25, 0.5, 0.75, 1].map((g) => ({
    // Grid at score g should be placed at: top + (1 - g) * height
    // g=1.0 (100%) → y = top + 0 = top
    // g=0.0 (0%) → y = top + height = bottom
    y: padding.top + (1 - g) * chartHeight,
    label: `${Math.round(g * 100)}%`,
    value: g
  }));

  // Threat level zones - positioned based on score ranges
  // Zone from score 0.6-1.0 (Dangerous/Red) should be at TOP
  // Zone from score 0.0-0.3 (Safe/Green) should be at BOTTOM
  const zones = [
    { start: 0.6, end: 1.0, color: '#fee2e2', label: 'Dangerous' },   // Top (60-100%)
    { start: 0.3, end: 0.6, color: '#fef3c7', label: 'Suspicious' },  // Middle (30-60%)
    { start: 0, end: 0.3, color: '#dcfce7', label: 'Safe' }           // Bottom (0-30%)
  ];

  return (
    <div className="w-full">
      {/* Legend */}
      <div className="mb-3 flex items-center gap-4 text-xs flex-wrap">
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded-full bg-blue-600"></div>
          <span className={darkMode ? "text-gray-300" : "text-gray-700"}>Fused Score</span>
        </div>
        <div className="flex items-center gap-4 ml-4">
          {zones.map((zone, i) => (
            <div key={i} className="flex items-center gap-1">
              <div className="w-3 h-3 rounded" style={{ backgroundColor: zone.color }}></div>
              <span className={darkMode ? "text-gray-400" : "text-gray-600"}>{zone.label} ({Math.round(zone.start * 100)}-{Math.round(zone.end * 100)}%)</span>
            </div>
          ))}
        </div>
      </div>

      <div className={`w-full overflow-auto border-2 rounded-lg p-2 ${darkMode ? "border-gray-900 bg-black" : "border-gray-200 bg-white"}`}>
        <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="w-full">
          {/* Background zones */}
          <g>
            {zones.map((zone, idx) => (
              <rect
                key={idx}
                x={padding.left}
                y={padding.top + (1 - zone.end) * chartHeight}
                width={chartWidth}
                height={(zone.end - zone.start) * chartHeight}
                fill={zone.color}
                opacity="0.3"
              />
            ))}
          </g>

          {/* Grid lines */}
          <g>
            {grids.map((g, idx) => (
              <g key={idx}>
                <line 
                  x1={padding.left} 
                  x2={padding.left + chartWidth} 
                  y1={g.y} 
                  y2={g.y} 
                  stroke="#d1d5db" 
                  strokeWidth="1" 
                  strokeDasharray={g.value === 0.5 ? "5,5" : "none"}
                />
                {/* Y-axis labels */}
                <text 
                  x={padding.left - 10} 
                  y={g.y + 4} 
                  textAnchor="end" 
                  fontSize="11" 
                  fill="#6b7280"
                >
                  {g.label}
                </text>
              </g>
            ))}
          </g>

          {/* Axes */}
          <line 
            x1={padding.left} 
            y1={padding.top} 
            x2={padding.left} 
            y2={padding.top + chartHeight} 
            stroke="#374151" 
            strokeWidth="2"
          />
          <line 
            x1={padding.left} 
            y1={padding.top + chartHeight} 
            x2={padding.left + chartWidth} 
            y2={padding.top + chartHeight} 
            stroke="#374151" 
            strokeWidth="2"
          />

          {/* Axis labels */}
          <text 
            x={padding.left + chartWidth / 2} 
            y={h - 10} 
            textAnchor="middle" 
            fontSize="12" 
            fill="#374151"
            fontWeight="600"
          >
            Detection Timeline (Most Recent →)
          </text>
          <text 
            x={15} 
            y={padding.top + chartHeight / 2} 
            textAnchor="middle" 
            fontSize="12" 
            fill="#374151"
            fontWeight="600"
            transform={`rotate(-90, 15, ${padding.top + chartHeight / 2})`}
          >
            Threat Score (%)
          </text>

          {/* Area under curve */}
          <polygon 
            points={`${padding.left},${padding.top + chartHeight} ${poly} ${padding.left + chartWidth},${padding.top + chartHeight}`}
            fill="#2563eb"
            opacity="0.1"
          />

          {/* Line */}
          <polyline 
            points={poly} 
            fill="none" 
            stroke="#2563eb" 
            strokeWidth="2.5" 
            strokeLinejoin="round" 
            strokeLinecap="round"
          />

          {/* Data points */}
          <g>
            {pts.map((p, i) => (
              <circle 
                key={i} 
                cx={p.x} 
                cy={p.y} 
                r={hoveredPoint === i ? 6 : 4} 
                fill={hoveredPoint === i ? "#1e40af" : "#2563eb"}
                stroke="#ffffff"
                strokeWidth="2"
                style={{ cursor: 'pointer', transition: 'all 0.2s' }}
                onMouseEnter={() => setHoveredPoint(i)}
                onMouseLeave={() => setHoveredPoint(null)}
              />
            ))}
          </g>

          {/* Tooltip */}
          {hoveredPoint !== null && pts[hoveredPoint] && (
            <g>
              <rect
                x={pts[hoveredPoint].x + 15}
                y={pts[hoveredPoint].y - 80}
                width="200"
                height="75"
                fill="white"
                stroke="#2563eb"
                strokeWidth="2"
                rx="4"
                filter="drop-shadow(0 4px 6px rgba(0,0,0,0.1))"
              />
              <text x={pts[hoveredPoint].x + 25} y={pts[hoveredPoint].y - 60} fontSize="11" fontWeight="600" fill="#1f2937">
                Detection #{hoveredPoint + 1}
              </text>
              <text x={pts[hoveredPoint].x + 25} y={pts[hoveredPoint].y - 45} fontSize="10" fill="#374151">
                Fused Score: {Math.round(pts[hoveredPoint].fused * 100)}%
              </text>
              <text x={pts[hoveredPoint].x + 25} y={pts[hoveredPoint].y - 32} fontSize="10" fill="#6b7280">
                CNN: {Math.round(pts[hoveredPoint].p_cnn * 100)}%
              </text>
              <text x={pts[hoveredPoint].x + 25} y={pts[hoveredPoint].y - 19} fontSize="10" fill="#6b7280">
                Rules: {Math.round(pts[hoveredPoint].p_rule * 100)}%
              </text>
              <text x={pts[hoveredPoint].x + 25} y={pts[hoveredPoint].y - 6} fontSize="9" fill="#9ca3af">
                {pts[hoveredPoint].query}
              </text>
            </g>
          )}
        </svg>
      </div>

      {/* Summary statistics */}
      <div className="mt-3 grid grid-cols-4 gap-3 text-xs">
        <div className={`p-2 rounded border-2 ${darkMode ? "bg-black border-gray-900" : "bg-gray-50 border-gray-200"}`}>
          <div className={darkMode ? "text-gray-400" : "text-gray-500"}>Total Points</div>
          <div className={`text-lg font-semibold ${darkMode ? "text-gray-200" : "text-gray-900"}`}>{points.length}</div>
        </div>
        <div className={`p-2 rounded border-2 ${darkMode ? "bg-black border-gray-900" : "bg-gray-50 border-gray-200"}`}>
          <div className={darkMode ? "text-gray-400" : "text-gray-500"}>Latest Score</div>
          <div className="text-lg font-semibold text-blue-600">{Math.round((pts[pts.length - 1]?.fused ?? 0) * 100)}%</div>
        </div>
        <div className={`p-2 rounded border-2 ${darkMode ? "bg-black border-gray-900" : "bg-gray-50 border-gray-200"}`}>
          <div className={darkMode ? "text-gray-400" : "text-gray-500"}>Average</div>
          <div className={`text-lg font-semibold ${darkMode ? "text-gray-200" : "text-gray-900"}`}>
            {Math.round((pts.reduce((sum, p) => sum + p.fused, 0) / pts.length) * 100)}%
          </div>
        </div>
        <div className={`p-2 rounded border-2 ${darkMode ? "bg-black border-gray-900" : "bg-gray-50 border-gray-200"}`}>
          <div className={darkMode ? "text-gray-400" : "text-gray-500"}>Peak Score</div>
          <div className="text-lg font-semibold text-red-600">
            {Math.round(Math.max(...pts.map(p => p.fused)) * 100)}%
          </div>
        </div>
      </div>

      {/* Description */}
      <div className={`mt-3 p-3 rounded-lg border-2 text-xs ${darkMode ? "bg-blue-900/30 border-blue-700 text-gray-300" : "bg-blue-50 border-blue-200 text-gray-700"}`}>
        <p className={`font-semibold mb-1 ${darkMode ? "text-blue-300" : "text-blue-900"}`}>📊 Understanding the Graph:</p>
        <p className="mb-2">
          This timeline shows the <strong>fused threat score</strong> for each SQL query detection over time. 
          The fused score combines CNN model predictions and rule-based engine results.
        </p>
        <ul className="list-disc list-inside space-y-1 ml-2">
          <li><strong>Green zone (0-30%)</strong>: Queries appear safe with low threat indicators</li>
          <li><strong>Yellow zone (30-60%)</strong>: Suspicious patterns detected, moderate risk</li>
          <li><strong>Red zone (60-100%)</strong>: High probability of SQL injection attack</li>
          <li><strong>Hover over data points</strong> to see detailed breakdown of CNN and rule scores</li>
        </ul>
      </div>
    </div>
  );
}
