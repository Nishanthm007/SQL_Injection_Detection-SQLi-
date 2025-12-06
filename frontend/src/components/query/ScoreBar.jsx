import React from "react";

export default function ScoreBar({ value = 0 }) {
  const v = Math.max(0, Math.min(1, Number(value) || 0));
  const percent = Math.round(v * 100);
  const bg =
    percent >= 80 ? "bg-red-500" :
    percent >= 50 ? "bg-yellow-500" : "bg-green-500";

  return (
    <div className="w-full bg-gray-200 h-7 rounded-md overflow-hidden">
      <div style={{ width: `${percent}%` }} className={`${bg} h-7 flex items-center justify-center text-white text-xs font-semibold`}>
        {percent}%
      </div>
    </div>
  );
}
