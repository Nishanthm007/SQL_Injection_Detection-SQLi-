import React from "react";

export default function ScoreBar({ value = 0, darkMode = false }) {
  const v = Math.max(0, Math.min(1, Number(value) || 0));
  const percent = Math.round(v * 100);
  
  const getColorStyle = () => {
    if (percent >= 80) return { background: 'linear-gradient(to right, #ef4444, #dc2626)' };
    if (percent >= 50) return { background: 'linear-gradient(to right, #eab308, #d97706)' };
    return { background: 'linear-gradient(to right, #10b981, #059669)' };
  };

  return (
    <div className={`w-full h-8 rounded-lg overflow-hidden shadow-inner transition-colors ${
      darkMode ? "bg-gray-700" : "bg-gray-200"
    }`}>
      <div 
        style={{ width: `${percent}%`, ...getColorStyle() }} 
        className="h-8 flex items-center justify-center text-white text-sm font-bold transition-all duration-500 ease-out shadow-lg"
      >
        {percent > 10 && `${percent}%`}
      </div>
    </div>
  );
}
