import React from "react";

export default function ScoreBar({ value = 0, darkMode = false }) {
  const v = Math.max(0, Math.min(1, Number(value) || 0));
  const percent = Math.round(v * 100);
  
  const getColorClasses = () => {
    if (percent >= 80) return "bg-gradient-to-r from-red-400/80 to-red-500/80";
    if (percent >= 50) return "bg-gradient-to-r from-yellow-400/80 to-amber-500/80";
    return "bg-gradient-to-r from-green-400/80 to-emerald-500/80";
  };

  return (
    <div className={`w-full h-8 rounded-lg overflow-hidden shadow-inner transition-colors ${
      darkMode ? "bg-gray-700" : "bg-gray-200"
    }`}>
      <div 
        style={{ width: `${percent}%` }} 
        className={`${getColorClasses()} h-8 flex items-center justify-center text-white text-sm font-bold transition-all duration-500 ease-out shadow-lg`}
      >
        {percent > 10 && `${percent}%`}
      </div>
    </div>
  );
}
