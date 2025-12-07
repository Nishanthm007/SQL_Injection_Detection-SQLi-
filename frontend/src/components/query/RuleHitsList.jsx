import React from "react";

export default function RuleHitsList({ rules = [] }) {
  if (!rules || rules.length === 0) {
    return <div className="text-sm text-gray-500 mt-2">No rules matched</div>;
  }

  return (
    <div className="mt-2 flex flex-wrap gap-2">
      {rules.map((r, i) => (
        <span key={i} className="inline-flex items-center gap-2 px-3 py-1 bg-yellow-50 text-yellow-800 border border-yellow-100 rounded-full text-sm">
          {r}
        </span>
      ))}
    </div>
  );
}
