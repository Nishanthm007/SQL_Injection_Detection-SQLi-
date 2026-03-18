import React, { useState } from "react";

export default function LogsTable({ logs, darkMode = false }) {
  const [expandedRow, setExpandedRow] = useState(null);

  if (!logs || logs.length === 0) {
    return (
      <div className="text-center py-16">
        <div className="text-6xl mb-4">📭</div>
        <p className={`text-lg font-medium ${darkMode ? "text-gray-400" : "text-gray-500"}`}>No logs available</p>
        <p className={`text-sm mt-2 ${darkMode ? "text-gray-500" : "text-gray-400"}`}>Queries will appear here once detected</p>
      </div>
    );
  }

  const formatDate = (dateString) => {
    if (!dateString) return "-";
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const getDecisionBadge = (decision) => {
    const badges = {
      'ALLOW': { bg: 'bg-green-100', text: 'text-green-800', icon: '✓' },
      'BLOCK_RISKY_RULE': { bg: 'bg-red-100', text: 'text-red-800', icon: '🛡️' },
      'BLOCK': { bg: 'bg-red-100', text: 'text-red-800', icon: '🚫' },
      'hybrid': { bg: 'bg-blue-100', text: 'text-blue-800', icon: '🔀' },
      'rules_fallback': { bg: 'bg-yellow-100', text: 'text-yellow-800', icon: '⚠️' }
    };
    
    const badge = badges[decision] || { bg: 'bg-gray-100', text: 'text-gray-800', icon: '❓' };
    
    return (
      <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-semibold ${badge.bg} ${badge.text}`}>
        <span>{badge.icon}</span>
        {decision}
      </span>
    );
  };

  const getLatencyColor = (latency) => {
    if (latency < 300) return 'text-green-600 bg-green-50';
    if (latency < 800) return 'text-yellow-600 bg-yellow-50';
    return 'text-red-600 bg-red-50';
  };

  return (
    <div className="overflow-x-auto">
      <table className={`min-w-full divide-y ${darkMode ? "divide-gray-700" : "divide-gray-200"}`}>
        <thead className={`${darkMode ? "bg-gradient-to-r from-gray-800 to-gray-900" : "bg-gradient-to-r from-gray-100 to-gray-50"}`}>
          <tr>
            <th className={`px-6 py-4 text-left text-xs font-bold uppercase tracking-wider ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
              #
            </th>
            <th className={`px-6 py-4 text-left text-xs font-bold uppercase tracking-wider ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
              Query
            </th>
            <th className={`px-6 py-4 text-left text-xs font-bold uppercase tracking-wider ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
              Label
            </th>
            <th className={`px-6 py-4 text-left text-xs font-bold uppercase tracking-wider ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
              Decision
            </th>
            <th className={`px-6 py-4 text-left text-xs font-bold uppercase tracking-wider ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
              Latency
            </th>
            <th className={`px-6 py-4 text-left text-xs font-bold uppercase tracking-wider ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
              Detected At
            </th>
            <th className={`px-6 py-4 text-left text-xs font-bold uppercase tracking-wider ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
              Actions
            </th>
          </tr>
        </thead>

        <tbody className={`${darkMode ? "bg-black divide-y divide-gray-800" : "bg-white divide-y divide-gray-200"}`}>
          {logs.map((log, i) => {
            const isExpanded = expandedRow === log.id;
            const latencyMs = Math.round(Number(log.latency_ms) || 0);
            
            return (
              <React.Fragment key={log.id || i}>
                <tr 
                  className={`${darkMode ? "hover:bg-gray-900" : "hover:bg-blue-50"} transition-colors cursor-pointer ${
                    isExpanded ? (darkMode ? 'bg-gray-900 border-l-4 border-blue-500' : 'bg-blue-50 border-l-4 border-blue-500') : ''
                  }`}
                  onClick={() => setExpandedRow(isExpanded ? null : log.id)}
                >
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <span className={`w-8 h-8 flex items-center justify-center rounded-full text-sm font-semibold ${darkMode ? "bg-gray-700 text-gray-300" : "bg-gray-100 text-gray-700"}`}>
                        {log.id ?? i + 1}
                      </span>
                    </div>
                  </td>
                  
                  <td className="px-6 py-4">
                    <div className="max-w-md">
                      <p className={`text-sm font-mono truncate ${darkMode ? "text-gray-300" : "text-gray-900"}`}>
                        {log.query}
                      </p>
                    </div>
                  </td>
                  
                  <td className="px-6 py-4 whitespace-nowrap">
                    {log.label === 1 ? (
                      <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold bg-red-100 text-red-800 border border-red-200">
                        <span className="text-base">🚨</span>
                        Malicious
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold bg-green-100 text-green-800 border border-green-200">
                        <span className="text-base">✅</span>
                        Benign
                      </span>
                    )}
                  </td>
                  
                  <td className="px-6 py-4 whitespace-nowrap">
                    {getDecisionBadge(log.decision_source)}
                  </td>
                  
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-lg text-xs font-semibold ${getLatencyColor(latencyMs)}`}>
                      <span>⚡</span>
                      {latencyMs} ms
                    </span>
                  </td>
                  
                  <td className={`px-6 py-4 whitespace-nowrap text-sm ${darkMode ? "text-gray-400" : "text-gray-600"}`}>
                    <div className="flex items-center gap-2">
                      <span className={darkMode ? "text-gray-500" : "text-gray-400"}>🕐</span>
                      {formatDate(log.detected_at)}
                    </div>
                  </td>
                  
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setExpandedRow(isExpanded ? null : log.id);
                      }}
                      className={`font-medium hover:underline ${darkMode ? "text-blue-400 hover:text-blue-300" : "text-blue-600 hover:text-blue-800"}`}
                    >
                      {isExpanded ? '▼ Hide' : '▶ Details'}
                    </button>
                  </td>
                </tr>
                
                {/* Expanded Row Details */}
                {isExpanded && (
                  <tr className={`${darkMode ? "bg-gradient-to-r from-gray-900 to-gray-800" : "bg-gradient-to-r from-blue-50 to-purple-50"} border-l-4 border-blue-500`}>
                    <td colSpan="7" className="px-6 py-6">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* Full Query */}
                        <div className="col-span-full">
                          <h4 className={`text-sm font-bold mb-2 flex items-center gap-2 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
                            <span>💬</span> Full Query
                          </h4>
                          <div className={`p-4 rounded-lg font-mono text-sm overflow-x-auto shadow-inner ${darkMode ? "bg-gray-950 text-green-300" : "bg-gray-900 text-green-400"}`}>
                            {log.query}
                          </div>
                        </div>
                        
                        {/* Scores */}
                        <div>
                          <h4 className={`text-sm font-bold mb-3 flex items-center gap-2 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
                            <span>📊</span> Detection Scores
                          </h4>
                          <div className="space-y-2">
                            <div className={`flex items-center justify-between p-3 rounded-lg shadow-sm ${darkMode ? "bg-gray-800 border border-gray-700" : "bg-white"}`}>
                              <span className={`text-sm ${darkMode ? "text-gray-400" : "text-gray-600"}`}>CNN Score</span>
                              <span className="font-bold text-purple-600">{log.cnn_score ? (log.cnn_score * 100).toFixed(1) : 0}%</span>
                            </div>
                            <div className={`flex items-center justify-between p-3 rounded-lg shadow-sm ${darkMode ? "bg-gray-800 border border-gray-700" : "bg-white"}`}>
                              <span className={`text-sm ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Rule Score</span>
                              <span className="font-bold text-orange-600">{log.rule_score ? (log.rule_score * 100).toFixed(1) : 0}%</span>
                            </div>
                            <div className={`flex items-center justify-between p-3 rounded-lg shadow-sm border-2 ${darkMode ? "bg-gray-800 border-blue-600" : "bg-white border-blue-300"}`}>
                              <span className={`text-sm ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Fused Score</span>
                              <span className="font-bold text-blue-600">{log.fused_score ? (log.fused_score * 100).toFixed(1) : 0}%</span>
                            </div>
                          </div>
                        </div>
                        
                        {/* Performance Metrics */}
                        <div>
                          <h4 className={`text-sm font-bold mb-3 flex items-center gap-2 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
                            <span>⏱️</span> Performance Metrics
                          </h4>
                          <div className="space-y-2">
                            <div className={`flex items-center justify-between p-3 rounded-lg shadow-sm ${darkMode ? "bg-gray-800 border border-gray-700" : "bg-white"}`}>
                              <span className={`text-sm ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Total Latency</span>
                              <span className={`font-bold ${darkMode ? "text-gray-200" : "text-gray-900"}`}>{latencyMs} ms</span>
                            </div>
                            <div className={`flex items-center justify-between p-3 rounded-lg shadow-sm ${darkMode ? "bg-gray-800 border border-gray-700" : "bg-white"}`}>
                              <span className={`text-sm ${darkMode ? "text-gray-400" : "text-gray-600"}`}>CNN Latency</span>
                              <span className={`font-bold ${darkMode ? "text-gray-200" : "text-gray-900"}`}>{log.cnn_latency_ms ? Math.round(log.cnn_latency_ms) : 'N/A'} ms</span>
                            </div>
                            <div className={`flex items-center justify-between p-3 rounded-lg shadow-sm ${darkMode ? "bg-gray-800 border border-gray-700" : "bg-white"}`}>
                              <span className={`text-sm ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Rule Latency</span>
                              <span className={`font-bold ${darkMode ? "text-gray-200" : "text-gray-900"}`}>{log.rule_latency_ms ? Math.round(log.rule_latency_ms) : 'N/A'} ms</span>
                            </div>
                          </div>
                        </div>
                        
                        {/* Additional Info */}
                        {(log.source_ip || log.query_hash) && (
                          <div className="col-span-full">
                            <h4 className={`text-sm font-bold mb-3 flex items-center gap-2 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
                              <span>ℹ️</span> Additional Information
                            </h4>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                              {log.source_ip && (
                                <div className={`p-3 rounded-lg shadow-sm ${darkMode ? "bg-gray-800 border border-gray-700" : "bg-white"}`}>
                                  <span className={`text-xs ${darkMode ? "text-gray-500" : "text-gray-500"}`}>Source IP</span>
                                  <p className={`text-sm font-mono mt-1 ${darkMode ? "text-gray-300" : "text-gray-900"}`}>{log.source_ip}</p>
                                </div>
                              )}
                              {log.query_hash && (
                                <div className={`p-3 rounded-lg shadow-sm ${darkMode ? "bg-gray-800 border border-gray-700" : "bg-white"}`}>
                                  <span className={`text-xs ${darkMode ? "text-gray-500" : "text-gray-500"}`}>Query Hash</span>
                                  <p className={`text-sm font-mono mt-1 truncate ${darkMode ? "text-gray-300" : "text-gray-900"}`}>{log.query_hash}</p>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
