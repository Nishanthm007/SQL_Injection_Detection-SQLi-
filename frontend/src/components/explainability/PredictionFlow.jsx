import React, { useState } from "react";
import { extractScores } from "../../utils/scoreUtils";

/**
 * PredictionFlow - Visual representation of how the model makes predictions
 * Shows the complete flow from input query to final decision
 */
export default function PredictionFlow({ queryData, darkMode = false }) {
  const [expandedStage, setExpandedStage] = useState(null);
  
  if (!queryData) {
    return (
      <div className={`text-center py-8 ${darkMode ? "text-gray-400" : "text-gray-500"}`}>
        <p>No query data available. Submit a query to see the prediction flow.</p>
      </div>
    );
  }

  const scores = extractScores(queryData);
  const query = queryData.query || queryData.sql || "";
  
  // Debug: Log the scores extraction
  console.log("PredictionFlow - queryData:", queryData);
  console.log("PredictionFlow - extracted scores:", scores);
  
  // Determine decision from multiple sources
  let decision = "Unknown";
  let isMalicious = false;
  
  // Check label first (0 = benign, 1 = malicious)
  if (queryData.label === 1) {
    decision = "Malicious";
    isMalicious = true;
  } else if (queryData.label === 0) {
    decision = "Benign";
    isMalicious = false;
  } 
  // Check decision_source or decision field
  else if (queryData.decision_source || queryData.decision) {
    const decisionSource = queryData.decision_source || queryData.decision;
    if (decisionSource === "MALICIOUS" || decisionSource === "malicious" || decisionSource === "attack") {
      decision = "Malicious";
      isMalicious = true;
    } else if (decisionSource === "BENIGN" || decisionSource === "benign" || decisionSource === "safe") {
      decision = "Benign";
      isMalicious = false;
    } else if (decisionSource === "SUSPICIOUS" || decisionSource === "suspicious") {
      decision = "Suspicious";
      isMalicious = true;
    }
  }
  // Check label_str
  else if (queryData.label_str) {
    const labelStr = queryData.label_str.toLowerCase();
    if (labelStr === "malicious" || labelStr === "attack") {
      decision = "Malicious";
      isMalicious = true;
    } else if (labelStr === "benign" || labelStr === "safe") {
      decision = "Benign";
      isMalicious = false;
    } else if (labelStr === "suspicious") {
      decision = "Suspicious";
      isMalicious = true;
    }
  }
  // Fallback: use fused score to determine
  else if (scores.fused !== null && scores.fused !== undefined) {
    if (scores.fused >= 0.5) {
      decision = "Malicious";
      isMalicious = true;
    } else {
      decision = "Benign";
      isMalicious = false;
    }
  }

  // Calculate percentages
  const cnnPercent = Math.round(Math.max(0, Math.min(1, scores.p_cnn || 0)) * 100);
  const rulePercent = Math.round(Math.max(0, Math.min(1, scores.p_rule || 0)) * 100);
  const fusedPercent = Math.round(Math.max(0, Math.min(1, scores.fused || 0)) * 100);

  // Determine threat level
  const getThreatLevel = (score) => {
    if (score < 30) return { level: "Low", color: "green", bgColor: "bg-green-100", textColor: "text-green-800" };
    if (score < 60) return { level: "Medium", color: "yellow", bgColor: "bg-yellow-100", textColor: "text-yellow-800" };
    return { level: "High", color: "red", bgColor: "bg-red-100", textColor: "text-red-800" };
  };

  const cnnThreat = getThreatLevel(cnnPercent);
  const ruleThreat = getThreatLevel(rulePercent);
  const fusedThreat = getThreatLevel(fusedPercent);

  const stages = [
    {
      id: 1,
      title: "📝 Input Query",
      subtitle: "Raw SQL Query",
      color: "blue",
      icon: "📝",
      content: (
        <div className="space-y-2">
          <div className={`p-4 rounded-lg font-mono text-sm overflow-x-auto ${darkMode ? "bg-gray-900 text-emerald-300 border-2 border-gray-900" : "bg-gray-900 text-green-400"}`}>
            {query}
          </div>
          <p className={`text-xs ${darkMode ? "text-gray-300" : "text-gray-600"}`}>
            The system receives your SQL query and prepares it for analysis by both the CNN model and rule-based engine.
          </p>
        </div>
      )
    },
    {
      id: 2,
      title: "🧠 CNN Deep Learning Analysis",
      subtitle: `Threat Score: ${cnnPercent}%`,
      color: "purple",
      score: cnnPercent,
      threat: cnnThreat,
      content: (
        <div className="space-y-3">
          {/* Progress bar */}
          <div className="relative">
            <div className={`w-full h-10 rounded-xl overflow-hidden border-2 shadow-inner ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-gray-200 border-gray-300'}`}>
              <div 
                style={{ width: `${cnnPercent}%` }}
                className={`h-full ${cnnPercent >= 60 ? 'bg-gradient-to-b from-red-400 via-red-500 to-red-600' : cnnPercent >= 30 ? 'bg-gradient-to-b from-yellow-300 via-yellow-400 to-yellow-500' : 'bg-gradient-to-b from-green-400 via-green-500 to-green-600'} transition-all duration-1000 ease-out flex items-center justify-center shadow-lg relative`}
              >
                <div className="absolute inset-0 bg-gradient-to-b from-white/30 to-transparent rounded-lg"></div>
                <span className="font-bold text-sm relative z-10" style={{textShadow: '0 1px 2px rgba(0,0,0,0.5)', color: 'white'}}>{cnnPercent}%</span>
              </div>
            </div>
          </div>

          {/* CNN Analysis breakdown */}
          <div className="grid grid-cols-2 gap-3">
            <div className={`p-3 rounded-lg border-2 ${darkMode ? "bg-black/50 border-gray-900" : "bg-purple-50 border-purple-200"}`}>
              <div className={`text-xs mb-1 ${darkMode ? "text-gray-300" : "text-purple-600"}`}>Pattern Recognition</div>
              <div className={`text-sm font-semibold ${darkMode ? "text-gray-200" : "text-purple-900"}`}>Neural Network</div>
              <div className={`text-xs mt-1 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Analyzes character sequences & patterns</div>
            </div>
            <div className={`p-3 rounded-lg border-2 ${darkMode ? "bg-black/50 border-gray-900" : "bg-purple-50 border-purple-200"}`}>
              <div className={`text-xs mb-1 ${darkMode ? "text-gray-300" : "text-purple-600"}`}>Confidence Level</div>
              <div className={`text-sm font-semibold ${cnnThreat.textColor}`}>{cnnThreat.level} Risk</div>
              <div className={`text-xs mt-1 ${darkMode ? "text-gray-300" : "text-gray-600"}`}>Based on trained attack patterns</div>
            </div>
          </div>

          <div className={`p-3 rounded-lg border-2 text-xs ${darkMode ? "bg-blue-500/10 border-blue-900 backdrop-blur-sm" : "bg-blue-50 border-blue-200"}`}>
            <p className={`font-semibold mb-1 ${darkMode ? "text-blue-400" : "text-blue-900"}`}>🔍 How CNN Analyzes:</p>
            <ul className={`list-disc list-inside space-y-1 ml-2 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
              <li>Converts query into numerical sequences (tokenization)</li>
              <li>Passes through multiple neural network layers</li>
              <li>Identifies malicious patterns learned from 1000s of examples</li>
              <li>Outputs probability score (0-100%) of being an attack</li>
            </ul>
          </div>
        </div>
      )
    },
    {
      id: 3,
      title: "📋 Rule-Based Engine Analysis",
      subtitle: `Threat Score: ${rulePercent}%`,
      color: "orange",
      score: rulePercent,
      threat: ruleThreat,
      content: (
        <div className="space-y-3">
          {/* Progress bar */}
          <div className="relative">
            <div className={`w-full h-10 rounded-xl overflow-hidden border-2 shadow-inner ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-gray-200 border-gray-300'}`}>
              <div 
                style={{ width: `${rulePercent}%` }}
                className={`h-full ${rulePercent >= 60 ? 'bg-gradient-to-b from-red-400 via-red-500 to-red-600' : rulePercent >= 30 ? 'bg-gradient-to-b from-yellow-300 via-yellow-400 to-yellow-500' : 'bg-gradient-to-b from-green-400 via-green-500 to-green-600'} transition-all duration-1000 ease-out flex items-center justify-center shadow-lg relative`}
              >
                <div className="absolute inset-0 bg-gradient-to-b from-white/30 to-transparent rounded-lg"></div>
                <span className="font-bold text-sm relative z-10" style={{textShadow: '0 1px 2px rgba(0,0,0,0.5)', color: 'white'}}>{rulePercent}%</span>
              </div>
            </div>
          </div>

          {/* Rule engine breakdown */}
          <div className="grid grid-cols-2 gap-3">
            <div className={`p-3 rounded-lg border-2 ${darkMode ? "bg-black/50 border-gray-900" : "bg-orange-50 border-orange-200"}`}>
              <div className={`text-xs mb-1 ${darkMode ? "text-gray-300" : "text-orange-600"}`}>Pattern Matching</div>
              <div className={`text-sm font-semibold ${darkMode ? "text-gray-200" : "text-orange-900"}`}>Expert Rules</div>
              <div className={`text-xs mt-1 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>Checks against known attack signatures</div>
            </div>
            <div className={`p-3 rounded-lg border-2 ${darkMode ? "bg-black/50 border-gray-900" : "bg-orange-50 border-orange-200"}`}>
              <div className={`text-xs mb-1 ${darkMode ? "text-gray-300" : "text-orange-600"}`}>Detection Status</div>
              <div className={`text-sm font-semibold ${ruleThreat.textColor}`}>{ruleThreat.level} Risk</div>
              <div className={`text-xs mt-1 ${darkMode ? "text-gray-300" : "text-gray-600"}`}>Based on security rules</div>
            </div>
          </div>

          <div className={`p-3 rounded-lg border-2 text-xs ${darkMode ? "bg-black/50 border-gray-900" : "bg-yellow-50 border-yellow-200"}`}>
            <p className={`font-semibold mb-1 ${darkMode ? "text-gray-200" : "text-yellow-900"}`}>⚡ Rule Engine Checks:</p>
            <ul className={`list-disc list-inside space-y-1 ml-2 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
              <li>Scans for SQL keywords (UNION, SELECT, DROP, etc.)</li>
              <li>Detects special characters and comment sequences</li>
              <li>Identifies logical operators used in attacks (OR 1=1)</li>
              <li>Matches against database of known injection patterns</li>
            </ul>
          </div>
        </div>
      )
    },
    {
      id: 4,
      title: "🔀 Fusion Layer",
      subtitle: `Combined Score: ${fusedPercent}%`,
      color: "indigo",
      score: fusedPercent,
      threat: fusedThreat,
      content: (
        <div className="space-y-3">
          {/* Fusion visualization */}
          <div className={`p-4 rounded-lg border-2 ${darkMode ? "bg-black/50 border-gray-900" : "bg-gradient-to-r from-purple-100 via-indigo-100 to-orange-100 border-indigo-300"}`}>
            <div className="text-center mb-3">
              <div className={`text-sm font-semibold mb-2 ${darkMode ? "text-white" : "text-gray-700"}`}>Intelligent Score Fusion</div>
              <div className="flex items-center justify-center gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-purple-600">{cnnPercent}%</div>
                  <div className="text-xs text-gray-600">CNN</div>
                </div>
                <div className="text-3xl text-indigo-600">⚡</div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-orange-600">{rulePercent}%</div>
                  <div className="text-xs text-gray-600">Rules</div>
                </div>
                <div className="text-3xl text-indigo-600">→</div>
                <div className="text-center">
                  <div className={`text-3xl font-bold ${fusedPercent >= 60 ? 'text-red-600' : fusedPercent >= 30 ? 'text-yellow-600' : 'text-green-600'}`}>
                    {fusedPercent}%
                  </div>
                  <div className="text-xs text-gray-600">Fused</div>
                </div>
              </div>
            </div>
          </div>

          {/* Fusion progress bar */}
          <div className="relative">
            <div className="w-full bg-gray-200 h-10 rounded-lg overflow-hidden">
              <div 
                style={{ width: `${fusedPercent}%` }}
                className={`h-10 ${fusedPercent >= 60 ? 'bg-gradient-to-r from-red-500 via-red-600 to-red-700' : fusedPercent >= 30 ? 'bg-gradient-to-r from-yellow-500 via-yellow-600 to-yellow-700' : 'bg-gradient-to-r from-green-500 via-green-600 to-green-700'} transition-all duration-1000 ease-out flex items-center justify-center shadow-lg`}
              >
                <span className="font-bold text-lg" style={{color: 'white'}}>{fusedPercent}%</span>
              </div>
            </div>
          </div>

          <div className={`p-3 rounded-lg border-2 text-xs ${darkMode ? "bg-black/50 border-gray-900" : "bg-indigo-50 border-indigo-200"}`}>
            <p className={`font-semibold mb-1 ${darkMode ? "text-gray-200" : "text-indigo-900"}`}>🎯 Fusion Process:</p>
            <ul className={`list-disc list-inside space-y-1 ml-2 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
              <li>Combines CNN's pattern recognition with rule-based logic</li>
              <li>Weights both scores using sophisticated algorithms</li>
              <li>CNN excels at novel attacks, Rules catch known patterns</li>
              <li>Creates a more robust, comprehensive threat assessment</li>
            </ul>
          </div>
        </div>
      )
    },
    {
      id: 5,
      title: "✅ Final Decision",
      subtitle: decision,
      color: isMalicious ? "red" : "green",
      finalDecision: true,
      content: (
        <div className="space-y-3">
          {/* Decision banner */}
          <div className={`p-6 rounded-xl shadow-lg text-center ${
            darkMode 
              ? `${isMalicious ? 'bg-gradient-to-r from-red-500 to-red-600' : 'bg-gradient-to-r from-green-500 to-green-600'} text-white`
              : `${isMalicious ? 'bg-red-100 border-2 border-red-300' : 'bg-green-100 border-2 border-green-300'}`
          }`}>
            <div className="text-6xl mb-3">{isMalicious ? '🚨' : '✅'}</div>
            <div className={`text-3xl font-bold mb-2 ${darkMode ? 'text-white' : (isMalicious ? 'text-red-900' : 'text-green-900')}`}>{decision}</div>
            <div className={`text-lg ${darkMode ? 'text-white opacity-90' : (isMalicious ? 'text-red-800' : 'text-green-800')}`}>
              {isMalicious ? 'SQL Injection Attack Detected' : 'Query is Safe'}
            </div>
            <div className={`mt-4 text-sm inline-block px-4 py-2 rounded-lg ${
              darkMode 
                ? 'bg-white/20 text-white' 
                : (isMalicious ? 'bg-red-200 text-red-900' : 'bg-green-200 text-green-900')
            }`}>
              Confidence: {fusedPercent}%
            </div>
          </div>

          {/* Decision breakdown */}
          <div className="grid grid-cols-3 gap-3">
            <div className={`${cnnThreat.bgColor} p-3 rounded-lg border-2 ${cnnPercent >= 60 ? 'border-red-300' : cnnPercent >= 30 ? 'border-yellow-300' : 'border-green-300'}`}>
              <div className="text-xs text-gray-600 mb-1">CNN Analysis</div>
              <div className={`text-2xl font-bold ${cnnThreat.textColor}`}>{cnnPercent}%</div>
              <div className={`text-xs font-semibold ${cnnThreat.textColor} mt-1`}>{cnnThreat.level}</div>
            </div>
            <div className={`${ruleThreat.bgColor} p-3 rounded-lg border-2 ${rulePercent >= 60 ? 'border-red-300' : rulePercent >= 30 ? 'border-yellow-300' : 'border-green-300'}`}>
              <div className="text-xs text-gray-600 mb-1">Rule Engine</div>
              <div className={`text-2xl font-bold ${ruleThreat.textColor}`}>{rulePercent}%</div>
              <div className={`text-xs font-semibold ${ruleThreat.textColor} mt-1`}>{ruleThreat.level}</div>
            </div>
            <div className={`${fusedThreat.bgColor} p-3 rounded-lg border-2 ${fusedPercent >= 60 ? 'border-red-400' : fusedPercent >= 30 ? 'border-yellow-400' : 'border-green-400'}`}>
              <div className="text-xs text-gray-600 mb-1">Final Score</div>
              <div className={`text-2xl font-bold ${fusedThreat.textColor}`}>{fusedPercent}%</div>
              <div className={`text-xs font-semibold ${fusedThreat.textColor} mt-1`}>{fusedThreat.level}</div>
            </div>
          </div>

          <div className={`p-4 rounded-lg border-2 text-xs ${darkMode ? (isMalicious ? 'bg-red-500/10 border-red-500/30 backdrop-blur-sm' : 'bg-emerald-500/10 border-emerald-500/30 backdrop-blur-sm') : (isMalicious ? 'bg-red-50 border-red-300' : 'bg-green-50 border-green-300')}`}>
            <p className={`font-semibold mb-2 ${darkMode ? (isMalicious ? 'text-red-400' : 'text-emerald-400') : (isMalicious ? 'text-red-900' : 'text-green-900')}`}>
              {isMalicious ? '⚠️ Why This is Malicious:' : '✅ Why This is Safe:'}
            </p>
            <ul className={`list-disc list-inside space-y-1 ml-2 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
              {isMalicious ? (
                <>
                  <li>Fused score ({fusedPercent}%) exceeds safe threshold (typically 50%)</li>
                  <li>Both CNN and Rule engines detected suspicious patterns</li>
                  <li>Query contains characteristics typical of SQL injection attacks</li>
                  <li>Recommended action: Block this query and log the attempt</li>
                </>
              ) : (
                <>
                  <li>Fused score ({fusedPercent}%) is within safe range</li>
                  <li>No malicious patterns detected by CNN or Rule engine</li>
                  <li>Query structure appears to be legitimate SQL</li>
                  <li>Recommended action: Allow query execution</li>
                </>
              )}
            </ul>
          </div>
        </div>
      )
    }
  ];

  return (
    <div className="space-y-4">
      {/* Flow diagram */}
      <div className={`p-6 rounded-xl border-2 ${darkMode ? "bg-black border-gray-800" : "bg-gradient-to-r from-blue-50 to-purple-50 border-blue-200"}`}>
        <h3 className={`text-xl font-bold mb-4 flex items-center gap-2 ${darkMode ? "text-white" : "text-gray-800"}`}>
          <span className="text-2xl">🔬</span>
          Prediction Analysis Flow
        </h3>
        
        {stages.map((stage, index) => (
          <div key={stage.id}>
            <div 
              className={`rounded-lg shadow-md border-2 hover:shadow-lg transition-all duration-300 cursor-pointer ${
                expandedStage === stage.id ? 'border-blue-500' : (darkMode ? 'border-gray-900 bg-black' : 'border-gray-200 bg-white')
              }`}
              onClick={() => setExpandedStage(expandedStage === stage.id ? null : stage.id)}
            >
              <div className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 flex-1">
                    <div className={`w-10 h-10 rounded-full bg-gradient-to-br ${
                      stage.color === 'blue' ? 'from-blue-400 to-blue-600' :
                      stage.color === 'purple' ? 'from-purple-400 to-purple-600' :
                      stage.color === 'orange' ? 'from-orange-400 to-orange-600' :
                      stage.color === 'indigo' ? 'from-indigo-400 to-indigo-600' :
                      stage.color === 'red' ? 'from-red-400 to-red-600' :
                      'from-green-400 to-green-600'
                    } flex items-center justify-center text-white font-bold text-lg shadow-md`}>
                      {stage.id}
                    </div>
                    <div className="flex-1">
                      <div className={`font-semibold flex items-center gap-2 ${darkMode ? "text-gray-100" : "text-gray-800"}`}>
                        {stage.title}
                      </div>
                      <div className={`text-sm ${
                        stage.finalDecision 
                          ? (isMalicious ? 'text-red-600 font-semibold' : 'text-green-600 font-semibold')
                          : (darkMode ? 'text-gray-400' : 'text-gray-600')
                      }`}>
                        {stage.subtitle}
                      </div>
                    </div>
                  </div>
                  
                  {/* Score indicator */}
                  {stage.score !== undefined && (
                    <div className={`${stage.threat.bgColor} ${stage.threat.textColor} px-4 py-2 rounded-lg font-bold text-lg mr-3`}>
                      {stage.score}%
                    </div>
                  )}
                  
                  <div className={`text-2xl transform transition-transform duration-300 ${
                    expandedStage === stage.id ? 'rotate-180' : ''
                  }`}>
                    ▼
                  </div>
                </div>
                
                {/* Expanded content */}
                {expandedStage === stage.id && (
                  <div className={`mt-4 pt-4 border-t ${darkMode ? "border-gray-700" : "border-gray-200"}`}>
                    {stage.content}
                  </div>
                )}
              </div>
            </div>
            
            {/* Connector arrow */}
            {index < stages.length - 1 && (
              <div className="flex justify-center py-2">
                <div className="text-3xl text-gray-400">↓</div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Summary explanation */}
      <div className={`p-5 rounded-xl shadow-sm border-2 ${darkMode ? "bg-black border-gray-800" : "bg-white border-gray-200"}`}>
        <h4 className={`font-bold text-lg mb-3 flex items-center gap-2 ${darkMode ? "text-white" : "text-gray-800"}`}>
          <span className="text-2xl">💡</span>
          Understanding the Prediction Process
        </h4>
        <div className={`space-y-3 text-sm ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
          <p className="leading-relaxed">
            Our hybrid SQL injection detection system uses a <strong>two-pronged approach</strong> to analyze queries with maximum accuracy:
          </p>
          
          <div className="grid md:grid-cols-2 gap-4">
            <div className={`p-4 rounded-lg border-2 ${darkMode ? "bg-black/50 border-gray-900" : "bg-purple-50 border-purple-200"}`}>
              <div className={`font-semibold mb-2 flex items-center gap-2 ${darkMode ? "text-gray-200" : "text-purple-900"}`}>
                <span className="text-xl">🧠</span> CNN Deep Learning
              </div>
              <p className={`text-xs ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
                A neural network trained on thousands of SQL injection examples. It excels at detecting <strong>novel and obfuscated attacks</strong> by recognizing complex patterns that traditional rules might miss.
              </p>
            </div>
            
            <div className={`p-4 rounded-lg border-2 ${darkMode ? "bg-black/50 border-gray-900" : "bg-orange-50 border-orange-200"}`}>
              <div className={`font-semibold mb-2 flex items-center gap-2 ${darkMode ? "text-gray-200" : "text-orange-900"}`}>
                <span className="text-xl">📋</span> Rule-Based Engine
              </div>
              <p className={`text-xs ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
                Expert-crafted rules that check for <strong>known attack signatures</strong> and malicious keywords. Fast and reliable for catching common injection techniques.
              </p>
            </div>
          </div>
          
          <div className={`p-4 rounded-lg border-2 ${darkMode ? "bg-black/50 border-gray-900" : "bg-indigo-50 border-indigo-200"}`}>
            <div className={`font-semibold mb-2 flex items-center gap-2 ${darkMode ? "text-gray-200" : "text-indigo-900"}`}>
              <span className="text-xl">🔀</span> Intelligent Fusion
            </div>
            <p className={`text-xs ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
              The fusion layer combines both scores using weighted algorithms. This creates a <strong>comprehensive threat assessment</strong> that leverages the strengths of both approaches while minimizing false positives.
            </p>
          </div>
          
          <div className={`p-4 rounded-lg border-2 mt-4 ${darkMode ? "bg-black/50 border-gray-900" : "bg-gradient-to-r from-blue-100 to-purple-100 border-blue-300"}`}>
            <p className={`text-xs ${darkMode ? "text-gray-200" : "text-gray-800"}`}>
              🎯 <strong>Result:</strong> A robust, multi-layered defense that catches both known attacks and emerging threats, with scores from 0% (safe) to 100% (malicious). Queries typically above 50-60% are flagged as attacks.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
