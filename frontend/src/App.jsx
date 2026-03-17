import React, { useState, useEffect } from "react";
import QueryForm from "./components/query/QueryForm";
import LogsPage from "./pages/LogsPage";
import ExplainabilityPage from "./pages/ExplainabilityPage";

export default function App() {
  const [activeTab, setActiveTab] = useState("detect");
  const [showNavbarGrid, setShowNavbarGrid] = useState(true);
  const [darkMode, setDarkMode] = useState(() => {
    // Check localStorage or default to dark mode
    const saved = localStorage.getItem("darkMode");
    if (saved !== null) return JSON.parse(saved);
    return true; // Default to dark mode
  });

  useEffect(() => {
    // Save preference to localStorage
    localStorage.setItem("darkMode", JSON.stringify(darkMode));
    // Update document class
    if (darkMode) {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
  }, [darkMode]);

  useEffect(() => {
    // Only track scroll when on detect tab
    if (activeTab !== "detect") {
      setShowNavbarGrid(false);
      return;
    }

    const handleScroll = () => {
      // Hero section height is approximately 500px (400px minHeight + padding)
      // Show grid if we're within the hero section area (first 500px of scroll)
      const heroSectionEnd = 500;
      setShowNavbarGrid(window.scrollY < heroSectionEnd);
    };

    // Set initial state
    handleScroll();
    
    // Add scroll listener
    window.addEventListener('scroll', handleScroll);
    
    // Cleanup
    return () => window.removeEventListener('scroll', handleScroll);
  }, [activeTab]);

  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
  };

  const TabButton = ({ id, children }) => (
    <button
      onClick={() => setActiveTab(id)}
      className={
        "px-3 py-1 rounded-md text-sm transition " +
        (activeTab === id
          ? "bg-white/10 border border-white/20 font-semibold"
          : "hover:bg-white/5")
      }
    >
      {children}
    </button>
  );

  return (
    <div className={`min-h-screen transition-colors duration-300 relative ${
      darkMode 
        ? "bg-black text-gray-100" 
        : "bg-white text-gray-900"
    }`}>
      
      <header className={`fixed top-0 left-0 right-0 z-50 transition-colors duration-300 backdrop-blur-md ${
        darkMode ? "bg-black/70 text-white" : "bg-white/90 text-gray-900 border-b border-gray-200"
      }`} style={showNavbarGrid && activeTab === "detect" ? {
        backgroundImage: darkMode 
          ? 'linear-gradient(rgba(59, 130, 246, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(59, 130, 246, 0.1) 1px, transparent 1px)'
          : 'linear-gradient(rgba(0, 0, 0, 0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 0, 0, 0.08) 1px, transparent 1px)',
        backgroundSize: '30px 30px',
        backgroundPosition: '0 0',
        transition: 'background-image 0.3s ease'
      } : {}}>
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4 cursor-pointer" onClick={() => setActiveTab("detect")}>
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center text-2xl font-bold shadow-lg transition-all relative ${
              darkMode 
                ? "bg-gradient-to-br from-cyan-500 via-blue-600 to-purple-700 text-white" 
                : "bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-700 text-white"
            }`} style={{boxShadow: darkMode ? '0 0 20px rgba(6, 182, 212, 0.4), 0 0 40px rgba(59, 130, 246, 0.2)' : '0 4px 20px rgba(0,0,0,0.3)'}}>
              <svg className="w-7 h-7" fill="currentColor" viewBox="0 0 24 24" style={{filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.3))'}}>
                <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" opacity="0.6"/>
                <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
                <circle cx="12" cy="12" r="1.5" fill="white" opacity="0.9"/>
              </svg>
              <div className="absolute inset-0 rounded-xl border-2 border-white/20"></div>
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight" style={{fontFamily: 'Orbitron, monospace', letterSpacing: '0.05em'}}>SQLShield</h1>
              <div className={`text-xs font-medium ${darkMode ? 'text-white/80' : 'text-gray-600'}`} style={{fontFamily: 'Share Tech Mono, monospace'}}>Hybrid CNN + Rule Engine</div>
            </div>
          </div>

          <nav className="flex items-center gap-3">
            <TabButton id="detect">Detect</TabButton>
            <TabButton id="logs">Logs</TabButton>
            <TabButton id="explain">Explainability</TabButton>
            
            {/* Dark Mode Toggle */}
            <button
              onClick={toggleDarkMode}
              className={`ml-2 relative w-14 h-7 rounded-full transition-all duration-500 ${
                darkMode 
                  ? "bg-gradient-to-r from-blue-900 to-indigo-900 border-2 border-blue-500/50" 
                  : "bg-gradient-to-r from-sky-200 to-blue-300 border-2 border-blue-400"
              }`}
              title={darkMode ? "Switch to Light Mode" : "Switch to Dark Mode"}
            >
              {/* Sliding Circle */}
              <div className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full transition-all duration-500 flex items-center justify-center ${
                darkMode 
                  ? "translate-x-7 bg-gradient-to-br from-gray-700 to-gray-900 shadow-[0_0_10px_rgba(59,130,246,0.5)]" 
                  : "translate-x-0 bg-gradient-to-br from-yellow-300 to-yellow-500 shadow-[0_0_12px_rgba(234,179,8,0.8)]"
              }`}>
                {darkMode ? (
                  <svg className="w-3 h-3 text-blue-300" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M21.64 13a1 1 0 00-1.05-.14 8.05 8.05 0 01-3.37.73 8.15 8.15 0 01-8.14-8.1 8.59 8.59 0 01.25-2A1 1 0 008 2.36a10.14 10.14 0 1014 11.69 1 1 0 00-.36-1.05z"/>
                  </svg>
                ) : (
                  <svg className="w-3.5 h-3.5 drop-shadow-lg" viewBox="0 0 24 24">
                    <circle cx="12" cy="12" r="4" fill="#1f2937"/>
                    <path d="M12 2v2m0 16v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M2 12h2m16 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" stroke="#1f2937" strokeWidth="1.5" strokeLinecap="round"/>
                  </svg>
                )}
              </div>
              
              {/* Background Stars/Sun rays */}
              <div className="absolute inset-0 rounded-full overflow-hidden">
                {darkMode ? (
                  <div className="opacity-40">
                    <div className="absolute top-1 left-2 w-0.5 h-0.5 bg-blue-300 rounded-full animate-pulse"></div>
                    <div className="absolute top-3 left-4 w-0.5 h-0.5 bg-blue-400 rounded-full animate-pulse" style={{animationDelay: '0.3s'}}></div>
                    <div className="absolute top-2 right-2 w-0.5 h-0.5 bg-indigo-300 rounded-full animate-pulse" style={{animationDelay: '0.6s'}}></div>
                  </div>
                ) : (
                  <div className="absolute inset-0 flex items-center justify-center opacity-50">
                    <div className="w-6 h-6 rounded-full bg-yellow-400/40 animate-ping"></div>
                  </div>
                )}
              </div>
            </button>
          </nav>
        </div>
      </header>

      {/* Continuous Grid Background - From navbar through hero section */}
      {activeTab === "detect" && (
        <div className="fixed top-0 left-0 right-0 pointer-events-none" style={{
          height: 'calc(80px + 32px + 400px + 64px)', // navbar + padding-top + hero min-height + padding-bottom
          zIndex: 5,
          backgroundImage: darkMode 
            ? 'linear-gradient(rgba(59, 130, 246, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(59, 130, 246, 0.1) 1px, transparent 1px)'
            : 'linear-gradient(rgba(0, 0, 0, 0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 0, 0, 0.08) 1px, transparent 1px)',
          backgroundSize: '30px 30px',
          backgroundPosition: '0 0',
          maskImage: 'linear-gradient(to bottom, rgba(0,0,0,1) 0%, rgba(0,0,0,1) 85%, rgba(0,0,0,0) 100%)',
          WebkitMaskImage: 'linear-gradient(to bottom, rgba(0,0,0,1) 0%, rgba(0,0,0,1) 85%, rgba(0,0,0,0) 100%)',
          opacity: showNavbarGrid ? 1 : 0,
          transition: 'opacity 0.3s ease'
        }}></div>
      )}

      {/* Spacer to prevent content from going under fixed navbar */}
      <div className="h-20"></div>

      <main className="px-6 py-8">
        {activeTab === "detect" && (
          <>
            {/* Hero Section */}
            <div className="mb-8 -mx-6">
              <div className={`relative overflow-hidden shadow-2xl transition-colors duration-300 ${
                darkMode 
                  ? "bg-gradient-to-br from-black via-gray-900 to-black" 
                  : "bg-gradient-to-br from-gray-50 via-blue-50 to-gray-100"
              }`} style={{minHeight: '400px'}}>
                {/* Grid is handled by the fixed overlay above */}
                <div className="relative z-10 flex flex-col items-center justify-center text-center py-16 px-8">
                  {/* Main Title */}
                  <h1 className={`font-bold mb-4 ${
                    darkMode 
                      ? "text-7xl text-white" 
                      : "text-7xl text-gray-900"
                  }`} style={{fontFamily: 'Orbitron, sans-serif', letterSpacing: '0.05em'}}>
                    SQLShield
                  </h1>
                  
                  {/* Tagline */}
                  <p className={`text-xl mb-8 max-w-3xl ${
                    darkMode 
                      ? "text-blue-400" 
                      : "text-blue-600"
                  }`} style={{fontFamily: 'Share Tech Mono, monospace'}}>
                    Advanced SQL injection detection powered by Hybrid CNN + Rule Engine. Real-time analysis, always up-to-date.
                  </p>

                  {/* System Status Badge */}
                  <div className={`flex items-center gap-2 backdrop-blur-sm px-6 py-3 rounded-full border ${
                    darkMode 
                      ? "bg-white/10 border-white/30" 
                      : "bg-white/60 border-gray-300"
                  }`}>
                    <span className="relative flex h-3 w-3">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-3 w-3 bg-green-400"></span>
                    </span>
                    <span className={`text-sm font-medium ${darkMode ? "text-white" : "text-gray-900"}`}>System Active</span>
                  </div>
                  
                  {/* Stats Row */}
                  <div className="mt-12 grid grid-cols-3 gap-6 w-full max-w-4xl">
                    <div className={`backdrop-blur-sm rounded-lg p-4 border transition-colors ${
                      darkMode 
                        ? "bg-white/5 border-gray-700/60" 
                        : "bg-white/60 border-gray-300"
                    }`}>
                      <div className={`text-xs font-medium uppercase tracking-wider ${darkMode ? "text-white/80" : "text-gray-600"}`}>Detection Engine</div>
                      <div className={`text-xl font-bold mt-2 ${darkMode ? "text-white" : "text-gray-900"}`}>🤖 Hybrid AI</div>
                    </div>
                    <div className={`backdrop-blur-sm rounded-lg p-4 border transition-colors ${
                      darkMode 
                        ? "bg-white/5 border-gray-700/60" 
                        : "bg-white/60 border-gray-300"
                    }`}>
                      <div className={`text-xs font-medium uppercase tracking-wider ${darkMode ? "text-white/80" : "text-gray-600"}`}>Response Time</div>
                      <div className={`text-xl font-bold mt-2 ${darkMode ? "text-white" : "text-gray-900"}`}>⚡ ~250ms</div>
                    </div>
                    <div className={`backdrop-blur-sm rounded-lg p-4 border transition-colors ${
                      darkMode 
                        ? "bg-white/5 border-gray-700/60" 
                        : "bg-white/60 border-gray-300"
                    }`}>
                      <div className={`text-xs font-medium uppercase tracking-wider ${darkMode ? "text-white/80" : "text-gray-600"}`}>Protection Status</div>
                      <div className={`text-xl font-bold mt-2 ${darkMode ? "text-white" : "text-gray-900"}`}>🔒 Active</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Main Content Grid */}
            <div className="max-w-7xl mx-auto">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Query Form - Takes 2 columns */}
                <div className="lg:col-span-2">
                <QueryForm darkMode={darkMode} />
              </div>

              {/* Sidebar - Takes 1 column */}
              <div className="space-y-6">
                {/* Quick Tips Card */}
                <div className={`p-6 rounded-xl shadow-lg border-2 hover:shadow-xl transition-all ${
                  darkMode 
                    ? "bg-gradient-to-br from-gray-800 to-gray-850 border-gray-700" 
                    : "bg-gradient-to-br from-amber-50 to-orange-50 border-amber-200"
                }`}>
                  <div className="flex items-center gap-2 mb-4">
                    <span className="text-2xl">💡</span>
                    <h3 className={`text-lg font-bold ${darkMode ? "text-gray-200" : "text-amber-900"}`}>Quick Tips</h3>
                  </div>
                  <ul className={`space-y-3 text-sm ${darkMode ? "text-gray-300" : "text-amber-900"}`}>
                    <li className="flex items-start gap-2">
                      <span className={`font-bold mt-0.5 ${darkMode ? "text-gray-400" : "text-amber-600"}`}>•</span>
                      <div>
                        <span className="font-semibold">Tautology:</span>
                        <code className={`block mt-1 px-2 py-1 rounded text-xs font-mono border ${
                          darkMode 
                            ? "bg-gray-900 border-gray-600 text-gray-300" 
                            : "bg-white/60 border-amber-300"
                        }`}>OR '1'='1'</code>
                      </div>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className={`font-bold mt-0.5 ${darkMode ? "text-gray-400" : "text-amber-600"}`}>•</span>
                      <div>
                        <span className="font-semibold">Union Injection:</span>
                        <code className={`block mt-1 px-2 py-1 rounded text-xs font-mono border ${
                          darkMode 
                            ? "bg-gray-900 border-gray-600 text-gray-300" 
                            : "bg-white/60 border-amber-300"
                        }`}>' UNION SELECT ... --</code>
                      </div>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className={`font-bold mt-0.5 ${darkMode ? "text-gray-400" : "text-amber-600"}`}>•</span>
                      <div>
                        <span className="font-semibold">Time Delays:</span>
                        <span className="block mt-1 text-xs">SLEEP & BENCHMARK patterns are strongly blocked</span>
                      </div>
                    </li>
                  </ul>
                </div>

                {/* Detection Features Card */}
                <div className={`p-6 rounded-xl shadow-lg border-2 hover:shadow-xl transition-all ${
                  darkMode 
                    ? "bg-gradient-to-br from-gray-800 to-gray-850 border-gray-700" 
                    : "bg-gradient-to-br from-purple-50 to-pink-50 border-purple-200"
                }`}>
                  <div className="flex items-center gap-2 mb-4">
                    <span className="text-2xl">🎯</span>
                    <h3 className={`text-lg font-bold ${darkMode ? "text-gray-200" : "text-purple-900"}`}>Detection Features</h3>
                  </div>
                  <div className="space-y-3">
                    <div className="flex items-center gap-3">
                      <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-lg ${
                        darkMode ? "bg-gray-700/50" : "bg-purple-200"
                      }`}>🧠</div>
                      <div>
                        <div className={`text-sm font-semibold ${darkMode ? "text-gray-200" : "text-purple-900"}`}>CNN Analysis</div>
                        <div className={`text-xs ${darkMode ? "text-gray-400" : "text-purple-700"}`}>Deep learning patterns</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-lg ${
                        darkMode ? "bg-gray-700/50" : "bg-pink-200"
                      }`}>📋</div>
                      <div>
                        <div className={`text-sm font-semibold ${darkMode ? "text-gray-200" : "text-purple-900"}`}>Rule Engine</div>
                        <div className={`text-xs ${darkMode ? "text-gray-400" : "text-purple-700"}`}>Pattern matching</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-lg ${
                        darkMode ? "bg-gray-700/50" : "bg-purple-300"
                      }`}>⚡</div>
                      <div>
                        <div className={`text-sm font-semibold ${darkMode ? "text-gray-200" : "text-purple-900"}`}>Fusion System</div>
                        <div className={`text-xs ${darkMode ? "text-gray-400" : "text-purple-700"}`}>Intelligent combining</div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* System Info Card */}
                <div className={`p-6 rounded-xl shadow-lg border-2 hover:shadow-xl transition-all ${
                  darkMode 
                    ? "bg-gradient-to-br from-gray-800 to-gray-850 border-gray-700" 
                    : "bg-gradient-to-br from-green-50 to-emerald-50 border-green-200"
                }`}>
                  <div className="flex items-center gap-2 mb-4">
                    <span className="text-2xl">⚙️</span>
                    <h3 className={`text-lg font-bold ${darkMode ? "text-gray-200" : "text-green-900"}`}>System Status</h3>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className={`text-sm ${darkMode ? "text-gray-300" : "text-green-800"}`}>Backend API</span>
                      <span className={`px-2 py-1 text-xs font-bold rounded ${
                        darkMode 
                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30" 
                          : "bg-green-200 text-green-900"
                      }`}>ONLINE</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className={`text-sm ${darkMode ? "text-gray-300" : "text-green-800"}`}>Model Loaded</span>
                      <span className={`px-2 py-1 text-xs font-bold rounded ${
                        darkMode 
                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30" 
                          : "bg-green-200 text-green-900"
                      }`}>READY</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className={`text-sm ${darkMode ? "text-gray-300" : "text-green-800"}`}>Endpoint</span>
                      <code className={`text-xs font-mono px-2 py-1 rounded border ${
                        darkMode 
                          ? "bg-black/30 border-green-700" 
                          : "bg-white/60 border-green-300"
                      }`}>:8000</code>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          </>
        )}

        {activeTab === "logs" && (
          <div className="max-w-7xl mx-auto">
            <LogsPage darkMode={darkMode} />
          </div>
        )}

        {activeTab === "explain" && (
          <div className="max-w-7xl mx-auto">
            <ExplainabilityPage darkMode={darkMode} />
          </div>
        )}
      </main>
    </div>
  );
}
