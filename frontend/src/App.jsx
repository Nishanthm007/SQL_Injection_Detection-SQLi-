import React, { useState } from "react";
import QueryForm from "./components/query/QueryForm";
import LogsPage from "./pages/LogsPage";
import ExplainabilityPage from "./pages/ExplainabilityPage";

export default function App() {
  const [activeTab, setActiveTab] = useState("detect");

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
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 text-gray-900">
      <header className="bg-blue-600 text-white">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 bg-white/10 rounded flex items-center justify-center text-lg font-bold">SI</div>
            <div>
              <h1 className="text-lg font-semibold">SQL Injection Detection</h1>
              <div className="text-xs text-white/80">Hybrid CNN + Rule Engine — Dashboard</div>
            </div>
          </div>

          <nav className="flex items-center gap-2">
            <TabButton id="detect">Detect</TabButton>
            <TabButton id="logs">Logs</TabButton>
            <TabButton id="explain">Explainability</TabButton>
          </nav>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8">
        {activeTab === "detect" && (
          <>
            <div className="mb-6">
              <h2 className="text-2xl font-semibold">Detection Console</h2>
              <p className="text-sm text-gray-600 mt-1">Paste a SQL query to analyze. The detector will return decision & scores.</p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <QueryForm />
              </div>

              <div className="space-y-6">
                <div className="p-4 bg-white rounded-lg shadow-sm border border-gray-100">
                  <h3 className="text-sm font-semibold text-gray-700">Quick Tips</h3>
                  <ul className="mt-2 text-sm text-gray-600 list-disc list-inside space-y-1">
                    <li>Try tautology: <code className="bg-gray-100 px-1 rounded">OR '1'='1'</code></li>
                    <li>Try union: <code className="bg-gray-100 px-1 rounded">' UNION SELECT ... --</code></li>
                    <li>Time delay patterns are strongly blocked (SLEEP, BENCHMARK)</li>
                  </ul>
                </div>

                <div className="p-4 bg-white rounded-lg shadow-sm border border-gray-100">
                  <h3 className="text-sm font-semibold text-gray-700">Status</h3>
                  <p className="mt-2 text-sm text-gray-600">Backend: <span className="font-medium">http://127.0.0.1:8000</span></p>
                </div>
              </div>
            </div>
          </>
        )}

        {activeTab === "logs" && (
          <>
            <h2 className="text-2xl font-semibold mb-4">Recent Logs</h2>
            <LogsPage />
          </>
        )}

        {activeTab === "explain" && <ExplainabilityPage />}

      </main>
    </div>
  );
}
