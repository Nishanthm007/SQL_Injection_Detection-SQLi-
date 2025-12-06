import React, { useState, useEffect } from "react";
import useRecentLogs from "../hooks/useRecentLogs";
import LogsTable from "../components/logs/LogsTable";
import LogFilters from "../components/logs/LogFilters";
import DownloadLogsButton from "../components/logs/DownloadLogsButton";
export default function LogsPage() {
  const [label, setLabel] = useState(null);
  const { logs, total, loading, error, refresh } = useRecentLogs({
    limit: 100,
    label,
    pollIntervalMs: 5000,
  });

  // when label changes, refresh immediately
  useEffect(() => {
    refresh();
  }, [label]);

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold">Recent Attacks</h3>
          <div className="text-sm text-gray-500">
            Total: <span className="font-medium">{total}</span>
          </div>
        </div>
      </div>
    <div>
      <div className="flex items-center gap-4, py-4">
        <DownloadLogsButton
          limit={100}
          label={label}
          filenamePrefix="sqli_logs"
        />
      </div>
    </div>
      <LogFilters label={label} setLabel={setLabel} refresh={refresh} />

      {loading && <div className="text-gray-600">Loading logs...</div>}
      {error && (
        <div className="text-red-600 bg-red-50 p-3 rounded">{error}</div>
      )}

      <LogsTable logs={logs} />
    </div>
  );
}
