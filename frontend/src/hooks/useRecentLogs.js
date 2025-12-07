import { useEffect, useState, useRef, useCallback } from "react";
import { getRecentAttacks } from "../services/logsApi";

export default function useRecentLogs({ limit = 50, offset = 0, label = null, pollIntervalMs = 5000 } = {}) {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const mountedRef = useRef(true);
  const timerRef = useRef(null);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getRecentAttacks({ limit, offset, label });
      if (!mountedRef.current) return;
      setLogs(data.attacks || []);
      setTotal(data.total || 0);
    } catch (err) {
      if (!mountedRef.current) return;
      setError(err.message || "Failed to fetch logs");
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, [limit, offset, label]);

  useEffect(() => {
    mountedRef.current = true;
    fetchLogs();

    if (pollIntervalMs > 0) {
      timerRef.current = setInterval(fetchLogs, pollIntervalMs);
    }

    return () => {
      mountedRef.current = false;
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [fetchLogs, pollIntervalMs]);

  return { logs, total, loading, error, refresh: fetchLogs };
}
