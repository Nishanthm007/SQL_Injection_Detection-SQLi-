import client from "./apiClient";

/**
 * detectQuery(query)
 * POST /api/v1/detect
 */
export async function detectQuery(query) {
  const payload = {
    query,
    metadata: {
      user_agent: navigator.userAgent,
      ip_address: "frontend-ui"
    }
  };

  const res = await client.post("/api/v1/detect", payload);
  return res.data;
}
