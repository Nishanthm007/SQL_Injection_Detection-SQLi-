import client from "./apiClient";

/**
 * getRecentAttacks({ limit, label })
 */
export async function getRecentAttacks({ limit = 100, label = null } = {}) {
  const params = { limit };
  if (label !== null) params.label = label;
  const res = await client.get("/api/v1/detect/attacks", { params });
  return res.data;
}
