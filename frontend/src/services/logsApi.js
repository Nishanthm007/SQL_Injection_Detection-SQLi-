import client from "./apiClient";

/**
 * getRecentAttacks({ limit, offset, label })
 */
export async function getRecentAttacks({ limit = 50, offset = 0, label = null } = {}) {
  const params = { limit, offset };
  if (label !== null) params.label = label;
  const res = await client.get("/api/v1/detect/attacks", { params });
  return res.data;
}
