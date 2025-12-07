import axios from "axios";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

const client = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
  headers: {
    "Content-Type": "application/json"
  }
});

// optional: response interceptor to unwrap certain shapes or errors
client.interceptors.response.use(
  (res) => res,
  (err) => {
    // normalize message
    if (err.response && err.response.data) {
      const data = err.response.data;
      err.message = data.message || data.detail || err.message;
    }
    return Promise.reject(err);
  }
);

export default client;
