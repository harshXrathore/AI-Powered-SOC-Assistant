import axios from "axios";

/**
 * Central Axios instance for all backend requests.
 *
 * Base URL resolves to the Nginx-proxied /api path in Docker, or directly
 * to the FastAPI dev server via VITE_API_BASE_URL when running outside
 * Docker. Auth token attachment and 401-refresh interceptors land in
 * Phase 2 alongside the auth module.
 */
export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? "/api/v1",
  timeout: 15_000,
  headers: {
    "Content-Type": "application/json",
  },
});
