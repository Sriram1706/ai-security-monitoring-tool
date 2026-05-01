import axios from "axios";

const API_BASE = import.meta.env.VITE_API_BASE || "/api";
const AUTH_TOKEN_KEY = "authToken";
const LEGACY_TOKEN_KEY = "token";
const DEFAULT_CREDENTIALS = [
  { email: "admin", password: "admin" },
  { email: "admin@ai-sec.local", password: "AdminPass123!" },
];

export const api = axios.create({
  baseURL: API_BASE,
});

export const getStoredToken = () => localStorage.getItem(AUTH_TOKEN_KEY) || localStorage.getItem(LEGACY_TOKEN_KEY) || "";

export const setToken = (token) => {
  if (token) {
    localStorage.setItem(AUTH_TOKEN_KEY, token);
    localStorage.setItem(LEGACY_TOKEN_KEY, token); // backward compatibility with existing fetch calls
    api.defaults.headers.common.Authorization = `Bearer ${token}`;
  } else {
    localStorage.removeItem(AUTH_TOKEN_KEY);
    localStorage.removeItem(LEGACY_TOKEN_KEY);
    delete api.defaults.headers.common.Authorization;
  }
};

export const autoLogin = async () => {
  for (const creds of DEFAULT_CREDENTIALS) {
    try {
      const { data } = await api.post("/auth/login", creds);
      if (data?.access_token) {
        setToken(data.access_token);
        return data.access_token;
      }
    } catch {
      // try next fallback credential
    }
  }
  return "";
};

export const ensureAuthToken = async () => {
  const existing = getStoredToken();
  if (existing) {
    setToken(existing);
    return existing;
  }
  return autoLogin();
};

let refreshPromise = null;

api.interceptors.request.use(async (config) => {
  const token = getStoredToken();
  if (token) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const status = error?.response?.status;
    if (status === 401) {
      if (!refreshPromise) {
        refreshPromise = autoLogin().finally(() => {
          refreshPromise = null;
        });
      }
      const newToken = await refreshPromise;
      if (newToken && error?.config && !error.config._retried) {
        error.config._retried = true;
        error.config.headers = error.config.headers || {};
        error.config.headers.Authorization = `Bearer ${newToken}`;
        return api.request(error.config);
      }
      setToken("");
      localStorage.setItem("auth_error", "Session expired");
    }
    return Promise.reject(error);
  },
);
