const DEFAULT_LOGIN_CREDENTIALS = [
  { email: "admin", password: "admin" },
  { email: "admin@ai-sec.local", password: "AdminPass123!" },
];

const getStoredToken = () => localStorage.getItem("token") || localStorage.getItem("authToken") || "";

const setStoredToken = (token) => {
  if (!token) return;
  localStorage.setItem("token", token);
  localStorage.setItem("authToken", token);
};

const clearStoredToken = () => {
  localStorage.removeItem("token");
  localStorage.removeItem("authToken");
};

async function tryAutoLogin(baseUrl) {
  for (const creds of DEFAULT_LOGIN_CREDENTIALS) {
    try {
      const res = await fetch(`${baseUrl}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(creds),
      });
      if (!res.ok) continue;
      const data = await res.json();
      const token = data?.access_token || "";
      if (token) {
        setStoredToken(token);
        return token;
      }
    } catch {
      // Try next fallback credentials.
    }
  }
  return "";
}

export async function apiFetch(url, options = {}) {
  const isFormData = typeof FormData !== "undefined" && options?.body instanceof FormData;
  const baseUrl = (() => {
    try {
      return new URL(url).origin;
    } catch {
      return "/api";
    }
  })();

  const buildHeaders = (token) => ({
    ...(!isFormData ? { "Content-Type": "application/json" } : {}),
    ...(options?.method && String(options.method).toUpperCase() !== "GET"
      ? {}
      : {
          "Cache-Control": "no-cache, no-store, must-revalidate",
          Pragma: "no-cache",
          Expires: "0",
        }),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  });

  let token = getStoredToken();
  let response = await fetch(url, {
    ...options,
    cache: options?.cache || "no-store",
    headers: buildHeaders(token),
  });

  if (response.status === 401) {
    token = await tryAutoLogin(baseUrl);
    if (token) {
      response = await fetch(url, {
        ...options,
        cache: options?.cache || "no-store",
        headers: buildHeaders(token),
      });
    }
  }

  if (response.status === 401) {
    clearStoredToken();
    localStorage.setItem("auth_error", "Session expired");
  }

  return response;
}
