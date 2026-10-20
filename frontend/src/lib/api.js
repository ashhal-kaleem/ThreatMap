import { API_BASE_URL } from '../config';

export const apiUrl = (path) => `${API_BASE_URL}${path}`;

/** Turns a FastAPI error body (string or validation array) into a readable message. */
export function errorMessageFrom(body, status) {
  const detail = body && body.detail;
  if (typeof detail === 'string' && detail.trim()) return detail;
  if (Array.isArray(detail) && detail.length) {
    return detail.map((d) => d.msg || JSON.stringify(d)).join('; ');
  }
  return `Server responded with status ${status}`;
}

/** fetch + JSON parse; throws Error with the backend's message on non-2xx. */
export async function apiFetch(path, options = {}) {
  const res = await fetch(apiUrl(path), options);
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error(errorMessageFrom(body, res.status));
    err.status = res.status;
    throw err;
  }
  return body;
}
