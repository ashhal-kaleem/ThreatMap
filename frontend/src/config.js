// Central frontend configuration. Values come from Vite env vars (see .env.example)
// so nothing environment-specific is hardcoded in components.

// Base URL of the ThreatMap API. Empty string = same origin (Vite dev proxy).
export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/+$/, '');

// Fallback upload limit used only until the backend reports its own limit via /health.
export const DEFAULT_MAX_UPLOAD_MB = Number(import.meta.env.VITE_MAX_UPLOAD_MB) || 50;

// Rows per page in the IOC table.
export const IOC_PAGE_SIZE = Number(import.meta.env.VITE_IOC_PAGE_SIZE) || 25;

// IOC filter categories: label shown in the UI and backend types each one covers.
export const IOC_CATEGORIES = [
  { id: 'ALL', label: 'All', types: null },
  { id: 'IPV4', label: 'IPv4', types: ['ipv4'] },
  { id: 'DOMAIN', label: 'Domain', types: ['domain'] },
  { id: 'URL', label: 'URL', types: ['url'] },
  { id: 'HASH', label: 'Hashes', types: ['md5', 'sha1', 'sha256'] },
  { id: 'CVE', label: 'CVE', types: ['cve'] },
];
