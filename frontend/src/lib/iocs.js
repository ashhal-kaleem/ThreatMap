import { IOC_CATEGORIES } from '../config';

const typeOf = (ioc) => (ioc.type || '').toLowerCase();

export function matchesCategory(ioc, categoryId) {
  const cat = IOC_CATEGORIES.find((c) => c.id === categoryId);
  return !cat || !cat.types || cat.types.includes(typeOf(ioc));
}

export function countByCategory(iocs) {
  return Object.fromEntries(
    IOC_CATEGORIES.map((c) => [c.id, iocs.filter((i) => matchesCategory(i, c.id)).length]),
  );
}

export function matchesQuery(ioc, query) {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [ioc.value, ioc.evidence, ioc.type].some((f) => (f || '').toLowerCase().includes(q));
}

const csvCell = (v) => {
  let s = String(v ?? '');
  // Neutralise spreadsheet formula injection from report text
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
};

export function toCSV(iocs) {
  const header = ['type', 'value', 'source_page', 'evidence'];
  const rows = iocs.map((i) => header.map((h) => csvCell(i[h])).join(','));
  return [header.join(','), ...rows].join('\r\n');
}

export function downloadFile(filename, content, mime) {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
