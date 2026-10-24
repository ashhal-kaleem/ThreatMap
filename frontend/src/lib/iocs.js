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

// Defang an indicator for safe display/sharing (hxxps://evil[.]com/path, 1.2.3[.]4).
// Hashes and CVEs are returned unchanged.
export function defang(value, type) {
  const v = String(value ?? '');
  const t = (type || '').toLowerCase();
  if (t === 'domain' || t === 'ipv4') return v.replace(/\./g, '[.]');
  if (t === 'url') {
    const m = v.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/i);
    if (!m) return v.replace(/\./g, '[.]');
    const scheme = m[1].replace(/^http/i, (s) => (s === 'HTTP' ? 'HXXP' : 'hxxp'));
    return `${scheme}://${m[2].replace(/\./g, '[.]')}${m[3]}`;
  }
  return v;
}

// Split an evidence snippet around the first case-insensitive occurrence of the indicator,
// so the UI can highlight it. Returns [{ text, match }] segments.
// When the report wrote the indicator defanged (hxxp, [.]), that form is matched instead.
export function highlightSegments(evidence, value, type) {
  const text = String(evidence ?? '');
  const lower = text.toLowerCase();
  let needle = String(value ?? '');
  if (!needle) return [{ text, match: false }];
  let idx = lower.indexOf(needle.toLowerCase());
  if (idx === -1 && type) {
    needle = defang(value, type);
    idx = lower.indexOf(needle.toLowerCase());
  }
  if (idx === -1) return [{ text, match: false }];
  return [
    { text: text.slice(0, idx), match: false },
    { text: text.slice(idx, idx + needle.length), match: true },
    { text: text.slice(idx + needle.length), match: false },
  ].filter((s) => s.text);
}
