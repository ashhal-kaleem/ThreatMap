import { describe, it, expect } from 'vitest';
import { countByCategory, matchesCategory, matchesQuery, toCSV } from '../lib/iocs';
import { errorMessageFrom } from '../lib/api';

const iocs = [
  { type: 'ipv4', value: '185.220.101.1', source_page: 1, evidence: 'C2 server' },
  { type: 'md5', value: 'a'.repeat(32), source_page: 2, evidence: 'dropper hash' },
  { type: 'sha256', value: 'b'.repeat(64), source_page: 2, evidence: 'payload' },
  { type: 'cve', value: 'CVE-2021-44228', source_page: 3, evidence: 'Log4Shell' },
];

describe('IOC helpers', () => {
  it('counts categories with hashes grouped', () => {
    expect(countByCategory(iocs)).toMatchObject({ ALL: 4, IPV4: 1, HASH: 2, CVE: 1, DOMAIN: 0, URL: 0 });
  });

  it('filters by category and query', () => {
    expect(iocs.filter((i) => matchesCategory(i, 'HASH'))).toHaveLength(2);
    expect(iocs.filter((i) => matchesQuery(i, 'log4'))).toHaveLength(1);
    expect(iocs.filter((i) => matchesQuery(i, '  '))).toHaveLength(4);
  });

  it('escapes CSV and neutralises formula injection', () => {
    const csv = toCSV([{ type: 'url', value: '=HYPERLINK("x")', source_page: 1, evidence: 'say "hi"' }]);
    expect(csv).toContain(`"'=HYPERLINK(""x"")"`);
    expect(csv).toContain('"say ""hi"""');
  });

  it('formats FastAPI error bodies', () => {
    expect(errorMessageFrom({ detail: 'File too big' }, 413)).toBe('File too big');
    expect(errorMessageFrom({ detail: [{ msg: 'field required' }] }, 422)).toBe('field required');
    expect(errorMessageFrom(null, 500)).toBe('Server responded with status 500');
  });
});
