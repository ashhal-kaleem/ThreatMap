import { describe, it, expect } from 'vitest';
import { defang, highlightSegments } from '../lib/iocs';

describe('defang', () => {
  it('defangs URLs in scheme and host only', () => {
    expect(defang('https://evil.example.com/a.php?x=1.2', 'url')).toBe('hxxps://evil[.]example[.]com/a.php?x=1.2');
  });
  it('defangs domains and IPv4', () => {
    expect(defang('evil.example.com', 'domain')).toBe('evil[.]example[.]com');
    expect(defang('1.2.3.4', 'ipv4')).toBe('1[.]2[.]3[.]4');
  });
  it('leaves hashes and CVEs unchanged', () => {
    expect(defang('CVE-2024-1234', 'cve')).toBe('CVE-2024-1234');
    expect(defang('d41d8cd98f00b204e9800998ecf8427e', 'md5')).toBe('d41d8cd98f00b204e9800998ecf8427e');
  });
});

describe('highlightSegments', () => {
  it('marks the first case-insensitive match', () => {
    expect(highlightSegments('Beacon to EVIL.com seen', 'evil.com')).toEqual([
      { text: 'Beacon to ', match: false },
      { text: 'EVIL.com', match: true },
      { text: ' seen', match: false },
    ]);
  });
  it('falls back to the defanged form used in the report', () => {
    expect(highlightSegments('get hxxps://evil[.]com/x now', 'https://evil.com/x', 'url')).toEqual([
      { text: 'get ', match: false },
      { text: 'hxxps://evil[.]com/x', match: true },
      { text: ' now', match: false },
    ]);
  });
  it('returns the whole text when the value is absent (e.g. defanged in source)', () => {
    expect(highlightSegments('evil[.]com', 'evil.com')).toEqual([{ text: 'evil[.]com', match: false }]);
  });
});
