import React, { useState, useMemo } from 'react';

export default function IOCTable({ iocs = [] }) {
  const [selectedFilter, setSelectedFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedValue, setCopiedValue] = useState(null);

  // Group hashes together or allow individual type matching
  const isHashType = (type) => ['md5', 'sha1', 'sha256'].includes(type.toLowerCase());

  // Category counts
  const counts = useMemo(() => {
    const c = { ALL: iocs.length, IPV4: 0, DOMAIN: 0, URL: 0, HASH: 0, CVE: 0 };
    iocs.forEach((item) => {
      const t = (item.type || '').toLowerCase();
      if (t === 'ipv4') c.IPV4++;
      else if (t === 'domain') c.DOMAIN++;
      else if (t === 'url') c.URL++;
      else if (isHashType(t)) c.HASH++;
      else if (t === 'cve') c.CVE++;
    });
    return c;
  }, [iocs]);

  // Filtered IOC list
  const filteredIOCs = useMemo(() => {
    return iocs.filter((item) => {
      const t = (item.type || '').toLowerCase();

      // Category filter
      let matchesCategory = true;
      if (selectedFilter === 'IPV4') matchesCategory = t === 'ipv4';
      else if (selectedFilter === 'DOMAIN') matchesCategory = t === 'domain';
      else if (selectedFilter === 'URL') matchesCategory = t === 'url';
      else if (selectedFilter === 'HASH') matchesCategory = isHashType(t);
      else if (selectedFilter === 'CVE') matchesCategory = t === 'cve';

      if (!matchesCategory) return false;

      // Text query filter
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase().trim();
        const inVal = (item.value || '').toLowerCase().includes(query);
        const inEvidence = (item.evidence || '').toLowerCase().includes(query);
        const inType = (item.type || '').toLowerCase().includes(query);
        return inVal || inEvidence || inType;
      }

      return true;
    });
  }, [iocs, selectedFilter, searchQuery]);

  const handleCopy = (value) => {
    navigator.clipboard.writeText(value);
    setCopiedValue(value);
    setTimeout(() => {
      setCopiedValue((prev) => (prev === value ? null : prev));
    }, 2000);
  };

  return (
    <div className="ioc-section">
      <div className="ioc-toolbar">
        {/* Category Filters */}
        <div className="filter-group">
          <button
            type="button"
            className={`filter-btn ${selectedFilter === 'ALL' ? 'active' : ''}`}
            onClick={() => setSelectedFilter('ALL')}
          >
            All ({counts.ALL})
          </button>
          <button
            type="button"
            className={`filter-btn ${selectedFilter === 'IPV4' ? 'active' : ''}`}
            onClick={() => setSelectedFilter('IPV4')}
          >
            IPv4 ({counts.IPV4})
          </button>
          <button
            type="button"
            className={`filter-btn ${selectedFilter === 'DOMAIN' ? 'active' : ''}`}
            onClick={() => setSelectedFilter('DOMAIN')}
          >
            Domain ({counts.DOMAIN})
          </button>
          <button
            type="button"
            className={`filter-btn ${selectedFilter === 'URL' ? 'active' : ''}`}
            onClick={() => setSelectedFilter('URL')}
          >
            URL ({counts.URL})
          </button>
          <button
            type="button"
            className={`filter-btn ${selectedFilter === 'HASH' ? 'active' : ''}`}
            onClick={() => setSelectedFilter('HASH')}
          >
            Hashes ({counts.HASH})
          </button>
          <button
            type="button"
            className={`filter-btn ${selectedFilter === 'CVE' ? 'active' : ''}`}
            onClick={() => setSelectedFilter('CVE')}
          >
            CVE ({counts.CVE})
          </button>
        </div>

        {/* Real-time search */}
        <div className="search-input-wrapper">
          <input
            type="text"
            className="search-input"
            placeholder="Search indicators, evidence..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      {/* IOC Table */}
      <div className="ioc-table-container">
        {filteredIOCs.length === 0 ? (
          <div className="empty-state">
            No indicators match the selected filter or search criteria.
          </div>
        ) : (
          <table className="ioc-table">
            <thead>
              <tr>
                <th style={{ width: '12%' }}>Type</th>
                <th style={{ width: '45%' }}>Normalized Value</th>
                <th style={{ width: '10%' }}>Page</th>
                <th style={{ width: '33%' }}>Evidence Snippet</th>
              </tr>
            </thead>
            <tbody>
              {filteredIOCs.map((ioc, idx) => {
                const typeClass = `type-${(ioc.type || '').toLowerCase()}`;
                const isCopied = copiedValue === ioc.value;

                return (
                  <tr key={`${ioc.type}-${ioc.value}-${ioc.source_page}-${idx}`}>
                    <td>
                      <span className={`type-badge ${typeClass}`}>
                        {ioc.type}
                      </span>
                    </td>
                    <td>
                      <div className="ioc-value-cell">
                        <span>{ioc.value}</span>
                        <button
                          type="button"
                          className={`copy-btn ${isCopied ? 'copied' : ''}`}
                          title="Copy indicator value"
                          onClick={() => handleCopy(ioc.value)}
                        >
                          {isCopied ? '✓ Copied' : '📋'}
                        </button>
                      </div>
                    </td>
                    <td className="page-cell">Page {ioc.source_page}</td>
                    <td className="evidence-cell" title={ioc.evidence}>
                      "{ioc.evidence}"
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
