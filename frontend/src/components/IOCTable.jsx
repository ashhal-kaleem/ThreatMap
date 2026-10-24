import { useState, useMemo, useEffect, useRef } from 'react';
import { IOC_CATEGORIES, IOC_PAGE_SIZE } from '../config';
import { countByCategory, matchesCategory, matchesQuery, toCSV, downloadFile } from '../lib/iocs';

const COPY_FEEDBACK_MS = 2000;

const rowKey = (ioc) => `${ioc.type}|${ioc.value}|${ioc.source_page}`;

export default function IOCTable({ iocs = [], reportName = 'report' }) {
  const [selectedFilter, setSelectedFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copyState, setCopyState] = useState({ key: null, ok: true });
  const [currentPage, setCurrentPage] = useState(1);
  const copyTimer = useRef(null);

  const counts = useMemo(() => countByCategory(iocs), [iocs]);

  const filteredIOCs = useMemo(
    () => iocs.filter((i) => matchesCategory(i, selectedFilter) && matchesQuery(i, searchQuery)),
    [iocs, selectedFilter, searchQuery],
  );

  // Reset to page 1 whenever the filter, search, or data changes
  useEffect(() => {
    setCurrentPage(1);
  }, [iocs, selectedFilter, searchQuery]);

  useEffect(() => () => clearTimeout(copyTimer.current), []);

  const totalPages = Math.max(1, Math.ceil(filteredIOCs.length / IOC_PAGE_SIZE));
  const safePage = Math.min(currentPage, totalPages);
  const pageStart = (safePage - 1) * IOC_PAGE_SIZE;
  const pagedIOCs = filteredIOCs.slice(pageStart, pageStart + IOC_PAGE_SIZE);

  const handleCopy = async (ioc) => {
    const key = rowKey(ioc);
    let ok = true;
    try {
      if (!navigator.clipboard) throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(ioc.value);
    } catch {
      ok = false;
    }
    setCopyState({ key, ok });
    clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopyState({ key: null, ok: true }), COPY_FEEDBACK_MS);
  };

  const exportBase = `${reportName.replace(/\.pdf$/i, '')}_iocs${selectedFilter === 'ALL' ? '' : `_${selectedFilter.toLowerCase()}`}`;
  const exportCSV = () => downloadFile(`${exportBase}.csv`, toCSV(filteredIOCs), 'text/csv;charset=utf-8');
  const exportJSON = () =>
    downloadFile(`${exportBase}.json`, JSON.stringify(filteredIOCs, null, 2), 'application/json');

  return (
    <div className="ioc-section">
      <div className="ioc-toolbar">
        <div className="filter-group" role="group" aria-label="Filter indicators by type">
          {IOC_CATEGORIES.map((cat) => (
            <button
              key={cat.id}
              type="button"
              className={`filter-btn ${selectedFilter === cat.id ? 'active' : ''}`}
              aria-pressed={selectedFilter === cat.id}
              onClick={() => setSelectedFilter(cat.id)}
            >
              {cat.label} ({counts[cat.id]})
            </button>
          ))}
        </div>

        <div className="toolbar-right">
          <div className="search-input-wrapper">
            <input
              type="search"
              className="search-input"
              placeholder="Search indicators, evidence..."
              aria-label="Search indicators and evidence"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          <button type="button" className="filter-btn" onClick={exportCSV} disabled={!filteredIOCs.length}>
            Export CSV
          </button>
          <button type="button" className="filter-btn" onClick={exportJSON} disabled={!filteredIOCs.length}>
            Export JSON
          </button>
        </div>
      </div>

      <div className="ioc-table-container">
        {filteredIOCs.length === 0 ? (
          <div className="empty-state">
            {iocs.length === 0
              ? 'No indicators were found in this report.'
              : 'No indicators match the selected filter or search criteria.'}
          </div>
        ) : (
          <table className="ioc-table">
            <colgroup>
              <col className="col-type" />
              <col className="col-value" />
              <col className="col-page" />
              <col className="col-evidence" />
            </colgroup>
            <thead>
              <tr>
                <th scope="col">Type</th>
                <th scope="col">Normalized Value</th>
                <th scope="col">Page</th>
                <th scope="col">Evidence Snippet</th>
              </tr>
            </thead>
            <tbody>
              {pagedIOCs.map((ioc) => {
                const key = rowKey(ioc);
                const showFeedback = copyState.key === key;
                return (
                  <tr key={key}>
                    <td>
                      <span className={`type-badge type-${(ioc.type || '').toLowerCase()}`}>{ioc.type}</span>
                    </td>
                    <td>
                      <div className="ioc-value-cell">
                        <span>{ioc.value}</span>
                        <button
                          type="button"
                          className={`copy-btn ${showFeedback ? (copyState.ok ? 'copied' : 'copy-failed') : ''}`}
                          title="Copy indicator value"
                          aria-label={`Copy ${ioc.value}`}
                          onClick={() => handleCopy(ioc)}
                        >
                          {showFeedback ? (copyState.ok ? '✓ Copied' : '✗ Copy failed') : '📋'}
                        </button>
                      </div>
                    </td>
                    <td className="page-cell">Page {ioc.source_page}</td>
                    <td className="evidence-cell" title={ioc.evidence}>
                      &ldquo;{ioc.evidence}&rdquo;
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {filteredIOCs.length > IOC_PAGE_SIZE && (
        <nav className="pagination" aria-label="IOC table pages">
          <button
            type="button"
            className="filter-btn"
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            disabled={safePage === 1}
          >
            ← Prev
          </button>
          <span className="pagination-info">
            {pageStart + 1}–{Math.min(pageStart + IOC_PAGE_SIZE, filteredIOCs.length)} of {filteredIOCs.length} · Page{' '}
            {safePage} of {totalPages}
          </span>
          <button
            type="button"
            className="filter-btn"
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            disabled={safePage === totalPages}
          >
            Next →
          </button>
        </nav>
      )}
    </div>
  );
}
