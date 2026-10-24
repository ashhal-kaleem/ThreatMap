import { useState, useMemo, useEffect, useRef } from 'react';
import { IOC_CATEGORIES, IOC_PAGE_SIZE } from '../config';
import {
  countByCategory,
  matchesCategory,
  matchesQuery,
  toCSV,
  downloadFile,
  defang,
  highlightSegments,
} from '../lib/iocs';
import { SearchIcon, CopyIcon, CheckIcon, AlertIcon, DownloadIcon, ChevronIcon } from './Icons';

const COPY_FEEDBACK_MS = 2000;

const rowKey = (ioc) => `${ioc.type}|${ioc.value}|${ioc.source_page}`;

export default function IOCTable({ iocs = [], reportName = 'report' }) {
  const [selectedFilter, setSelectedFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [defanged, setDefanged] = useState(false);
  const [expanded, setExpanded] = useState(() => new Set());
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

  const display = (ioc) => (defanged ? defang(ioc.value, ioc.type) : ioc.value);

  const handleCopy = async (ioc) => {
    const key = rowKey(ioc);
    let ok = true;
    try {
      if (!navigator.clipboard) throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(display(ioc));
    } catch {
      ok = false;
    }
    setCopyState({ key, ok });
    clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopyState({ key: null, ok: true }), COPY_FEEDBACK_MS);
  };

  const toggleExpanded = (key) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const exportBase = `${reportName.replace(/\.pdf$/i, '')}_iocs${selectedFilter === 'ALL' ? '' : `_${selectedFilter.toLowerCase()}`}`;
  const exportCSV = () => downloadFile(`${exportBase}.csv`, toCSV(filteredIOCs), 'text/csv;charset=utf-8');
  const exportJSON = () =>
    downloadFile(`${exportBase}.json`, JSON.stringify(filteredIOCs, null, 2), 'application/json');

  const total = iocs.length || 1;

  return (
    <section className="ioc-section" aria-label="Extracted indicators">
      <div className="cat-grid" role="group" aria-label="Filter indicators by type">
        {IOC_CATEGORIES.map((cat) => {
          const active = selectedFilter === cat.id;
          const count = counts[cat.id];
          return (
            <button
              key={cat.id}
              type="button"
              className={`cat-card cat-${cat.id.toLowerCase()} ${active ? 'active' : ''}`}
              aria-pressed={active}
              onClick={() => setSelectedFilter(cat.id)}
            >
              <span className="cat-label">{cat.label}</span>
              <span className="cat-count">{count}</span>
              <span className="cat-meter" aria-hidden="true">
                <span style={{ width: `${cat.id === 'ALL' ? 100 : (count / total) * 100}%` }} />
              </span>
            </button>
          );
        })}
      </div>

      <div className="ioc-panel">
        <div className="ioc-toolbar">
          <div className="search-input-wrapper">
            <SearchIcon size={16} className="search-icon" />
            <input
              type="search"
              className="search-input"
              placeholder="Search indicators or evidence"
              aria-label="Search indicators and evidence"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div className="toolbar-right">
            <label className="switch">
              <input type="checkbox" checked={defanged} onChange={(e) => setDefanged(e.target.checked)} />
              <span className="switch-track" aria-hidden="true" />
              <span>Defang</span>
            </label>
            <button type="button" className="btn btn-ghost" onClick={exportCSV} disabled={!filteredIOCs.length}>
              <DownloadIcon size={15} /> CSV
            </button>
            <button type="button" className="btn btn-ghost" onClick={exportJSON} disabled={!filteredIOCs.length}>
              <DownloadIcon size={15} /> JSON
            </button>
          </div>
        </div>

        <div className="ioc-table-container">
          {filteredIOCs.length === 0 ? (
            <div className="empty-state">
              <SearchIcon size={22} />
              <p>
                {iocs.length === 0
                  ? 'No indicators were found in this report.'
                  : 'No indicators match this filter or search.'}
              </p>
            </div>
          ) : (
            <table className="ioc-table">
              <colgroup>
                <col className="col-type" />
                <col className="col-value" />
                <col className="col-page" />
                <col className="col-evidence" />
                <col className="col-actions" />
              </colgroup>
              <thead>
                <tr>
                  <th scope="col">Type</th>
                  <th scope="col">Indicator</th>
                  <th scope="col">Page</th>
                  <th scope="col">Evidence</th>
                  <th scope="col">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {pagedIOCs.map((ioc) => {
                  const key = rowKey(ioc);
                  const showFeedback = copyState.key === key;
                  const isOpen = expanded.has(key);
                  return (
                    <tr key={key} className={isOpen ? 'expanded' : ''}>
                      <td>
                        <span className={`type-badge type-${(ioc.type || '').toLowerCase()}`}>{ioc.type}</span>
                      </td>
                      <td className="ioc-value-cell">{display(ioc)}</td>
                      <td>
                        <span className="page-chip">p.{ioc.source_page}</span>
                      </td>
                      <td className="evidence-cell">
                        <p className="evidence-text">
                          {highlightSegments(ioc.evidence, ioc.value, ioc.type).map((seg, i) =>
                            seg.match ? <mark key={i}>{seg.text}</mark> : <span key={i}>{seg.text}</span>,
                          )}
                        </p>
                      </td>
                      <td className="actions-cell">
                        <button
                          type="button"
                          className={`icon-btn ${showFeedback ? (copyState.ok ? 'copied' : 'copy-failed') : ''}`}
                          title={showFeedback ? (copyState.ok ? 'Copied' : 'Copy failed') : 'Copy indicator'}
                          aria-label={`Copy ${display(ioc)}`}
                          onClick={() => handleCopy(ioc)}
                        >
                          {showFeedback ? copyState.ok ? <CheckIcon size={15} /> : <AlertIcon size={15} /> : <CopyIcon size={15} />}
                        </button>
                        <button
                          type="button"
                          className={`icon-btn expand-btn ${isOpen ? 'open' : ''}`}
                          title={isOpen ? 'Collapse evidence' : 'Show full evidence'}
                          aria-label={isOpen ? 'Collapse evidence' : 'Show full evidence'}
                          aria-expanded={isOpen}
                          onClick={() => toggleExpanded(key)}
                        >
                          <ChevronIcon size={15} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {filteredIOCs.length > 0 && (
          <div className="table-footer">
            <span className="pagination-info">
              {pageStart + 1}–{Math.min(pageStart + IOC_PAGE_SIZE, filteredIOCs.length)} of {filteredIOCs.length}
            </span>
            {filteredIOCs.length > IOC_PAGE_SIZE && (
              <nav className="pagination" aria-label="IOC table pages">
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  disabled={safePage === 1}
                >
                  Prev
                </button>
                <span className="pagination-info">
                  Page {safePage} of {totalPages}
                </span>
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  disabled={safePage === totalPages}
                >
                  Next
                </button>
              </nav>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
