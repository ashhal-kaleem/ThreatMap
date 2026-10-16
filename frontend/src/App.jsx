import React, { useState, useEffect } from 'react';
import UploadZone from './components/UploadZone';
import IOCTable from './components/IOCTable';

export default function App() {
  const [currentReport, setCurrentReport] = useState(null);
  const [iocs, setIocs] = useState([]);
  const [isUploading, setIsUploading] = useState(false);
  const [backendOnline, setBackendOnline] = useState(null);

  // Check backend health on mount
  useEffect(() => {
    fetch('/health')
      .then((res) => res.json())
      .then(() => setBackendOnline(true))
      .catch(() => setBackendOnline(false));
  }, []);

  const handleUploadSuccess = async (reportId, filename) => {
    try {
      // Fetch full report results
      const res = await fetch(`/reports/${reportId}/results`);
      if (res.ok) {
        const data = await res.json();
        setCurrentReport({
          id: data.report_id,
          fileName: filename || data.file_name,
          pageCount: data.page_count,
          createdAt: data.created_at,
          summary: data.ioc_summary || {},
        });
        setIocs(data.iocs || []);
      } else {
        // Fallback to /iocs endpoint
        const iocRes = await fetch(`/reports/${reportId}/iocs`);
        const iocData = await iocRes.json();
        setCurrentReport({
          id: reportId,
          fileName: filename,
          pageCount: null,
          createdAt: new Date().toISOString(),
          summary: {},
        });
        setIocs(iocData || []);
      }
    } catch (err) {
      console.error('Failed to retrieve report results:', err);
    }
  };

  const handleReset = () => {
    setCurrentReport(null);
    setIocs([]);
  };

  return (
    <div className="app-container">
      {/* Application Header */}
      <header className="app-header">
        <div className="brand-section">
          <span className="brand-logo">🛡️</span>
          <h1 className="brand-title">ThreatMap Lite</h1>
          <span className="brand-badge">IOC Intelligence</span>
        </div>
        <div className="header-status">
          <span
            className="status-dot"
            style={{
              backgroundColor: backendOnline === false ? 'var(--color-red)' : 'var(--color-green)',
            }}
          />
          <span>{backendOnline === false ? 'Backend Offline' : 'API Connected'}</span>
        </div>
      </header>

      {/* Main Content Area */}
      <main>
        {!currentReport ? (
          <div>
            <UploadZone
              onUploadSuccess={handleUploadSuccess}
              isUploading={isUploading}
              setIsUploading={setIsUploading}
            />
          </div>
        ) : (
          <div>
            {/* Active Report Header Bar */}
            <div className="report-summary-bar">
              <div className="report-meta-info">
                <h2>{currentReport.fileName}</h2>
                <div className="report-meta-details">
                  {currentReport.pageCount && <span>📄 {currentReport.pageCount} Pages</span>}
                  <span>🔍 {iocs.length} Extracted Indicators</span>
                  <span>🕒 {new Date(currentReport.createdAt).toLocaleTimeString()}</span>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <div className="summary-badges">
                  {Object.entries(currentReport.summary).map(([type, count]) => (
                    <span key={type} className="stat-pill">
                      {type.toUpperCase()}: <strong>{count}</strong>
                    </span>
                  ))}
                </div>
                <button
                  type="button"
                  className="filter-btn"
                  onClick={handleReset}
                  style={{ whiteSpace: 'nowrap' }}
                >
                  Analyze Another Report
                </button>
              </div>
            </div>

            {/* IOC Results Table */}
            <IOCTable iocs={iocs} />
          </div>
        )}
      </main>
    </div>
  );
}
