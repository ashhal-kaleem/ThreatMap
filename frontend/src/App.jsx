import { useState, useEffect } from 'react';
import UploadZone from './components/UploadZone';
import IOCTable from './components/IOCTable';
import { apiFetch } from './lib/api';
import { DEFAULT_MAX_UPLOAD_MB } from './config';
import { FileIcon, AlertIcon, RefreshIcon } from './components/Icons';

const HEALTH_LABELS = {
  checking: 'Checking API…',
  online: 'API Connected',
  offline: 'Backend Offline',
};

export default function App() {
  const [currentReport, setCurrentReport] = useState(null);
  const [iocs, setIocs] = useState([]);
  const [isUploading, setIsUploading] = useState(false);
  const [health, setHealth] = useState('checking');
  const [maxUploadMb, setMaxUploadMb] = useState(DEFAULT_MAX_UPLOAD_MB);
  const [loadError, setLoadError] = useState(null);

  // Check backend health on mount and pick up the server's upload limit
  useEffect(() => {
    let cancelled = false;
    apiFetch('/health')
      .then((data) => {
        if (cancelled) return;
        setHealth(data && data.status === 'ok' ? 'online' : 'offline');
        if (data && Number(data.max_upload_mb) > 0) setMaxUploadMb(Number(data.max_upload_mb));
      })
      .catch(() => !cancelled && setHealth('offline'));
    return () => {
      cancelled = true;
    };
  }, []);

  const handleUploadSuccess = async (reportId, filename) => {
    setLoadError(null);
    try {
      const data = await apiFetch(`/reports/${reportId}/results`);
      setCurrentReport({
        id: data.report_id,
        fileName: filename || data.file_name,
        pageCount: data.page_count,
        createdAt: data.created_at,
        summary: data.ioc_summary || {},
      });
      setIocs(data.iocs || []);
    } catch (err) {
      setLoadError(`The report was processed, but its results could not be loaded: ${err.message}`);
    }
  };

  const handleReset = () => {
    setCurrentReport(null);
    setIocs([]);
    setLoadError(null);
  };

  return (
    <div className="app-container">
      <header className="app-header">
        <div className="brand-section">
          <span className="brand-logo" aria-hidden="true">🛡️</span>
          <h1 className="brand-title">ThreatMap Lite</h1>
          <span className="brand-badge">IOC Intelligence</span>
        </div>
        <div className="header-status" role="status">
          <span className={`status-dot status-${health}`} aria-hidden="true" />
          <span>{HEALTH_LABELS[health]}</span>
        </div>
      </header>

      <main>
        {!currentReport ? (
          <>
            <UploadZone
              onUploadSuccess={handleUploadSuccess}
              isUploading={isUploading}
              setIsUploading={setIsUploading}
              maxUploadMb={maxUploadMb}
            />
            {loadError && (
              <div className="notice notice-error" role="alert">
                <AlertIcon size={16} />
                <span>{loadError}</span>
              </div>
            )}
          </>
        ) : (
          <div>
            <div className="report-header">
              <div className="report-file">
                <span className="report-file-icon" aria-hidden="true">
                  <FileIcon size={22} />
                </span>
                <div>
                  <span className="panel-kicker">Report analyzed</span>
                  <h2 className="report-name">{currentReport.fileName}</h2>
                  <div className="report-meta">
                    {currentReport.pageCount != null && <span>{currentReport.pageCount} pages</span>}
                    <span>{iocs.length} indicators</span>
                    {currentReport.createdAt && (
                      <span>{new Date(currentReport.createdAt).toLocaleString()}</span>
                    )}
                    <span className="report-id">ID {String(currentReport.id).slice(0, 8)}</span>
                  </div>
                </div>
              </div>
              <button type="button" className="btn btn-secondary nowrap" onClick={handleReset}>
                <RefreshIcon size={15} /> Analyze another report
              </button>
            </div>

            <IOCTable iocs={iocs} reportName={currentReport.fileName} />
          </div>
        )}
      </main>
    </div>
  );
}
