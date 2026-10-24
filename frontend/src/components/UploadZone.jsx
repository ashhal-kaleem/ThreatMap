import { useState, useRef } from 'react';
import { apiFetch } from '../lib/api';
import { UploadIcon, FileIcon, AlertIcon } from './Icons';

const BYTES_PER_MB = 1024 * 1024;

const DETECTS = ['IPv4', 'Domain', 'URL', 'MD5', 'SHA1', 'SHA256', 'CVE'];

export default function UploadZone({ onUploadSuccess, isUploading, setIsUploading, maxUploadMb }) {
  const [dragActive, setDragActive] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);
  const [activeFile, setActiveFile] = useState(null);
  const fileInputRef = useRef(null);

  const validateFile = (file) => {
    if (!file) return false;

    if (!file.name.toLowerCase().endsWith('.pdf')) {
      setErrorMessage('Invalid file type: ThreatMap Lite accepts native text-based PDF reports only.');
      return false;
    }
    if (file.size === 0) {
      setErrorMessage('Uploaded file is empty (0 bytes).');
      return false;
    }
    if (file.size > maxUploadMb * BYTES_PER_MB) {
      setErrorMessage(
        `File exceeds ${maxUploadMb}MB limit (${(file.size / BYTES_PER_MB).toFixed(1)}MB).`,
      );
      return false;
    }

    setErrorMessage(null);
    return true;
  };

  const handleFile = async (file) => {
    if (!validateFile(file)) return;

    setIsUploading(true);
    setErrorMessage(null);
    setActiveFile({ name: file.name, size: file.size });

    const formData = new FormData();
    formData.append('file', file);

    try {
      const data = await apiFetch('/reports/upload', { method: 'POST', body: formData });

      // The backend returns 201 even when extraction fails; surface that as an error
      if (data.status === 'failed') {
        const statusInfo = await apiFetch(`/reports/${data.report_id}/status`).catch(() => null);
        throw new Error(
          (statusInfo && statusInfo.error_msg) ||
            'The PDF was uploaded but text extraction failed. It may be scanned, encrypted, or corrupted.',
        );
      }

      if (onUploadSuccess) await onUploadSuccess(data.report_id, file.name);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to upload and analyze report.');
    } finally {
      setIsUploading(false);
      setActiveFile(null);
      // Allow selecting the same file again after an error
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const openPicker = () => {
    if (!isUploading) fileInputRef.current?.click();
  };

  const onDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!isUploading) setDragActive(true);
  };

  const onDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
  };

  const onDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (isUploading) return;
    if (e.dataTransfer.files && e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
  };

  const onFileChange = (e) => {
    if (e.target.files && e.target.files[0]) handleFile(e.target.files[0]);
  };

  const onKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      openPicker();
    }
  };

  return (
    <section className="upload-panel" aria-labelledby="upload-heading">
      <div className="panel-head">
        <span className="panel-kicker">Ingest</span>
        <h2 id="upload-heading" className="panel-title">
          Analyze a threat report
        </h2>
        <p className="panel-desc">
          Upload a CTI report PDF. Indicators are extracted page by page, refanged, normalized and
          deduplicated, each with the page and sentence it came from.
        </p>
      </div>

      <div
        className={`upload-card ${dragActive ? 'drag-active' : ''} ${errorMessage ? 'error' : ''} ${
          isUploading ? 'busy' : ''
        }`}
        role="button"
        tabIndex={isUploading ? -1 : 0}
        aria-disabled={isUploading}
        aria-busy={isUploading}
        aria-label="Upload a threat report PDF"
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        onClick={openPicker}
        onKeyDown={onKeyDown}
      >
        <input
          type="file"
          ref={fileInputRef}
          onChange={onFileChange}
          accept=".pdf,application/pdf"
          className="visually-hidden"
          tabIndex={-1}
          disabled={isUploading}
        />
        <span className="corner tl" aria-hidden="true" />
        <span className="corner tr" aria-hidden="true" />
        <span className="corner bl" aria-hidden="true" />
        <span className="corner br" aria-hidden="true" />

        {isUploading ? (
          <div className="scan-state">
            <div className="scan-doc" aria-hidden="true">
              <FileIcon size={40} />
              <span className="scan-line" />
            </div>
            <p className="upload-title">Extracting indicators…</p>
            {activeFile && (
              <p className="scan-file">
                {activeFile.name} · {(activeFile.size / BYTES_PER_MB).toFixed(1)} MB
              </p>
            )}
            <div className="progress-track" aria-hidden="true">
              <span className="progress-bar" />
            </div>
            <p className="upload-subtitle">Large reports can take a few seconds.</p>
          </div>
        ) : (
          <>
            <div className="upload-icon" aria-hidden="true">
              <UploadIcon size={28} />
            </div>
            <p className="upload-title">
              {dragActive ? 'Release to upload' : 'Drop a PDF here, or browse'}
            </p>
            <p className="upload-subtitle">Text-based PDFs · up to {maxUploadMb} MB</p>
            <button
              type="button"
              className="btn btn-primary"
              tabIndex={-1}
              onClick={(e) => {
                e.stopPropagation();
                openPicker();
              }}
            >
              <FileIcon size={16} /> Choose file
            </button>
          </>
        )}
      </div>

      {errorMessage && (
        <div className="notice notice-error" role="alert">
          <AlertIcon size={16} />
          <span>{errorMessage}</span>
        </div>
      )}

      <div className="detects" aria-label="Indicator types detected">
        <span className="detects-label">Detects</span>
        {DETECTS.map((d) => (
          <span key={d} className="detect-chip">
            {d}
          </span>
        ))}
        <span className="detect-chip detect-note">Defanged forms (hxxp, [.])</span>
      </div>
    </section>
  );
}
