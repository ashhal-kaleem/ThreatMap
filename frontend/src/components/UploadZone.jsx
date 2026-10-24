import { useState, useRef } from 'react';
import { apiFetch } from '../lib/api';

const BYTES_PER_MB = 1024 * 1024;

export default function UploadZone({ onUploadSuccess, isUploading, setIsUploading, maxUploadMb }) {
  const [dragActive, setDragActive] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);
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
    <div
      className={`upload-card ${dragActive ? 'drag-active' : ''} ${errorMessage ? 'error' : ''}`}
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

      <div className="upload-icon" aria-hidden="true">
        {isUploading ? '⏳' : '📄'}
      </div>

      <h3 className="upload-title">
        {isUploading ? 'Processing & Extracting Indicators...' : 'Drop Threat Report PDF Here'}
      </h3>

      <p className="upload-subtitle">Native text-based PDFs only · Maximum {maxUploadMb}MB</p>

      <button
        type="button"
        className="upload-btn"
        disabled={isUploading}
        tabIndex={-1}
        onClick={(e) => {
          e.stopPropagation();
          openPicker();
        }}
      >
        {isUploading ? (
          <>
            <span className="spinner" /> Analyzing Document...
          </>
        ) : (
          'Browse Computer'
        )}
      </button>

      {errorMessage && (
        <div className="upload-error-message" role="alert">
          ⚠️ {errorMessage}
        </div>
      )}
    </div>
  );
}
