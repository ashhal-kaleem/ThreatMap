import React, { useState, useRef } from 'react';

const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB

export default function UploadZone({ onUploadSuccess, isUploading, setIsUploading }) {
  const [dragActive, setDragActive] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);
  const fileInputRef = useRef(null);

  const validateFile = (file) => {
    if (!file) return false;

    // Check file extension
    if (!file.name.toLowerCase().endsWith('.pdf')) {
      setErrorMessage('Invalid file type: ThreatMap Lite accepts native text-based PDF reports only.');
      return false;
    }

    // Check size <= 50MB
    if (file.size > MAX_FILE_SIZE) {
      setErrorMessage(`File exceeds 50MB limit (${(file.size / (1024 * 1024)).toFixed(1)}MB).`);
      return false;
    }

    if (file.size === 0) {
      setErrorMessage('Uploaded file is empty (0 bytes).');
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
      const response = await fetch('/reports/upload', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Server responded with status ${response.status}`);
      }

      const data = await response.json();
      if (onUploadSuccess) {
        onUploadSuccess(data.report_id, file.name);
      }
    } catch (err) {
      console.error('Upload error:', err);
      setErrorMessage(err.message || 'Failed to upload and analyze report.');
    } finally {
      setIsUploading(false);
    }
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

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const onFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFile(e.target.files[0]);
    }
  };

  return (
    <div
      className={`upload-card ${dragActive ? 'drag-active' : ''} ${errorMessage ? 'error' : ''}`}
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
      onClick={() => !isUploading && fileInputRef.current?.click()}
    >
      <input
        type="file"
        ref={fileInputRef}
        onChange={onFileChange}
        accept=".pdf,application/pdf"
        style={{ display: 'none' }}
        disabled={isUploading}
      />

      <div className="upload-icon">
        {isUploading ? '⏳' : '📄'}
      </div>

      <h3 className="upload-title">
        {isUploading ? 'Processing & Extracting Indicators...' : 'Drop Threat Report PDF Here'}
      </h3>

      <p className="upload-subtitle">
        Native text-based PDFs only · Maximum 50MB · Subprocess PyMuPDF extraction
      </p>

      <button
        type="button"
        className="upload-btn"
        disabled={isUploading}
        onClick={(e) => {
          e.stopPropagation();
          fileInputRef.current?.click();
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
        <div className="upload-error-message">
          ⚠️ {errorMessage}
        </div>
      )}
    </div>
  );
}
