import React, { useCallback, useState } from 'react';
import { AlertTriangle, FileText, Loader2, UploadCloud } from 'lucide-react';
import { investigateAPI } from '../api';

export default function FileUpload({ onInvestigationStart, compact = false }) {
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');

  const handleDrag = useCallback((event) => {
    event.preventDefault();
    event.stopPropagation();
    setIsDragging(event.type === 'dragenter' || event.type === 'dragover');
  }, []);

  const handleDrop = useCallback((event) => {
    event.preventDefault();
    event.stopPropagation();
    setIsDragging(false);
    const droppedFile = event.dataTransfer.files?.[0];
    if (droppedFile) setFile(droppedFile);
  }, []);

  const handleFileSelect = (event) => {
    const selected = event.target.files?.[0];
    if (selected) setFile(selected);
  };

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setError('');
    try {
      const response = await investigateAPI.upload(file);
      onInvestigationStart(response.data.investigation_id);
    } catch (err) {
      setError(err.response?.data?.detail || 'Upload failed. Ensure the backend is running.');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className={compact ? 'upload-widget compact' : 'upload-widget'}>
      {!compact && (
        <div className="upload-heading">
          <div className="section-eyebrow">New Investigation</div>
          <h2>Upload security logs</h2>
          <p>JSON, XML, text, syslog, CEF, and generic event files are accepted.</p>
        </div>
      )}

      <div
        role="button"
        tabIndex={0}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => document.getElementById('file-input')?.click()}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') document.getElementById('file-input')?.click();
        }}
        className={`upload-dropzone ${isDragging ? 'dragging' : ''} ${file ? 'ready' : ''}`}
      >
        <input
          id="file-input"
          type="file"
          className="hidden"
          accept=".log,.json,.xml,.txt,.csv,.evtx"
          onChange={handleFileSelect}
        />

        <div className="upload-icon">
          {file ? <FileText className="w-7 h-7" /> : <UploadCloud className="w-7 h-7" />}
        </div>
        <div>
          <strong>{file ? file.name : 'Drop logs here or browse'}</strong>
          <span>{file ? `${(file.size / 1024).toFixed(1)} KB selected` : '.log, .json, .xml, .txt, .csv, .evtx'}</span>
        </div>
      </div>

      {error && (
        <div className="upload-error">
          <AlertTriangle className="w-4 h-4" />
          <span>{error}</span>
        </div>
      )}

      <button type="button" onClick={handleUpload} disabled={!file || uploading} className="primary-button upload-submit">
        {uploading ? <Loader2 className="w-4 h-4 animate-spin" /> : <UploadCloud className="w-4 h-4" />}
        {uploading ? 'Starting analysis' : 'Start Investigation'}
      </button>
    </div>
  );
}
