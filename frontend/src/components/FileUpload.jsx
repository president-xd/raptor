import React, { useCallback, useRef, useState } from 'react';
import {
  AlertTriangle,
  ClipboardList,
  Database,
  FileText,
  Loader2,
  Search,
  SlidersHorizontal,
  UploadCloud,
} from 'lucide-react';
import { investigateAPI } from '../api';

const INPUT_MODES = [
  { id: 'file', label: 'File Upload', icon: UploadCloud },
  { id: 'paste', label: 'Paste Logs', icon: ClipboardList },
  { id: 'elastic', label: 'Elastic Query', icon: Database },
];

export default function FileUpload({ onInvestigationStart, compact = false }) {
  const inputRef = useRef(null);
  const [mode, setMode] = useState('file');
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState(null);
  const [logText, setLogText] = useState('');
  const [elasticQuery, setElasticQuery] = useState('');
  const [timeRangeStart, setTimeRangeStart] = useState('');
  const [timeRangeEnd, setTimeRangeEnd] = useState('');
  const [sensitivity, setSensitivity] = useState('medium');
  const [aptFilters, setAptFilters] = useState('');
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');

  const activeMode = compact ? 'file' : mode;

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

  const selectedAptFilters = aptFilters
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

  const canSubmit =
    activeMode === 'file'
      ? Boolean(file)
      : activeMode === 'paste'
        ? Boolean(logText.trim())
        : Boolean(elasticQuery.trim());

  const handleUpload = async () => {
    if (!canSubmit) return;
    setUploading(true);
    setError('');
    try {
      let response;
      if (activeMode === 'file') {
        response = await investigateAPI.upload(file);
      } else {
        response = await investigateAPI.submitText({
          source: activeMode,
          log_content: activeMode === 'paste' ? logText : '',
          elastic_query: activeMode === 'elastic' ? elasticQuery : null,
          time_range_start: timeRangeStart || null,
          time_range_end: timeRangeEnd || null,
          sensitivity,
          apt_filters: selectedAptFilters,
        });
      }
      onInvestigationStart(response.data.investigation_id);
    } catch (err) {
      setError(err.response?.data?.detail || 'Investigation failed to start. Ensure the backend is running.');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className={compact ? 'upload-widget compact' : 'upload-widget'}>
      {!compact && (
        <div className="upload-heading">
          <div className="section-eyebrow">New Investigation</div>
          <h2>Collect evidence</h2>
          <p>Start from a file, pasted log text, or a scoped Elasticsearch query.</p>
        </div>
      )}

      {!compact && (
        <div className="mode-segment">
          {INPUT_MODES.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              type="button"
              className={mode === id ? 'active' : ''}
              onClick={() => setMode(id)}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          ))}
        </div>
      )}

      {activeMode === 'file' && (
        <div
          role="button"
          tabIndex={0}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => {
            if (event.key === 'Enter' || event.key === ' ') inputRef.current?.click();
          }}
          className={`upload-dropzone ${isDragging ? 'dragging' : ''} ${file ? 'ready' : ''}`}
        >
          <input
            ref={inputRef}
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
      )}

      {activeMode === 'paste' && (
        <div className="investigation-input-panel">
          <label>
            <span>Raw log content</span>
            <textarea
              value={logText}
              onChange={(event) => setLogText(event.target.value)}
              placeholder='{"timestamp":"2026-04-25T10:00:00Z","source_host":"WS-01","event_type":"process","raw":"powershell execution"}'
              rows={9}
            />
          </label>
        </div>
      )}

      {activeMode === 'elastic' && (
        <div className="investigation-input-panel">
          <label>
            <span>Elasticsearch query string</span>
            <div className="inline-field">
              <Search className="w-4 h-4" />
              <input
                type="text"
                value={elasticQuery}
                onChange={(event) => setElasticQuery(event.target.value)}
                placeholder='event.dataset:sysmon AND powershell'
              />
            </div>
          </label>
        </div>
      )}

      {!compact && (
        <div className="wizard-options">
          <div className="option-title">
            <SlidersHorizontal className="w-4 h-4" />
            Investigation options
          </div>
          <div className="option-grid">
            <label>
              <span>Start time</span>
              <input type="datetime-local" value={timeRangeStart} onChange={(event) => setTimeRangeStart(event.target.value)} />
            </label>
            <label>
              <span>End time</span>
              <input type="datetime-local" value={timeRangeEnd} onChange={(event) => setTimeRangeEnd(event.target.value)} />
            </label>
            <label>
              <span>Sensitivity</span>
              <select value={sensitivity} onChange={(event) => setSensitivity(event.target.value)}>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
              </select>
            </label>
            <label>
              <span>APT focus</span>
              <input
                type="text"
                value={aptFilters}
                onChange={(event) => setAptFilters(event.target.value)}
                placeholder="APT29, FIN8"
              />
            </label>
          </div>
        </div>
      )}

      {error && (
        <div className="upload-error">
          <AlertTriangle className="w-4 h-4" />
          <span>{error}</span>
        </div>
      )}

      <button type="button" onClick={handleUpload} disabled={!canSubmit || uploading} className="primary-button upload-submit">
        {uploading ? <Loader2 className="w-4 h-4 animate-spin" /> : <UploadCloud className="w-4 h-4" />}
        {uploading ? 'Starting analysis' : 'Start Investigation'}
      </button>
    </div>
  );
}
