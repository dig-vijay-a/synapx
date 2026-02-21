import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import './UploadPage.css';

const API_BASE = 'http://localhost:5000';

function UploadPage() {
  const navigate = useNavigate();
  const [selectedFile, setSelectedFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const fileInputRef = useRef(null);

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) { setSelectedFile(file); setUploadError(''); }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) { setSelectedFile(file); setUploadError(''); }
  };

  const handleDragOver = (e) => { e.preventDefault(); setIsDragging(true); };
  const handleDragLeave = () => setIsDragging(false);

  const handleUpload = async () => {
    if (!selectedFile) return;
    setIsUploading(true);
    setUploadError('');

    try {
      const form = new FormData();
      form.append('file', selectedFile);

      const res = await fetch(`${API_BASE}/api/upload`, { method: 'POST', body: form });
      const data = await res.json();

      if (!res.ok) throw new Error(data.error || 'Upload failed');

      // Navigate to /searchresult with file state
      navigate('/searchresult', { state: { fileId: data.file_id, fileName: data.original_name } });

    } catch (err) {
      setUploadError(err.message || 'Could not connect to backend. Is the server running?');
      setIsUploading(false);
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="upload-page">
      <div className="orb orb-1" />
      <div className="orb orb-2" />
      <div className="orb orb-3" />

      <div className="upload-container">
        {/* Header */}
        <div className="upload-header">
          <div className="logo-badge">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="url(#grad1)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M2 17L12 22L22 17" stroke="url(#grad1)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M2 12L12 17L22 12" stroke="url(#grad1)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              <defs>
                <linearGradient id="grad1" x1="2" y1="2" x2="22" y2="22" gradientUnits="userSpaceOnUse">
                  <stop stopColor="#818cf8" /><stop offset="1" stopColor="#38bdf8" />
                </linearGradient>
              </defs>
            </svg>
          </div>
          <div className="header-text">
            <span className="project-name">CipherSearch</span>
            <span className="project-tagline">Priority-Aware Secure Search over Encrypted Cloud Data</span>
          </div>
        </div>

        {/* Card */}
        <div className="upload-card">
          <h2 className="card-title">Upload Encrypted Document</h2>
          <p className="card-subtitle">Select a document to begin secure keyword indexing</p>

          {/* Drop Zone */}
          <div
            className={`drop-zone ${isDragging ? 'dragging' : ''} ${selectedFile ? 'has-file' : ''}`}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onClick={() => fileInputRef.current.click()}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".txt,.pdf,.doc,.docx,.enc"
              onChange={handleFileChange}
              style={{ display: 'none' }}
              id="file-input"
            />

            {selectedFile ? (
              <div className="file-preview">
                <div className="file-icon">
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none">
                    <path d="M14 2H6C5.47 2 4.96 2.21 4.59 2.59C4.21 2.96 4 3.47 4 4V20C4 20.53 4.21 21.04 4.59 21.41C4.96 21.79 5.47 22 6 22H18C18.53 22 19.04 21.79 19.41 21.41C19.79 21.04 20 20.53 20 20V8L14 2Z" stroke="#818cf8" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    <polyline points="14 2 14 8 20 8" stroke="#818cf8" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    <line x1="16" y1="13" x2="8" y2="13" stroke="#818cf8" strokeWidth="1.5" strokeLinecap="round" />
                    <line x1="16" y1="17" x2="8" y2="17" stroke="#818cf8" strokeWidth="1.5" strokeLinecap="round" />
                  </svg>
                </div>
                <div className="file-info">
                  <span className="file-name">{selectedFile.name}</span>
                  <span className="file-size">{formatFileSize(selectedFile.size)}</span>
                </div>
                <div className="change-file-hint">Click to change file</div>
              </div>
            ) : (
              <div className="drop-prompt">
                <div className="upload-icon">
                  <svg width="40" height="40" viewBox="0 0 24 24" fill="none">
                    <path d="M21 15V19C21 19.53 20.79 20.04 20.41 20.41C20.04 20.79 19.53 21 19 21H5C4.47 21 3.96 20.79 3.59 20.41C3.21 20.04 3 19.53 3 19V15" stroke="url(#uploadGrad)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    <polyline points="17 8 12 3 7 8" stroke="url(#uploadGrad)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    <line x1="12" y1="3" x2="12" y2="15" stroke="url(#uploadGrad)" strokeWidth="1.5" strokeLinecap="round" />
                    <defs>
                      <linearGradient id="uploadGrad" x1="3" y1="3" x2="21" y2="21" gradientUnits="userSpaceOnUse">
                        <stop stopColor="#818cf8" /><stop offset="1" stopColor="#38bdf8" />
                      </linearGradient>
                    </defs>
                  </svg>
                </div>
                <p className="drop-text">Drag & drop your document here</p>
                <p className="drop-subtext">or click to browse files</p>
                <p className="drop-formats">Supports: .txt, .pdf, .doc, .docx, .enc</p>
              </div>
            )}
          </div>

          {/* Filename Display Field */}
          <div className="filename-field">
            <label className="field-label">Selected File</label>
            <div className="filename-input-wrapper">
              <svg className="field-icon" width="16" height="16" viewBox="0 0 24 24" fill="none">
                <path d="M13 2H6C5.47 2 4.96 2.21 4.59 2.59C4.21 2.96 4 3.47 4 4V20C4 20.53 4.21 21.04 4.59 21.41C4.96 21.79 5.47 22 6 22H18C18.53 22 19.04 21.79 19.41 21.41C19.79 21.04 20 20.53 20 20V9L13 2Z" stroke="#64748b" strokeWidth="1.5" />
              </svg>
              <input
                type="text"
                readOnly
                className="filename-display"
                value={selectedFile ? selectedFile.name : ''}
                placeholder="No file selected"
              />
              {selectedFile && (
                <button
                  className="clear-btn"
                  onClick={(e) => { e.stopPropagation(); setSelectedFile(null); setUploadError(''); }}
                  title="Remove file"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                    <line x1="18" y1="6" x2="6" y2="18" stroke="#64748b" strokeWidth="2" strokeLinecap="round" />
                    <line x1="6" y1="6" x2="18" y2="18" stroke="#64748b" strokeWidth="2" strokeLinecap="round" />
                  </svg>
                </button>
              )}
            </div>
          </div>

          {/* Error banner */}
          {uploadError && (
            <div className="error-banner">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                <circle cx="12" cy="12" r="10" stroke="#f87171" strokeWidth="1.5" />
                <line x1="12" y1="8" x2="12" y2="12" stroke="#f87171" strokeWidth="1.5" strokeLinecap="round" />
                <line x1="12" y1="16" x2="12.01" y2="16" stroke="#f87171" strokeWidth="2" strokeLinecap="round" />
              </svg>
              {uploadError}
            </div>
          )}

          {/* Upload Button */}
          <button
            className={`upload-btn ${!selectedFile ? 'disabled' : ''} ${isUploading ? 'uploading' : ''}`}
            onClick={handleUpload}
            disabled={!selectedFile || isUploading}
          >
            {isUploading ? (
              <>
                <div className="spinner" />
                <span>Encrypting & Uploading...</span>
              </>
            ) : (
              <>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  <polyline points="9 12 11 14 15 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                <span>Upload & Index Document</span>
              </>
            )}
          </button>
        </div>

        <p className="footer-note">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" style={{ marginRight: '6px' }}>
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke="#475569" strokeWidth="1.5" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" stroke="#475569" strokeWidth="1.5" />
          </svg>
          All documents are encrypted with AES-256-GCM before storage. Plaintext never persists.
        </p>
      </div>
    </div>
  );
}

export default UploadPage;
