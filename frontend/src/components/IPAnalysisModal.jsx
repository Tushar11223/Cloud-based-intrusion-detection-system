// components/IPAnalysisModal.jsx
// Modal component for displaying VirusTotal IP analysis

import React, { useState, useEffect } from 'react'
import axios from 'axios'

export default function IPAnalysisModal({ ipAddress, onClose }) {
  const [loading, setLoading] = useState(true)
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  
  useEffect(() => {
    fetchIPAnalysis()
  }, [ipAddress])
  
  const fetchIPAnalysis = async () => {
    try {
      setLoading(true)
      setError(null)
      
      const response = await axios.get(
        `http://localhost:5000/api/virustotal/ip/${ipAddress}`
      )
      
      if (response.data.success) {
        setData(response.data.data)
      } else {
        setError(response.data.message)
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to fetch IP analysis')
    } finally {
      setLoading(false)
    }
  }
  
  const getThreatColor = (level) => {
    switch(level) {
      case 'CRITICAL': return '#d32f2f'
      case 'HIGH': return '#f57c00'
      case 'MEDIUM': return '#fbc02d'
      case 'LOW': return '#757575'
      case 'SAFE': return '#4CAF50'
      default: return '#999'
    }
  }
  
  const getThreatIcon = (level) => {
    switch(level) {
      case 'CRITICAL': return '🔴'
      case 'HIGH': return '🟠'
      case 'MEDIUM': return '🟡'
      case 'LOW': return '⚪'
      case 'SAFE': return '🟢'
      default: return '❓'
    }
  }
  
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content ip-analysis-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>🔍 IP Analysis: {ipAddress}</h2>
          <button onClick={onClose} className="modal-close">×</button>
        </div>
        
        <div className="modal-body">
          {loading && (
            <div className="loading-state">
              <div className="spinner"></div>
              <p>Analyzing IP with VirusTotal...</p>
            </div>
          )}
          
          {error && (
            <div className="error-state">
              <p>❌ {error}</p>
              {error.includes('API key') && (
                <div className="api-key-help">
                  <h4>How to get VirusTotal API Key:</h4>
                  <ol>
                    <li>Go to <a href="https://www.virustotal.com" target="_blank" rel="noopener noreferrer">virustotal.com</a></li>
                    <li>Sign up for free account</li>
                    <li>Get API key from your profile</li>
                    <li>Add to .env file: <code>VIRUSTOTAL_API_KEY=your_key_here</code></li>
                    <li>Restart backend</li>
                  </ol>
                </div>
              )}
            </div>
          )}
          
          {data && !loading && (
            <div className="analysis-results">
              {/* Threat Level Banner */}
              <div 
                className="threat-banner"
                style={{ 
                  background: getThreatColor(data.threatLevel),
                  color: 'white'
                }}
              >
                <span className="threat-icon">{getThreatIcon(data.threatLevel)}</span>
                <span className="threat-text">Threat Level: {data.threatLevel}</span>
              </div>
              
              {/* Detection Summary */}
              <div className="detection-summary">
                <h3>Detection Summary</h3>
                <div className="summary-grid">
                  <div className="summary-item malicious">
                    <div className="summary-value">{data.summary.malicious}</div>
                    <div className="summary-label">Malicious</div>
                  </div>
                  <div className="summary-item suspicious">
                    <div className="summary-value">{data.summary.suspicious}</div>
                    <div className="summary-label">Suspicious</div>
                  </div>
                  <div className="summary-item harmless">
                    <div className="summary-value">{data.summary.harmless}</div>
                    <div className="summary-label">Harmless</div>
                  </div>
                  <div className="summary-item undetected">
                    <div className="summary-value">{data.summary.undetected}</div>
                    <div className="summary-label">Undetected</div>
                  </div>
                </div>
              </div>
              
              {/* Location Info */}
              <div className="info-section">
                <h3>📍 Location & Network</h3>
                <div className="info-grid">
                  <div className="info-item">
                    <span className="info-label">Country:</span>
                    <span className="info-value">{data.location.country}</span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">ASN:</span>
                    <span className="info-value">{data.location.asn}</span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Network:</span>
                    <span className="info-value">{data.location.network}</span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Reputation:</span>
                    <span className="info-value">{data.reputation}</span>
                  </div>
                </div>
              </div>
              
              {/* Tags */}
              {data.tags && data.tags.length > 0 && (
                <div className="info-section">
                  <h3>🏷️ Tags</h3>
                  <div className="tags-container">
                    {data.tags.map((tag, idx) => (
                      <span key={idx} className="tag">{tag}</span>
                    ))}
                  </div>
                </div>
              )}
              
              {/* Detections */}
              {data.detections && data.detections.length > 0 && (
                <div className="info-section">
                  <h3>🛡️ Security Vendor Detections</h3>
                  <div className="detections-list">
                    {data.detections.map((detection, idx) => (
                      <div key={idx} className="detection-item">
                        <span className="vendor-name">{detection.vendor}</span>
                        <span className={`detection-category ${detection.category}`}>
                          {detection.category}
                        </span>
                        {detection.result && (
                          <span className="detection-result">{detection.result}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              
              {/* Last Analysis */}
              {data.lastAnalysis && (
                <div className="info-section">
                  <p className="last-analysis">
                    Last analyzed: {new Date(data.lastAnalysis).toLocaleString()}
                  </p>
                </div>
              )}
              
              {/* VirusTotal Link */}
              <div className="actions">
                <a 
                  href={data.virustotalUrl} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="btn btn-primary"
                >
                  🔗 View Full Report on VirusTotal
                </a>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}