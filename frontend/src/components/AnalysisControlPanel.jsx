// components/AnalysisControlPanel.jsx
// Dashboard component for controlling auto-analysis

import React, { useState, useEffect } from 'react'
import axios from 'axios'

export default function AnalysisControlPanel() {
  const [settings, setSettings] = useState({
    isRunning: false,
    analysisMethod: 'HYBRID',
    checkInterval: 10000,
    batchSize: 50
  })
  const [loading, setLoading] = useState(false)
  const [selectedMethod, setSelectedMethod] = useState('HYBRID')
  
  useEffect(() => {
    fetchStatus()
    // Refresh status every 5 seconds
    const interval = setInterval(fetchStatus, 5000)
    return () => clearInterval(interval)
  }, [])
  
  const fetchStatus = async () => {
    try {
      const response = await axios.get('http://localhost:5000/api/auto-analysis/status')
      if (response.data.success) {
        setSettings(response.data.data)
        setSelectedMethod(response.data.data.analysisMethod)
      }
    } catch (error) {
      console.error('Failed to fetch status:', error)
    }
  }
  
  const handleMethodChange = async (method) => {
    try {
      setLoading(true)
      const response = await axios.post(
        'http://localhost:5000/api/auto-analysis/set-method',
        { method }
      )
      
      if (response.data.success) {
        setSelectedMethod(method)
        alert(`✓ Analysis method changed to ${method}`)
        fetchStatus()
      }
    } catch (error) {
      alert('Failed to change method: ' + error.message)
    } finally {
      setLoading(false)
    }
  }
  
  const handleStartStop = async () => {
    try {
      setLoading(true)
      const endpoint = settings.isRunning ? 'stop' : 'start'
      const response = await axios.post(
        `http://localhost:5000/api/auto-analysis/${endpoint}`
      )
      
      if (response.data.success) {
        alert(response.data.message)
        fetchStatus()
      }
    } catch (error) {
      alert('Failed to toggle service: ' + error.message)
    } finally {
      setLoading(false)
    }
  }
  
  const handleAnalyzeNow = async () => {
    try {
      setLoading(true)
      const response = await axios.post(
        'http://localhost:5000/api/auto-analysis/analyze-now'
      )
      
      if (response.data.success) {
        alert('✓ Immediate analysis triggered!')
      }
    } catch (error) {
      alert('Failed to trigger analysis: ' + error.message)
    } finally {
      setLoading(false)
    }
  }
  
  return (
    <div className="analysis-control-panel">
      <h2>🤖 Auto-Analysis Control</h2>
      
      {/* Status Indicator */}
      <div className="status-section">
        <div className={`status-indicator ${settings.isRunning ? 'running' : 'stopped'}`}>
          <span className="status-dot"></span>
          <span className="status-text">
            {settings.isRunning ? 'Running' : 'Stopped'}
          </span>
        </div>
        <button
          onClick={handleStartStop}
          disabled={loading}
          className={`btn ${settings.isRunning ? 'btn-danger' : 'btn-success'}`}
        >
          {settings.isRunning ? '⏸️ Stop Auto-Analysis' : '▶️ Start Auto-Analysis'}
        </button>
      </div>
      
      {/* Method Selection */}
      <div className="method-section">
        <h3>Analysis Method</h3>
        <p className="section-description">
          Select how new logs should be analyzed automatically
        </p>
        
        <div className="method-buttons">
          <button
            onClick={() => handleMethodChange('HYBRID')}
            disabled={loading || selectedMethod === 'HYBRID'}
            className={`method-btn ${selectedMethod === 'HYBRID' ? 'active' : ''}`}
          >
            <div className="method-icon">🔄</div>
            <div className="method-name">Hybrid</div>
            <div className="method-desc">Rules + ML</div>
          </button>
          
          <button
            onClick={() => handleMethodChange('RULE_BASED')}
            disabled={loading || selectedMethod === 'RULE_BASED'}
            className={`method-btn ${selectedMethod === 'RULE_BASED' ? 'active' : ''}`}
          >
            <div className="method-icon">📋</div>
            <div className="method-name">Rule-Based</div>
            <div className="method-desc">Rules only</div>
          </button>
          
          <button
            onClick={() => handleMethodChange('MACHINE_LEARNING')}
            disabled={loading || selectedMethod === 'MACHINE_LEARNING'}
            className={`method-btn ${selectedMethod === 'MACHINE_LEARNING' ? 'active' : ''}`}
          >
            <div className="method-icon">🤖</div>
            <div className="method-name">ML Only</div>
            <div className="method-desc">Machine Learning</div>
          </button>
        </div>
      </div>
      
      {/* Settings Info */}
      <div className="settings-info">
        <h3>Current Settings</h3>
        <div className="info-grid">
          <div className="info-item">
            <span className="info-label">Check Interval:</span>
            <span className="info-value">{settings.checkInterval / 1000}s</span>
          </div>
          <div className="info-item">
            <span className="info-label">Batch Size:</span>
            <span className="info-value">{settings.batchSize} logs</span>
          </div>
        </div>
      </div>
      
      {/* Manual Trigger */}
      {settings.isRunning && (
        <div className="manual-section">
          <button
            onClick={handleAnalyzeNow}
            disabled={loading}
            className="btn btn-primary"
          >
            ⚡ Analyze Pending Logs Now
          </button>
          <p className="help-text">
            Don't wait for the next interval - analyze immediately
          </p>
        </div>
      )}
      
      
      </div>
  )
}