import React, { useState } from 'react';

export default function ControlPanel({ onGenerateLogs, onAnalyze, onReset, loading }) {
  const [logCount, setLogCount] = useState(100);
  const [malwareRatio, setMalwareRatio] = useState(0.15);
  const [detectionMethod, setDetectionMethod] = useState('HYBRID');
  
  return (
    <div className="control-panel">
      <h2>Control Panel</h2>
      
      <div className="control-section">
        <h3>1. Generate Simulated Traffic</h3>
        <div className="form-group">
          <label>Number of Logs:</label>
          <input
            type="number"
            value={logCount}
            onChange={(e) => setLogCount(parseInt(e.target.value))}
            min="10"
            max="1000"
          />
        </div>
        <div className="form-group">
          <label>Malware Ratio:</label>
          <input
            type="range"
            value={malwareRatio}
            onChange={(e) => setMalwareRatio(parseFloat(e.target.value))}
            min="0"
            max="0.5"
            step="0.05"
          />
          <span>{(malwareRatio * 100).toFixed(0)}%</span>
        </div>
        <button
          onClick={() => onGenerateLogs(logCount, malwareRatio)}
          disabled={loading}
          className="btn btn-primary"
        >
          {loading ? 'Generating...' : 'Generate Logs'}
        </button>
      </div>
      
      <div className="control-section">
        <h3>2. Analyze Traffic</h3>
        <div className="form-group">
          <label>Detection Method:</label>
          <select
            value={detectionMethod}
            onChange={(e) => setDetectionMethod(e.target.value)}
          >
            <option value="HYBRID">Hybrid (Rules + ML)</option>
            <option value="RULE_BASED">Rule-Based Only</option>
            <option value="MACHINE_LEARNING">ML Only</option>
          </select>
        </div>
        <button
          onClick={() => onAnalyze(detectionMethod)}
          disabled={loading}
          className="btn btn-success"
        >
          {loading ? 'Analyzing...' : 'Run Analysis'}
        </button>
      </div>
      
      <div className="control-section">
        <h3>3. System Actions</h3>
        <button
          onClick={onReset}
          disabled={loading}
          className="btn btn-danger"
        >
          Reset All Data
        </button>
      </div>
    </div>
  );
}
