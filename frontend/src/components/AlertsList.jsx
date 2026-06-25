// components/AlertsList.jsx
// FIXED: Refresh button now works properly

import React, { useState } from 'react'
import IPAnalysisModal from './IPAnalysisModal'

export default function AlertsList({ alerts = [], onRefresh }) {
  const [selectedIP, setSelectedIP] = useState(null)
  const [showModal, setShowModal] = useState(false)
  
  const getSeverityClass = (severity) => {
    return severity?.toLowerCase() || 'low'
  }
  
  const formatTime = (timestamp) => {
    const date = new Date(timestamp)
    return date.toLocaleTimeString()
  }
  
  const handleIPClick = (ip) => {
    setSelectedIP(ip)
    setShowModal(true)
  }
  
  const closeModal = () => {
    setShowModal(false)
    setSelectedIP(null)
  }
  
  // Handle refresh click - FIXED
  const handleRefreshClick = (e) => {
    e.preventDefault()
    e.stopPropagation()
    console.log('🔄 AlertsList refresh clicked')
    if (onRefresh && typeof onRefresh === 'function') {
      onRefresh()
    } else {
      console.warn('onRefresh function not provided')
    }
  }
  
  return (
    <>
      <div className="alerts-list">
        {/* Alerts Container */}
        {alerts.length === 0 ? (
          <div className="no-alerts">
            <p>No alerts to display</p>
            <span className="help-text">Alerts will appear when malware is detected</span>
          </div>
        ) : (
          <div className="alerts-container">
            {alerts.map((alert) => (
              <div key={alert._id} className={`alert-item ${getSeverityClass(alert.severity)}`}>
                <div className="alert-header">
                  <span className={`severity-badge ${getSeverityClass(alert.severity)}`}>
                    {alert.severity}
                  </span>
                  <span className="alert-time">{formatTime(alert.timestamp)}</span>
                </div>
                
                <div className="alert-title">{alert.title}</div>
                <div className="alert-desc">{alert.description}</div>
                
                <div className="alert-details">
                  <div className="ip-addresses">
                    <span 
                      className="clickable-ip source-ip"
                      onClick={() => handleIPClick(alert.sourceIp)}
                      title="Click to analyze with VirusTotal"
                    >
                      🔍 {alert.sourceIp}
                    </span>
                    <span className="ip-separator">→</span>
                    <span 
                      className="clickable-ip dest-ip"
                      onClick={() => handleIPClick(alert.destinationIp)}
                      title="Click to analyze with VirusTotal"
                    >
                      🔍 {alert.destinationIp}
                    </span>
                  </div>
                  <span className="alert-type">{alert.alertType}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      
      {/* VirusTotal Analysis Modal */}
      {showModal && selectedIP && (
        <IPAnalysisModal 
          ipAddress={selectedIP}
          onClose={closeModal}
        />
      )}
    </>
  )
}