// frontend/src/pages/Dashboard.jsx
// Professional Malware Detection Dashboard

import React, { useState, useEffect } from 'react'
import { flowLogsAPI, alertsAPI, detectionAPI } from '../services/api'
import StatsCard from '../components/StatsCard'
import AlertsList from '../components/AlertsList'
import TrafficChart from '../components/TrafficChart'
import AnalysisControlPanel from '../components/AnalysisControlPanel'
import './Dashboard.css'

export default function Dashboard() {
  const [stats, setStats] = useState({
    totalLogs: 0,
    malwareLogs: 0,
    benignLogs: 0,
    totalAlerts: 0,
    criticalAlerts: 0,
    detectionRate: 0,
    analysisProgress: 0
  })
  
  const [systemStatus, setSystemStatus] = useState({
    mlService: 'CHECKING',
    ruleEngine: 'CHECKING',
    database: 'CHECKING',
    autoAnalysis: 'CHECKING'
  })
  
  const [timelineData, setTimelineData] = useState([])
  const [recentAlerts, setRecentAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastUpdate, setLastUpdate] = useState(null)
  
  // Auto-refresh every 10 seconds
  useEffect(() => {
    fetchDashboardData()
    const interval = setInterval(fetchDashboardData, 10000)
    return () => clearInterval(interval)
  }, [])
  
  const fetchDashboardData = async () => {
    try {
      setError(null)
      
      // Fetch system status
      try {
        const statusRes = await detectionAPI.getStatus()
        if (statusRes.data.success) {
          setSystemStatus(statusRes.data.status)
        }
      } catch (err) {
        console.error('Status fetch error:', err)
      }
      
      // Fetch flow log stats
      const flowStatsRes = await flowLogsAPI.getStats()
      
      // Fetch alert stats
      const alertStatsRes = await alertsAPI.getStats()
      
      // Fetch timeline data (last hour)
      const timelineRes = await flowLogsAPI.getTimeline(
        new Date(Date.now() - 3600000).toISOString(),
        new Date().toISOString(),
        'minute'
      )
      
      // Fetch recent alerts
      const recentAlertsRes = await alertsAPI.getRecent(10)
      
      // Update stats
      if (flowStatsRes.data.success && alertStatsRes.data.success) {
        const flowData = flowStatsRes.data.data
        const alertData = alertStatsRes.data.data
        
        const totalLogs = flowData.totals.logs || 0
        const malwareLogs = flowData.totals.malware || 0
        const benignLogs = flowData.totals.benign || 0
        const totalAlerts = alertData.totals.alerts || 0
        
        const criticalAlerts = alertData.severityDistribution?.find(
          s => s._id === 'CRITICAL'
        )?.count || 0
        
        const detectionRate = totalLogs > 0 
          ? ((malwareLogs / totalLogs) * 100).toFixed(1)
          : 0
        
        const analysisProgress = totalLogs > 0
          ? ((flowData.totals.analyzed / totalLogs) * 100).toFixed(1)
          : 0
        
        setStats({
          totalLogs,
          malwareLogs,
          benignLogs,
          totalAlerts,
          criticalAlerts,
          detectionRate,
          analysisProgress
        })
      }
      
      // Update timeline
      if (timelineRes.data.success) {
        setTimelineData(timelineRes.data.data)
      }
      
      // Update recent alerts
      if (recentAlertsRes.data.success) {
        setRecentAlerts(recentAlertsRes.data.data)
      }
      
      setLastUpdate(new Date())
      setLoading(false)
      
    } catch (err) {
      console.error('Dashboard data fetch error:', err)
      setError('Failed to load dashboard data. Make sure backend is running.')
      setLoading(false)
    }
  }
  
  if (loading && stats.totalLogs === 0) {
    return (
      <div className="dashboard">
        <div className="loading-screen">
          <div className="loading-spinner"></div>
          <p>Loading dashboard...</p>
        </div>
      </div>
    )
  }
  
  return (
    <div className="dashboard">
      {/* Header */}
      <header className="dashboard-header">
        <div className="header-left">
          <h1>🛡️ Malware Detection System</h1>
          <p className="header-subtitle">Real-time Network Traffic Analysis</p>
        </div>
        
        <div className="header-right">
          <div className="system-status">
            <span className={`status-badge ${systemStatus.database.toLowerCase()}`}>
              <span className="status-dot"></span>
              DB: {systemStatus.database}
            </span>
            <span className={`status-badge ${systemStatus.mlService.toLowerCase()}`}>
              <span className="status-dot"></span>
              ML: {systemStatus.mlService}
            </span>
            <span className={`status-badge ${systemStatus.ruleEngine.toLowerCase()}`}>
              <span className="status-dot"></span>
              Rules: {systemStatus.ruleEngine}
            </span>
          </div>
          
          <button 
            onClick={fetchDashboardData} 
            className="refresh-btn"
            disabled={loading}
          >
            <span className={loading ? 'spinning' : ''}>🔄</span>
            Refresh
          </button>
          
          {lastUpdate && (
            <span className="last-update">
              Updated: {lastUpdate.toLocaleTimeString()}
            </span>
          )}
        </div>
      </header>
      
      {/* Error Banner */}
      {error && (
        <div className="error-banner">
          <span className="error-icon">⚠️</span>
          <span className="error-message">{error}</span>
          <button onClick={fetchDashboardData} className="retry-btn">Retry</button>
        </div>
      )}
      
      {/* Welcome Message (if no data) */}
      {stats.totalLogs === 0 && !loading && (
        <div className="welcome-banner">
          <div className="welcome-content">
            <h2>👋 Welcome to Malware Detection System</h2>
            
            
          </div>
        </div>
      )}
      
      {/* Stats Grid */}
      <div className="stats-grid">
        <StatsCard
          title="Total Flow Logs"
          value={stats.totalLogs.toLocaleString()}
          subtitle="Network flows captured"
          icon="📊"
          trend={stats.totalLogs > 0 ? 'up' : 'neutral'}
        />
        
        <StatsCard
          title="Malware Detected"
          value={stats.malwareLogs.toLocaleString()}
          subtitle={`${stats.detectionRate}% of total traffic`}
          icon="🦠"
          trend="alert"
          highlight
        />
        
        <StatsCard
          title="Clean Traffic"
          value={stats.benignLogs.toLocaleString()}
          subtitle={`${(100 - stats.detectionRate).toFixed(1)}% benign`}
          icon="✅"
          trend="safe"
        />
        
        <StatsCard
          title="Total Alerts"
          value={stats.totalAlerts.toLocaleString()}
          subtitle={`${stats.criticalAlerts} critical`}
          icon="⚠️"
          trend={stats.criticalAlerts > 0 ? 'alert' : 'neutral'}
        />
      </div>
      
      {/* Main Content */}
      <div className="main-content">
        {/* Left Panel */}
        <div className="left-panel">
          {/* Analysis Control */}
          <div className="panel analysis-panel">
            <AnalysisControlPanel />
          </div>
          
          {/* Traffic Chart */}
          <div className="panel chart-panel">
            <div className="panel-header">
              <h2>📈 Traffic Timeline</h2>
              <span className="panel-subtitle">Last Hour Activity</span>
            </div>
            <div className="panel-body">
              {timelineData.length > 0 ? (
                <TrafficChart data={timelineData} />
              ) : (
                <div className="no-data">
                  <p>No traffic data available</p>
                  <span className="help-text">Import logs to see timeline</span>
                </div>
              )}
            </div>
          </div>
          
          {/* Quick Stats */}
          <div className="panel quick-stats-panel">
            <div className="panel-header">
              <h2>⚡ Quick Stats</h2>
            </div>
            <div className="panel-body">
              <div className="quick-stats-grid">
                <div className="quick-stat">
                  <span className="stat-label">Detection Rate</span>
                  <span className="stat-value">{stats.detectionRate}%</span>
                </div>
                <div className="quick-stat">
                  <span className="stat-label">Analysis Progress</span>
                  <span className="stat-value">{stats.analysisProgress}%</span>
                </div>
                <div className="quick-stat">
                  <span className="stat-label">Critical Alerts</span>
                  <span className="stat-value critical">{stats.criticalAlerts}</span>
                </div>
                <div className="quick-stat">
                  <span className="stat-label">System Status</span>
                  <span className="stat-value healthy">
                    {systemStatus.database === 'CONNECTED' ? '✓ Healthy' : '⚠ Warning'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        {/* Right Panel - Alerts */}
        <div className="right-panel">
          <div className="panel alerts-panel">
            <AlertsList 
              alerts={recentAlerts} 
              onRefresh={fetchDashboardData}
            />
          </div>
        </div>
      </div>
      
      {/* Footer */}
      <footer className="dashboard-footer">
        <div className="footer-content">
          <span>Malware Detection System v2.0</span>
          <span className="separator">•</span>
          <span>Hybrid Detection (Rules + ML)</span>
          <span className="separator">•</span>
          <span>{stats.totalLogs.toLocaleString()} flows analyzed</span>
        </div>
      </footer>
    </div>
  )
}