// components/StatsCard.jsx
// Enhanced Stats Card Component

import React from 'react'
import './StatsCard.css'

export default function StatsCard({ title, value, subtitle, icon, trend, highlight }) {
  const getTrendIcon = () => {
    switch(trend) {
      case 'up': return '↗️'
      case 'down': return '↘️'
      case 'alert': return '⚠️'
      case 'safe': return '✓'
      default: return ''
    }
  }
  
  const getTrendClass = () => {
    switch(trend) {
      case 'up': return 'trend-up'
      case 'down': return 'trend-down'
      case 'alert': return 'trend-alert'
      case 'safe': return 'trend-safe'
      default: return ''
    }
  }
  
  return (
    <div className={`stats-card ${highlight ? 'highlight' : ''} ${getTrendClass()}`}>
      <div className="stats-card-content">
        <div className="stats-icon">{icon}</div>
        <div className="stats-info">
          <h3 className="stats-title">{title}</h3>
          <div className="stats-value-container">
            <span className="stats-value">{value}</span>
            {trend && <span className="trend-indicator">{getTrendIcon()}</span>}
          </div>
          {subtitle && <p className="stats-subtitle">{subtitle}</p>}
        </div>
      </div>
      <div className={`stats-card-footer ${getTrendClass()}`}></div>
    </div>
  )
}