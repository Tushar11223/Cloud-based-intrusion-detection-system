// models/Alert.js
// MongoDB schema for security alerts

const mongoose = require('mongoose');

/**
 * Alert Schema
 * Stores detected threats and anomalies from both rule-based and ML detection
 */
const alertSchema = new mongoose.Schema({
  // Alert identification
  alertId: {
    type: String,
    unique: true,
    required: false // Made optional for auto-generation
  },
  
  // Timestamp
  timestamp: {
    type: Date,
    default: Date.now,
    required: true,
    index: true
  },
  
  // Severity level
  severity: {
    type: String,
    enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
    required: true,
    index: true
  },
  
  // Alert type/category - EXPANDED ENUM
  alertType: {
    type: String,
    enum: [
      'C2_BEACONING',
      'PORT_SCANNING',
      'PORT_SCAN',
      'VOLUME_ANOMALY',
      'ML_DETECTION',
      'SUSPICIOUS_IP',
      'SUSPICIOUS_PORT',
      'DATA_EXFILTRATION',
      'DOS_ATTACK',
      'BRUTE_FORCE',
      'WEB_ATTACK',
      'RULE_BASED',
      'UNKNOWN'
    ],
    required: true
  },
  
  // Detection method
  detectionMethod: {
    type: String,
    enum: ['RULE_BASED', 'MACHINE_LEARNING', 'HYBRID'],
    required: true
  },
  
  // Related flow log reference
  flowLogId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'FlowLog'
  },
  
  // Source and destination
  sourceIp: {
    type: String,
    required: true
  },
  destinationIp: {
    type: String,
    required: true
  },
  sourcePort: {
    type: Number
  },
  destinationPort: {
    type: Number
  },
  protocol: {
    type: Number
  },
  
  // Alert description
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  
  // Detection details
  detectionDetails: {
    // For rule-based detection
    ruleName: String,
    ruleConditions: [String],
    
    // For ML detection
    mlModel: String,
    confidence: Number,
    predictedClass: String,
    
    // Evidence
    evidence: mongoose.Schema.Types.Mixed
  },
  
  // Simplified confidence field at root level
  confidence: {
    type: Number,
    min: 0,
    max: 1,
    default: 0.5
  },
  
  // Rule ID for rule-based detection
  ruleId: {
    type: String
  },
  
  // Risk score (0-100)
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 50
  },
  
  // Status
  status: {
    type: String,
    enum: ['NEW', 'INVESTIGATING', 'CONFIRMED', 'FALSE_POSITIVE', 'RESOLVED'],
    default: 'NEW'
  },
  
  // Response actions
  recommendedActions: [{
    type: String
  }],
  
  // Analysis
  analyzed: {
    type: Boolean,
    default: false
  },
  analystNotes: {
    type: String,
    default: ''
  },
  
  // Metadata
  metadata: {
    affectedAssets: [String],
    relatedAlerts: [String],
    tags: [String]
  }
}, {
  timestamps: true,
  collection: 'alerts'
});

// Auto-generate alertId if not provided
alertSchema.pre('save', function(next) {
  if (!this.alertId) {
    this.alertId = `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
  next();
});

// Indexes
alertSchema.index({ timestamp: -1 });
alertSchema.index({ severity: 1, status: 1 });
alertSchema.index({ alertType: 1 });
alertSchema.index({ sourceIp: 1 });
alertSchema.index({ destinationIp: 1 });

// Virtual for age calculation
alertSchema.virtual('age').get(function() {
  return Math.floor((Date.now() - this.timestamp) / 1000 / 60); // minutes
});

// Method to format alert for display
alertSchema.methods.formatForDisplay = function() {
  return {
    id: this.alertId,
    timestamp: this.timestamp,
    severity: this.severity,
    type: this.alertType,
    title: this.title,
    description: this.description,
    source: `${this.sourceIp}:${this.sourcePort || 'N/A'}`,
    destination: `${this.destinationIp}:${this.destinationPort || 'N/A'}`,
    riskScore: this.riskScore,
    status: this.status,
    detectionMethod: this.detectionMethod,
    confidence: this.confidence || this.detectionDetails?.confidence,
    age: this.age
  };
};

// Static method to get alert statistics
alertSchema.statics.getStatistics = async function(startDate, endDate) {
  return await this.aggregate([
    {
      $match: {
        timestamp: { $gte: startDate, $lte: endDate }
      }
    },
    {
      $group: {
        _id: {
          severity: '$severity',
          alertType: '$alertType'
        },
        count: { $sum: 1 },
        avgRiskScore: { $avg: '$riskScore' }
      }
    },
    {
      $sort: { count: -1 }
    }
  ]);
};

// Static method to get severity distribution
alertSchema.statics.getSeverityDistribution = async function(startDate, endDate) {
  return await this.aggregate([
    {
      $match: {
        timestamp: { $gte: startDate, $lte: endDate }
      }
    },
    {
      $group: {
        _id: '$severity',
        count: { $sum: 1 }
      }
    }
  ]);
};

module.exports = mongoose.model('Alert', alertSchema);