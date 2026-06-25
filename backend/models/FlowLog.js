// models/FlowLog.js
// MongoDB schema for network flow logs (AWS VPC Flow Logs style)

const mongoose = require('mongoose');

/**
 * FlowLog Schema
 * Simulates AWS VPC Flow Log format with additional fields for malware detection
 * 
 * Format inspired by AWS VPC Flow Logs:
 * version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
 */
const flowLogSchema = new mongoose.Schema({
  // Basic flow information
  timestamp: {
    type: Date,
    default: Date.now,
    required: true,
    index: true
  },
  
  // Source information
  srcAddr: {
    type: String,
    required: true,
    index: true
  },
  srcPort: {
    type: Number,
    required: true
  },
  
  // Destination information
  dstAddr: {
    type: String,
    required: true,
    index: true
  },
  dstPort: {
    type: Number,
    required: true,
    index: true
  },
  
  // Protocol (6=TCP, 17=UDP, 1=ICMP)
  protocol: {
    type: Number,
    required: true
  },
  
  // Traffic metrics
  packets: {
    type: Number,
    default: 0
  },
  bytes: {
    type: Number,
    default: 0
  },
  
  // Connection duration (seconds)
  duration: {
    type: Number,
    default: 0
  },
  
  // Action (ACCEPT or REJECT)
  action: {
    type: String,
    enum: ['ACCEPT', 'REJECT'],
    default: 'ACCEPT'
  },
  
  // TCP flags (if TCP protocol)
  tcpFlags: {
    type: String,
    default: ''
  },
  
  // Flow metadata
  flowId: {
    type: String,
    unique: true,
    required: true
  },
  
  // Data source - ADDED THIS FIELD
  source: {
    type: String,
    enum: ['CIC-IDS-2017', 'CIC-IDS-2018', 'NSL-KDD', 'UNSW-NB15', 'synthetic', 'live'],
    default: 'synthetic',
    index: true
  },
  
  // Classification labels
  isSimulated: {
    type: Boolean,
    default: true
  },
  
  // Ground truth label (for simulated data)
  actualLabel: {
    type: String,
    enum: ['BENIGN', 'MALWARE', 'UNKNOWN'],
    default: 'UNKNOWN'
  },
  
  // Traffic pattern type (for simulated malware) - UPDATED ENUM
  patternType: {
    type: String,
    enum: [
      'NORMAL',
      'BENIGN',
      'C2_BEACONING', 
      'PORT_SCAN', 
      'DATA_EXFILTRATION',
      'DOS_ATTACK',
      'BRUTE_FORCE',
      'WEB_ATTACK',
      'MALWARE',
      'UNKNOWN'
    ],
    default: 'NORMAL'
  },
  
  // Detection status
  analyzed: {
    type: Boolean,
    default: false
  },
  
  detectedAs: {
    type: String,
    enum: ['BENIGN', 'SUSPICIOUS', 'MALICIOUS', 'PENDING'],
    default: 'PENDING'
  },
  
  // ML prediction details - ADDED
  mlPrediction: {
    type: Number, // 0 = benign, 1 = malware
    default: null
  },
  
  mlConfidence: {
    type: Number,
    default: null
  },
  
  ruleMatches: [{
    type: String
  }],
  
  analyzedAt: {
    type: Date,
    default: null
  }
}, {
  timestamps: true,
  collection: 'flow_logs'
});

// Indexes for efficient querying
flowLogSchema.index({ timestamp: -1 });
flowLogSchema.index({ srcAddr: 1, dstAddr: 1 });
flowLogSchema.index({ dstPort: 1 });
flowLogSchema.index({ detectedAs: 1 });
flowLogSchema.index({ patternType: 1 });
flowLogSchema.index({ source: 1 });
flowLogSchema.index({ analyzed: 1 });
flowLogSchema.index({ actualLabel: 1 });

// Virtual field for protocol name
flowLogSchema.virtual('protocolName').get(function() {
  const protocolMap = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP'
  };
  return protocolMap[this.protocol] || 'UNKNOWN';
});

// Method to get flow summary
flowLogSchema.methods.getSummary = function() {
  return {
    flowId: this.flowId,
    timestamp: this.timestamp,
    source: `${this.srcAddr}:${this.srcPort}`,
    destination: `${this.dstAddr}:${this.dstPort}`,
    protocol: this.protocolName,
    bytes: this.bytes,
    packets: this.packets,
    duration: this.duration,
    action: this.action,
    detected: this.detectedAs,
    dataSource: this.source
  };
};

// Static method to get traffic statistics
flowLogSchema.statics.getStatistics = async function(startDate, endDate) {
  return await this.aggregate([
    {
      $match: {
        timestamp: { 
          $gte: startDate, 
          $lte: endDate 
        }
      }
    },
    {
      $group: {
        _id: '$detectedAs',
        count: { $sum: 1 },
        totalBytes: { $sum: '$bytes' },
        totalPackets: { $sum: '$packets' }
      }
    }
  ]);
};

module.exports = mongoose.model('FlowLog', flowLogSchema);