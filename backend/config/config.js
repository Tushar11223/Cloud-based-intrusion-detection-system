// config/config.js
// Configuration settings for the malware detection system

module.exports = {
  // Server configuration
  port: process.env.PORT || 5000,
  
  // MongoDB configuration
  mongoUri: process.env.MONGO_URI || 'mongodb://localhost:27017/malware_detection',
  
  // ML Service configuration
  mlServiceUrl: process.env.ML_SERVICE_URL || 'http://localhost:5001',
  
  // Detection thresholds
  detection: {
    // Rule-based thresholds
    beaconing: {
      minConnections: 5,           // Minimum connections to consider beaconing
      timeWindowSeconds: 60,       // Time window for analysis
      intervalVariance: 5,         // Max variance in seconds for periodic behavior
      minInterval: 10,             // Minimum interval between connections (seconds)
      maxInterval: 300             // Maximum interval between connections (seconds)
    },
    
    volumeAnomaly: {
      bytesThreshold: 100000000,   // 100MB threshold for single connection
      packetsThreshold: 100000     // Packet count threshold
    },
    
    portScanning: {
      uniquePortsThreshold: 20,    // Number of unique ports accessed
      timeWindowSeconds: 60        // Time window for port scanning detection
    },
    
    // ML-based thresholds
    ml: {
      confidenceThreshold: 0.7     // Minimum confidence for ML predictions
    }
  },
  
  // Suspicious IP ranges (for simulation)
  suspiciousIpRanges: [
    '203.0.113.0/24',              // TEST-NET-3 (RFC 5737)
    '198.51.100.0/24',             // TEST-NET-2 (RFC 5737)
    '192.0.2.0/24'                 // TEST-NET-1 (RFC 5737)
  ],
  
  // Known malicious ports
  suspiciousPorts: [
    4444,  // Metasploit default
    5555,  // Common backdoor
    6666,  // IRC/Backdoor
    6667,  // IRC
    31337, // Elite/backdoor
    12345  // NetBus
  ],
  
  // Alert severity mapping
  severity: {
    CRITICAL: 'CRITICAL',
    HIGH: 'HIGH',
    MEDIUM: 'MEDIUM',
    LOW: 'LOW'
  },
  
  // Log generation settings (for simulation)
  logGeneration: {
    normalTrafficRatio: 0.85,      // 85% normal traffic
    malwareTrafficRatio: 0.15,     // 15% malware-like traffic
    logsPerBatch: 100,             // Logs generated per batch
    batchIntervalMs: 5000          // Interval between batches (5 seconds)
  }
};