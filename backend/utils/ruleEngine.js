// utils/ruleEngine.js
// Rule-Based Detection Engine

/**
 * Rule-Based Detection Rules
 * Each rule checks for specific malware patterns
 */

const RULES = [
  {
    id: 'RULE_001',
    name: 'Suspicious Port Scanning',
    type: 'PORT_SCAN',
    severity: 'HIGH',
    description: 'Multiple connections to sequential ports from same source',
    confidence: 0.85,
    check: (flowLog) => {
      // Detect common scanning ports
      const scanPorts = [21, 22, 23, 25, 80, 443, 445, 3389, 8080];
      return scanPorts.includes(flowLog.dstPort) && flowLog.packets < 5;
    }
  },
  
  {
    id: 'RULE_002',
    name: 'C2 Beaconing Pattern',
    type: 'C2_BEACONING',
    severity: 'CRITICAL',
    description: 'Regular periodic connections indicating command & control',
    confidence: 0.90,
    check: (flowLog) => {
      // Small packets at regular intervals
      const avgPacketSize = flowLog.bytes / (flowLog.packets || 1);
      return flowLog.packets > 0 && 
             flowLog.packets < 20 && 
             avgPacketSize < 100 &&
             flowLog.duration > 60;
    }
  },
  
  {
    id: 'RULE_003',
    name: 'Data Exfiltration',
    type: 'DATA_EXFILTRATION',
    severity: 'CRITICAL',
    description: 'Large outbound data transfer',
    confidence: 0.80,
    check: (flowLog) => {
      // Large amount of data sent out
      return flowLog.bytes > 1000000 && // > 1MB
             flowLog.packets > 100 &&
             flowLog.protocol === 6; // TCP
    }
  },
  
  {
    id: 'RULE_004',
    name: 'DoS Attack Pattern',
    type: 'DOS_ATTACK',
    severity: 'CRITICAL',
    description: 'High volume of packets indicating denial of service',
    confidence: 0.85,
    check: (flowLog) => {
      // Very high packet count in short time
      const packetsPerSecond = flowLog.packets / (flowLog.duration || 1);
      return packetsPerSecond > 1000 || flowLog.packets > 10000;
    }
  },
  
  {
    id: 'RULE_005',
    name: 'Suspicious Destination Port',
    type: 'SUSPICIOUS_PORT',
    severity: 'MEDIUM',
    description: 'Connection to commonly exploited ports',
    confidence: 0.70,
    check: (flowLog) => {
      // Known malicious ports
      const maliciousPorts = [4444, 5555, 6666, 7777, 8888, 9999, 31337];
      return maliciousPorts.includes(flowLog.dstPort);
    }
  },
  
  {
    id: 'RULE_006',
    name: 'Brute Force Attempt',
    type: 'BRUTE_FORCE',
    severity: 'HIGH',
    description: 'Multiple failed connection attempts',
    confidence: 0.75,
    check: (flowLog) => {
      // SSH or RDP with low duration
      const authPorts = [22, 3389];
      return authPorts.includes(flowLog.dstPort) &&
             flowLog.duration < 1 &&
             flowLog.packets < 10;
    }
  },
  
  {
    id: 'RULE_007',
    name: 'Web Attack Pattern',
    type: 'WEB_ATTACK',
    severity: 'HIGH',
    description: 'Suspicious HTTP/HTTPS traffic pattern',
    confidence: 0.70,
    check: (flowLog) => {
      // HTTP/HTTPS with suspicious patterns
      const webPorts = [80, 443, 8080, 8443];
      const avgPacketSize = flowLog.bytes / (flowLog.packets || 1);
      return webPorts.includes(flowLog.dstPort) &&
             avgPacketSize > 1000 && // Large requests
             flowLog.packets < 50;
    }
  },
  
  {
    id: 'RULE_008',
    name: 'Abnormal Traffic Volume',
    type: 'VOLUME_ANOMALY',
    severity: 'MEDIUM',
    description: 'Unusually high data volume',
    confidence: 0.65,
    check: (flowLog) => {
      return flowLog.bytes > 10000000; // > 10MB
    }
  }
];

/**
 * Analyze a flow log against all rules
 * @param {Object} flowLog - Flow log to analyze
 * @returns {Array} Array of matched rules
 */
function analyzeFlow(flowLog) {
  if (!flowLog) {
    return [];
  }
  
  const matches = [];
  
  for (const rule of RULES) {
    try {
      if (rule.check(flowLog)) {
        matches.push({
          id: rule.id,
          name: rule.name,
          type: rule.type,
          severity: rule.severity,
          description: rule.description,
          confidence: rule.confidence
        });
      }
    } catch (err) {
      console.error(`Rule ${rule.id} check failed:`, err.message);
    }
  }
  
  return matches;
}

/**
 * Get all available rules
 * @returns {Array} Array of all rules
 */
function getAllRules() {
  return RULES.map(rule => ({
    id: rule.id,
    name: rule.name,
    type: rule.type,
    severity: rule.severity,
    description: rule.description,
    confidence: rule.confidence
  }));
}

/**
 * Get rule by ID
 * @param {String} ruleId - Rule ID
 * @returns {Object} Rule object or null
 */
function getRuleById(ruleId) {
  const rule = RULES.find(r => r.id === ruleId);
  if (!rule) return null;
  
  return {
    id: rule.id,
    name: rule.name,
    type: rule.type,
    severity: rule.severity,
    description: rule.description,
    confidence: rule.confidence
  };
}

/**
 * Test rules against sample data
 * @returns {Object} Test results
 */
function testRules() {
  const testFlows = [
    {
      srcAddr: '192.168.1.100',
      dstAddr: '8.8.8.8',
      srcPort: 54321,
      dstPort: 4444, // Malicious port
      protocol: 6,
      packets: 10,
      bytes: 500,
      duration: 5
    },
    {
      srcAddr: '10.0.0.5',
      dstAddr: '203.0.113.1',
      srcPort: 12345,
      dstPort: 80,
      protocol: 6,
      packets: 1000,
      bytes: 50000,
      duration: 2
    }
  ];
  
  const results = testFlows.map(flow => ({
    flow,
    matches: analyzeFlow(flow)
  }));
  
  return {
    totalTests: testFlows.length,
    results
  };
}

module.exports = {
  analyzeFlow,
  getAllRules,
  getRuleById,
  testRules,
  RULES
};