// utils/logGenerator.js
// Generates simulated network flow logs for testing and demonstration

const { v4: uuidv4 } = require('crypto');

/**
 * Network Flow Log Generator
 * Creates synthetic logs that simulate AWS VPC Flow Logs format
 * Includes both normal traffic and malware-like patterns
 */
class LogGenerator {
  constructor() {
    // Common internal IP ranges (simulated)
    this.internalIPs = [
      '10.0.1.15', '10.0.1.23', '10.0.1.45', '10.0.1.67',
      '10.0.2.12', '10.0.2.34', '10.0.2.56', '10.0.2.78'
    ];
    
    // Common legitimate external IPs
    this.legitimateExternalIPs = [
      '8.8.8.8',       // Google DNS
      '1.1.1.1',       // Cloudflare DNS
      '52.84.223.12',  // AWS CloudFront
      '151.101.1.69',  // Fastly CDN
      '172.217.14.206' // Google services
    ];
    
    // Suspicious IPs (using TEST-NET ranges for simulation)
    this.suspiciousIPs = [
      '203.0.113.45',  // TEST-NET-3
      '198.51.100.23', // TEST-NET-2
      '192.0.2.156',   // TEST-NET-1
      '203.0.113.89',
      '198.51.100.67'
    ];
    
    // Common legitimate ports
    this.commonPorts = {
      HTTP: 80,
      HTTPS: 443,
      DNS: 53,
      SSH: 22,
      FTP: 21,
      SMTP: 25,
      POP3: 110,
      IMAP: 143
    };
    
    // Suspicious ports
    this.suspiciousPorts = [4444, 5555, 6666, 6667, 31337, 12345];
  }
  
  /**
   * Generate random IP from array
   */
  randomIP(ipArray) {
    return ipArray[Math.floor(Math.random() * ipArray.length)];
  }
  
  /**
   * Generate random port
   */
  randomPort(portList = null) {
    if (portList) {
      return portList[Math.floor(Math.random() * portList.length)];
    }
    return Math.floor(Math.random() * 65535) + 1;
  }
  
  /**
   * Generate random byte count based on traffic type
   */
  randomBytes(trafficType = 'normal') {
    if (trafficType === 'normal') {
      return Math.floor(Math.random() * 50000) + 500; // 500B - 50KB
    } else if (trafficType === 'bulk') {
      return Math.floor(Math.random() * 10000000) + 100000; // 100KB - 10MB
    }
    return Math.floor(Math.random() * 5000) + 100; // Small packets
  }
  
  /**
   * Generate random packet count
   */
  randomPackets(bytes) {
    const avgPacketSize = 1200; // bytes
    const basePackets = Math.floor(bytes / avgPacketSize);
    return Math.max(1, basePackets + Math.floor(Math.random() * 10) - 5);
  }
  
  /**
   * Generate normal HTTP/HTTPS traffic
   */
  generateNormalHTTP() {
    const srcIP = this.randomIP(this.internalIPs);
    const dstIP = this.randomIP(this.legitimateExternalIPs);
    const dstPort = Math.random() > 0.7 ? this.commonPorts.HTTP : this.commonPorts.HTTPS;
    const bytes = this.randomBytes('normal');
    
    return {
      flowId: this.generateFlowId(),
      timestamp: new Date(),
      srcAddr: srcIP,
      srcPort: Math.floor(Math.random() * 60000) + 1024,
      dstAddr: dstIP,
      dstPort: dstPort,
      protocol: 6, // TCP
      packets: this.randomPackets(bytes),
      bytes: bytes,
      duration: Math.random() * 5 + 0.1, // 0.1-5 seconds
      action: 'ACCEPT',
      tcpFlags: 'SYN,ACK',
      actualLabel: 'BENIGN',
      patternType: 'NORMAL'
    };
  }
  
  /**
   * Generate normal DNS traffic
   */
  generateNormalDNS() {
    const srcIP = this.randomIP(this.internalIPs);
    const bytes = Math.floor(Math.random() * 500) + 100;
    
    return {
      flowId: this.generateFlowId(),
      timestamp: new Date(),
      srcAddr: srcIP,
      srcPort: Math.floor(Math.random() * 60000) + 1024,
      dstAddr: '8.8.8.8',
      dstPort: this.commonPorts.DNS,
      protocol: 17, // UDP
      packets: this.randomPackets(bytes),
      bytes: bytes,
      duration: Math.random() * 0.5 + 0.01, // Very short
      action: 'ACCEPT',
      tcpFlags: '',
      actualLabel: 'BENIGN',
      patternType: 'NORMAL'
    };
  }
  
  /**
   * Generate C2 beaconing pattern (malware-like)
   * Characteristic: Regular, periodic connections to same external IP
   */
  generateC2Beaconing() {
    const srcIP = this.randomIP(this.internalIPs);
    const dstIP = this.randomIP(this.suspiciousIPs);
    const dstPort = this.randomPort(this.suspiciousPorts);
    const bytes = Math.floor(Math.random() * 2000) + 100; // Small data transfers
    
    return {
      flowId: this.generateFlowId(),
      timestamp: new Date(),
      srcAddr: srcIP,
      srcPort: Math.floor(Math.random() * 60000) + 1024,
      dstAddr: dstIP,
      dstPort: dstPort,
      protocol: 6, // TCP
      packets: this.randomPackets(bytes),
      bytes: bytes,
      duration: Math.random() * 2 + 0.5, // Short connections
      action: 'ACCEPT',
      tcpFlags: 'SYN,ACK',
      actualLabel: 'MALWARE',
      patternType: 'C2_BEACONING'
    };
  }
  
  /**
   * Generate port scanning pattern (malware-like)
   * Characteristic: Same source connecting to many ports on same destination
   */
  generatePortScan() {
    const srcIP = this.randomIP(this.internalIPs);
    const dstIP = this.randomIP([...this.legitimateExternalIPs, ...this.suspiciousIPs]);
    const bytes = Math.floor(Math.random() * 100) + 40; // Minimal data
    
    return {
      flowId: this.generateFlowId(),
      timestamp: new Date(),
      srcAddr: srcIP,
      srcPort: Math.floor(Math.random() * 60000) + 1024,
      dstAddr: dstIP,
      dstPort: Math.floor(Math.random() * 65535) + 1, // Random port
      protocol: 6, // TCP
      packets: this.randomPackets(bytes),
      bytes: bytes,
      duration: Math.random() * 0.1 + 0.01, // Very short
      action: Math.random() > 0.5 ? 'ACCEPT' : 'REJECT',
      tcpFlags: 'SYN',
      actualLabel: 'MALWARE',
      patternType: 'PORT_SCAN'
    };
  }
  
  /**
   * Generate data exfiltration pattern (malware-like)
   * Characteristic: Large outbound data transfer to suspicious IP
   */
  generateDataExfiltration() {
    const srcIP = this.randomIP(this.internalIPs);
    const dstIP = this.randomIP(this.suspiciousIPs);
    const dstPort = this.randomPort(this.suspiciousPorts);
    const bytes = this.randomBytes('bulk'); // Large transfer
    
    return {
      flowId: this.generateFlowId(),
      timestamp: new Date(),
      srcAddr: srcIP,
      srcPort: Math.floor(Math.random() * 60000) + 1024,
      dstAddr: dstIP,
      dstPort: dstPort,
      protocol: 6, // TCP
      packets: this.randomPackets(bytes),
      bytes: bytes,
      duration: Math.random() * 30 + 5, // Longer duration
      action: 'ACCEPT',
      tcpFlags: 'SYN,ACK,PSH',
      actualLabel: 'MALWARE',
      patternType: 'DATA_EXFILTRATION'
    };
  }
  
  /**
   * Generate a batch of mixed traffic logs
   */
  generateBatch(count = 100, malwareRatio = 0.15) {
    const logs = [];
    const malwareCount = Math.floor(count * malwareRatio);
    const normalCount = count - malwareCount;
    
    // Generate normal traffic
    for (let i = 0; i < normalCount; i++) {
      const rand = Math.random();
      if (rand < 0.7) {
        logs.push(this.generateNormalHTTP());
      } else {
        logs.push(this.generateNormalDNS());
      }
    }
    
    // Generate malware traffic
    for (let i = 0; i < malwareCount; i++) {
      const rand = Math.random();
      if (rand < 0.4) {
        logs.push(this.generateC2Beaconing());
      } else if (rand < 0.7) {
        logs.push(this.generatePortScan());
      } else {
        logs.push(this.generateDataExfiltration());
      }
    }
    
    // Shuffle logs
    return this.shuffleArray(logs);
  }
  
  /**
   * Generate flow ID
   */
  generateFlowId() {
    // Simulate AWS-style flow ID
    return `flow-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
  
  /**
   * Shuffle array
   */
  shuffleArray(array) {
    const shuffled = [...array];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled;
  }
  
  /**
   * Generate logs continuously with time spacing
   * Simulates real-time log generation
   */
  generateContinuous(callback, intervalMs = 5000, batchSize = 10) {
    const generator = this;
    
    const interval = setInterval(() => {
      const logs = generator.generateBatch(batchSize);
      callback(logs);
    }, intervalMs);
    
    return interval; // Return interval ID for stopping
  }
}

module.exports = LogGenerator;

// Example usage for testing
if (require.main === module) {
  const generator = new LogGenerator();
  
  console.log('Generating sample network flow logs...\n');
  
  // Generate a batch
  const logs = generator.generateBatch(20, 0.3);
  
  console.log(`Generated ${logs.length} logs:`);
  logs.forEach((log, idx) => {
    console.log(`\n[${idx + 1}] Flow ID: ${log.flowId}`);
    console.log(`    ${log.srcAddr}:${log.srcPort} → ${log.dstAddr}:${log.dstPort}`);
    console.log(`    Protocol: ${log.protocol === 6 ? 'TCP' : 'UDP'}, Bytes: ${log.bytes}, Packets: ${log.packets}`);
    console.log(`    Label: ${log.actualLabel}, Pattern: ${log.patternType}`);
  });
  
  console.log('\n✓ Log generation test completed');
}