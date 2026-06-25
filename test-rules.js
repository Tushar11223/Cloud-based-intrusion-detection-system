#!/usr/bin/env node
/**
 * Test Rule Engine
 * Run: node test-rules.js
 */

const ruleEngine = require('./backend/utils/ruleEngine');

console.log('🧪 Testing Rule Engine\n');

// Test 1: Check if analyzeFlow exists
console.log('Test 1: Function exists');
console.log('✓ analyzeFlow:', typeof ruleEngine.analyzeFlow);
console.log('✓ getAllRules:', typeof ruleEngine.getAllRules);
console.log('✓ getRuleById:', typeof ruleEngine.getRuleById);
console.log('');

// Test 2: Get all rules
console.log('Test 2: Get all rules');
const allRules = ruleEngine.getAllRules();
console.log(`✓ Total rules: ${allRules.length}`);
allRules.forEach(rule => {
  console.log(`  - ${rule.id}: ${rule.name} (${rule.severity})`);
});
console.log('');

// Test 3: Analyze sample flows
console.log('Test 3: Analyze sample flows');

const testFlows = [
  {
    name: 'Normal HTTP Traffic',
    flowLog: {
      srcAddr: '192.168.1.100',
      dstAddr: '8.8.8.8',
      srcPort: 54321,
      dstPort: 80,
      protocol: 6,
      packets: 50,
      bytes: 5000,
      duration: 2
    }
  },
  {
    name: 'Malicious Port (4444)',
    flowLog: {
      srcAddr: '10.0.0.5',
      dstAddr: '203.0.113.1',
      srcPort: 12345,
      dstPort: 4444,
      protocol: 6,
      packets: 5,
      bytes: 200,
      duration: 1
    }
  },
  {
    name: 'Port Scan (SSH)',
    flowLog: {
      srcAddr: '172.16.0.10',
      dstAddr: '192.168.1.50',
      srcPort: 60000,
      dstPort: 22,
      protocol: 6,
      packets: 3,
      bytes: 150,
      duration: 0.5
    }
  },
  {
    name: 'Data Exfiltration',
    flowLog: {
      srcAddr: '192.168.1.200',
      dstAddr: '1.2.3.4',
      srcPort: 55555,
      dstPort: 443,
      protocol: 6,
      packets: 5000,
      bytes: 5000000,
      duration: 60
    }
  }
];

testFlows.forEach(test => {
  console.log(`\n${test.name}:`);
  const matches = ruleEngine.analyzeFlow(test.flowLog);
  
  if (matches.length === 0) {
    console.log('  ✓ No threats detected (benign)');
  } else {
    console.log(`  ⚠️  ${matches.length} threat(s) detected:`);
    matches.forEach(match => {
      console.log(`     - ${match.name} (${match.severity})`);
      console.log(`       ${match.description}`);
    });
  }
});

console.log('\n✅ Rule engine test complete!\n');