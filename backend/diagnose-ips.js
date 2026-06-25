#!/usr/bin/env node
/**
 * Diagnostic Script - Check IP Addresses in Database
 */

const mongoose = require('mongoose');

const MONGO_URI = 'mongodb://localhost:27017/malware_detection';

async function diagnose() {
  try {
    console.log('🔌 Connecting to MongoDB...\n');
    await mongoose.connect(MONGO_URI);
    
    const FlowLog = require('./models/FlowLog');
    
    console.log('📊 Analyzing IP Addresses in Database\n');
    
    // Total logs
    const total = await FlowLog.countDocuments();
    console.log(`Total Logs: ${total.toLocaleString()}`);
    
    // Logs with 0.0.0.0 IPs
    const zeroSrcIP = await FlowLog.countDocuments({ srcAddr: '0.0.0.0' });
    const zeroDstIP = await FlowLog.countDocuments({ dstAddr: '0.0.0.0' });
    const zeroBothIP = await FlowLog.countDocuments({ srcAddr: '0.0.0.0', dstAddr: '0.0.0.0' });
    
    console.log(`\nIP Address Analysis:`);
    console.log(`  Logs with srcAddr = 0.0.0.0: ${zeroSrcIP.toLocaleString()}`);
    console.log(`  Logs with dstAddr = 0.0.0.0: ${zeroDstIP.toLocaleString()}`);
    console.log(`  Logs with BOTH = 0.0.0.0: ${zeroBothIP.toLocaleString()}`);
    
    // Get sample of real IPs
    const realIPLogs = await FlowLog.find({
      srcAddr: { $ne: '0.0.0.0' },
      dstAddr: { $ne: '0.0.0.0' }
    }).limit(5);
    
    if (realIPLogs.length > 0) {
      console.log(`\n✅ Found ${realIPLogs.length} logs with real IPs:`);
      realIPLogs.forEach((log, i) => {
        console.log(`  ${i+1}. ${log.srcAddr} → ${log.dstAddr}`);
      });
    } else {
      console.log('\n❌ NO logs with real IPs found!');
      console.log('   All ${total.toLocaleString()} logs have 0.0.0.0 IPs');
    }
    
    // Check malware count
    const malwareCount = await FlowLog.countDocuments({ actualLabel: 'MALWARE' });
    const benignCount = await FlowLog.countDocuments({ actualLabel: 'BENIGN' });
    
    console.log(`\nLabel Distribution:`);
    console.log(`  Malware: ${malwareCount.toLocaleString()}`);
    console.log(`  Benign: ${benignCount.toLocaleString()}`);
    
    // Recommendation
    console.log(`\n💡 Recommendation:`);
    
    if (zeroBothIP > total * 0.9) {
      console.log(`  ⚠️  ${((zeroBothIP/total)*100).toFixed(1)}% of logs have 0.0.0.0 IPs!`);
      console.log(`  This means CSV column names didn't match during import.`);
      console.log(`\n  Solution:`);
      console.log(`  1. Delete current data: node backend-cli.js reset`);
      console.log(`  2. Re-import with fixed CLI: node backend-cli.js import <file>`);
      console.log(`  3. The new CLI auto-detects column names`);
    } else {
      console.log(`  ✓ Most logs have real IPs - data looks good!`);
    }
    
    await mongoose.connection.close();
    console.log('\n✓ Diagnosis complete\n');
    
  } catch (err) {
    console.error('✗ Error:', err.message);
    process.exit(1);
  }
}

diagnose();