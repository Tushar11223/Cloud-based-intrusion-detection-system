#!/usr/bin/env node
/**
 * Backend CLI - FIXED CSV Column Detection
 */

const mongoose = require('mongoose');
const fs = require('fs');
const csv = require('csv-parser');

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/malware_detection';

let FlowLog, Alert;

async function connectDB() {
  try {
    console.log('🔌 Connecting to MongoDB...');
    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      connectTimeoutMS: 10000,
    });
    console.log('✓ Connected to MongoDB');
    
    FlowLog = require('./models/FlowLog');
    Alert = require('./models/Alert');
    console.log('✓ Models loaded');
    return true;
  } catch (err) {
    console.error('✗ MongoDB connection failed:', err.message);
    process.exit(1);
  }
}

function mapAttackType(label) {
  if (!label) return 'UNKNOWN';
  label = String(label).trim().toUpperCase();
  if (label === 'BENIGN') return 'BENIGN';
  if (label.includes('PORTSCAN')) return 'PORT_SCAN';
  if (label.includes('BOT')) return 'C2_BEACONING';
  if (label.includes('INFILTRATION')) return 'DATA_EXFILTRATION';
  if (label.includes('DOS') || label.includes('DDOS')) return 'DOS_ATTACK';
  if (label.includes('BRUTE') || label.includes('PATATOR')) return 'BRUTE_FORCE';
  if (label.includes('WEB ATTACK')) return 'WEB_ATTACK';
  return 'MALWARE';
}

// Helper function to find column value with multiple possible names
function getColumnValue(row, possibleNames, defaultValue = '0.0.0.0') {
  for (const name of possibleNames) {
    if (row[name] !== undefined && row[name] !== null && row[name] !== '') {
      return String(row[name]).trim();
    }
  }
  return defaultValue;
}

async function importDataset(csvPath) {
  console.log(`\n📥 Importing dataset: ${csvPath}\n`);
  
  if (!fs.existsSync(csvPath)) {
    console.error('✗ File not found:', csvPath);
    process.exit(1);
  }
  
  let totalRows = 0;
  let savedRows = 0;
  let errorRows = 0;
  let currentBatch = [];
  let sampleRow = null;
  
  const BATCH_SIZE = 500;
  
  return new Promise((resolve, reject) => {
    const stream = fs.createReadStream(csvPath)
      .pipe(csv())
      .on('data', (row) => {
        totalRows++;
        
        // Save first row to show column names
        if (totalRows === 1) {
          sampleRow = row;
          console.log('📋 CSV Columns detected:');
          console.log(Object.keys(row).slice(0, 10).join(', '));
          console.log('');
        }
        
        try {
          // Multiple possible column names for each field
          const srcAddr = getColumnValue(row, [
            'Source IP', 'Src IP', ' Source IP', ' Src IP',
            'source_ip', 'src_ip', 'SourceIP', 'SrcIP'
          ]);
          
          const dstAddr = getColumnValue(row, [
            'Destination IP', 'Dst IP', ' Destination IP', ' Dst IP',
            'destination_ip', 'dst_ip', 'DestinationIP', 'DstIP'
          ]);
          
          const srcPortStr = getColumnValue(row, [
            'Source Port', 'Src Port', ' Source Port', ' Src Port',
            'source_port', 'src_port', 'SourcePort', 'SrcPort'
          ], '0');
          
          const dstPortStr = getColumnValue(row, [
            'Destination Port', 'Dst Port', ' Destination Port', ' Dst Port',
            'destination_port', 'dst_port', 'DestinationPort', 'DstPort'
          ], '0');
          
          const protocolStr = getColumnValue(row, [
            'Protocol', ' Protocol', 'protocol'
          ], '6');
          
          const fwdPacketsStr = getColumnValue(row, [
            'Total Fwd Packets', ' Total Fwd Packets',
            'total_fwd_packets', 'TotalFwdPackets', 'Fwd Packets'
          ], '0');
          
          const bwdPacketsStr = getColumnValue(row, [
            'Total Backward Packets', ' Total Backward Packets',
            'total_backward_packets', 'TotalBackwardPackets', 'Bwd Packets'
          ], '0');
          
          const fwdBytesStr = getColumnValue(row, [
            'Total Length of Fwd Packets', ' Total Length of Fwd Packets',
            'total_length_of_fwd_packets', 'TotalLengthOfFwdPackets', 'Fwd Bytes'
          ], '0');
          
          const bwdBytesStr = getColumnValue(row, [
            'Total Length of Bwd Packets', ' Total Length of Bwd Packets',
            'total_length_of_bwd_packets', 'TotalLengthOfBwdPackets', 'Bwd Bytes'
          ], '0');
          
          const durationStr = getColumnValue(row, [
            'Flow Duration', ' Flow Duration', 'flow_duration', 'Duration'
          ], '0');
          
          const label = getColumnValue(row, [
            'Label', ' Label', 'label', 'CLASS', 'class'
          ], 'UNKNOWN');
          
          // Parse values
          const srcPort = parseInt(srcPortStr) || 0;
          const dstPort = parseInt(dstPortStr) || 0;
          const protocol = parseInt(protocolStr) || 6;
          
          const fwdPackets = parseFloat(fwdPacketsStr) || 0;
          const bwdPackets = parseFloat(bwdPacketsStr) || 0;
          const packets = parseInt(fwdPackets + bwdPackets) || 0;
          
          const fwdBytes = parseFloat(fwdBytesStr) || 0;
          const bwdBytes = parseFloat(bwdBytesStr) || 0;
          const bytes = parseInt(fwdBytes + bwdBytes) || 0;
          
          const duration = parseFloat(durationStr) / 1000000 || 0;
          
          const actualLabel = label.toUpperCase() === 'BENIGN' ? 'BENIGN' : 'MALWARE';
          const patternType = mapAttackType(label);
          
          // Validate IP addresses
          if (srcAddr === '0.0.0.0' && dstAddr === '0.0.0.0') {
            if (totalRows <= 5) {
              console.warn(`⚠️  Row ${totalRows}: Both IPs are 0.0.0.0 - check CSV column names!`);
            }
          }
          
          const flowLog = {
            flowId: `cicids-${Date.now()}-${totalRows}`,
            timestamp: new Date(),
            srcAddr,
            dstAddr,
            srcPort,
            dstPort,
            protocol,
            packets,
            bytes,
            duration,
            action: 'ACCEPT',
            actualLabel,
            patternType,
            analyzed: false,
            detectedAs: 'PENDING',
            source: 'CIC-IDS-2017'
          };
          
          currentBatch.push(flowLog);
          
        } catch (err) {
          errorRows++;
          if (errorRows <= 3) {
            console.error(`⚠️  Row ${totalRows} parse error:`, err.message);
          }
        }
        
        if (currentBatch.length >= BATCH_SIZE) {
          const batchToInsert = [...currentBatch];
          currentBatch = [];
          stream.pause();
          
          FlowLog.insertMany(batchToInsert, { ordered: false })
            .then((docs) => {
              savedRows += docs.length;
              process.stdout.write(`\r  Progress: ${totalRows.toLocaleString()} rows | Saved: ${savedRows.toLocaleString()}`);
              stream.resume();
            })
            .catch((err) => {
              console.error(`\n⚠️  Batch insert error: ${err.message}`);
              stream.resume();
            });
        }
      })
      .on('end', async () => {
        if (currentBatch.length > 0) {
          try {
            const docs = await FlowLog.insertMany(currentBatch, { ordered: false });
            savedRows += docs.length;
          } catch (err) {
            console.error('\n⚠️  Final batch error:', err.message);
          }
        }
        
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        console.log(`\n\n✓ Import complete!`);
        console.log(`  Total rows processed: ${totalRows.toLocaleString()}`);
        
        if (errorRows > 0) {
          console.log(`  Rows with errors: ${errorRows.toLocaleString()}`);
        }
        
        try {
          const dbTotal = await FlowLog.countDocuments({ source: 'CIC-IDS-2017' });
          const dbBenign = await FlowLog.countDocuments({ source: 'CIC-IDS-2017', actualLabel: 'BENIGN' });
          const dbMalware = await FlowLog.countDocuments({ source: 'CIC-IDS-2017', actualLabel: 'MALWARE' });
          
          // Check for 0.0.0.0 IPs
          const zeroIPs = await FlowLog.countDocuments({ 
            source: 'CIC-IDS-2017', 
            srcAddr: '0.0.0.0',
            dstAddr: '0.0.0.0'
          });
          
          console.log(`\n📊 Database Statistics:`);
          console.log(`  Total saved: ${dbTotal.toLocaleString()}`);
          console.log(`  Benign: ${dbBenign.toLocaleString()}`);
          console.log(`  Malware: ${dbMalware.toLocaleString()}`);
          
          if (zeroIPs > 0) {
            console.log(`\n⚠️  WARNING: ${zeroIPs.toLocaleString()} rows have 0.0.0.0 IPs`);
            console.log(`  This means column names don't match!`);
            console.log(`\n  First row columns were:`);
            if (sampleRow) {
              console.log(`  ${Object.keys(sampleRow).slice(0, 15).join(', ')}`);
            }
          }
        } catch (err) {
          console.error('  Could not fetch statistics:', err.message);
        }
        
        resolve();
      })
      .on('error', (err) => {
        console.error('\n✗ CSV read error:', err.message);
        reject(err);
      });
  });
}

// ... rest of the functions (generateLogs, analyzeLogs, showStats, resetData, main) ...
// Copy from previous backend-cli.js

async function showStats() {
  console.log('\n📊 Database Statistics\n');
  
  try {
    const totalLogs = await FlowLog.countDocuments();
    const benignLogs = await FlowLog.countDocuments({ actualLabel: 'BENIGN' });
    const malwareLogs = await FlowLog.countDocuments({ actualLabel: 'MALWARE' });
    const analyzedLogs = await FlowLog.countDocuments({ analyzed: true });
    const pendingLogs = await FlowLog.countDocuments({ analyzed: false });
    
    console.log('Flow Logs:');
    console.log(`  Total: ${totalLogs.toLocaleString()}`);
    console.log(`  Benign: ${benignLogs.toLocaleString()}`);
    console.log(`  Malware: ${malwareLogs.toLocaleString()}`);
    console.log(`  Analyzed: ${analyzedLogs.toLocaleString()}`);
    console.log(`  Pending: ${pendingLogs.toLocaleString()}`);
    console.log('');
    
    const totalAlerts = await Alert.countDocuments();
    const criticalAlerts = await Alert.countDocuments({ severity: 'CRITICAL' });
    
    console.log('Alerts:');
    console.log(`  Total: ${totalAlerts.toLocaleString()}`);
    console.log(`  Critical: ${criticalAlerts.toLocaleString()}`);
  } catch (err) {
    console.error('✗ Error:', err.message);
  }
}

async function resetData() {
  console.log('\n⚠️  Resetting all data...\n');
  const deletedLogs = await FlowLog.deleteMany({});
  const deletedAlerts = await Alert.deleteMany({});
  console.log(`✓ Deleted ${deletedLogs.deletedCount.toLocaleString()} flow logs`);
  console.log(`✓ Deleted ${deletedAlerts.deletedCount.toLocaleString()} alerts`);
}

async function main() {
  const command = process.argv[2];
  const arg = process.argv[3];
  
  if (!command) {
    console.log(`
╔═══════════════════════════════════════════════════════╗
║     Malware Detection - Backend CLI Tool             ║
╚═══════════════════════════════════════════════════════╝

Usage: node backend-cli.js <command> [options]

Commands:
  import <csv-file>     Import dataset from CSV
  stats                 Show database statistics
  reset                 Clear all data

Examples:
  node backend-cli.js import F:\\datasets\\Monday.csv
  node backend-cli.js stats
  node backend-cli.js reset
    `);
    process.exit(0);
  }
  
  await connectDB();
  
  try {
    switch (command.toLowerCase()) {
      case 'import':
        if (!arg) {
          console.error('\n✗ Error: CSV file path required');
          process.exit(1);
        }
        await importDataset(arg);
        break;
        
      case 'stats':
        await showStats();
        break;
        
      case 'reset':
        await resetData();
        break;
        
      default:
        console.error(`\n✗ Unknown command: ${command}`);
        process.exit(1);
    }
    
    await mongoose.connection.close();
    console.log('\n✓ Done\n');
    process.exit(0);
    
  } catch (error) {
    console.error('\n✗ Error:', error.message);
    await mongoose.connection.close();
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
  });
}

module.exports = { connectDB, importDataset, showStats, resetData };