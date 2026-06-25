// routes/csvImport.js
// CSV Import Feature - Upload and process real network flow logs

const express = require('express');
const router = express.Router();
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');
const path = require('path');
const FlowLog = require('../models/FlowLog');

// Configure multer for file upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'flow-logs-' + uniqueSuffix + '.csv');
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
  fileFilter: (req, file, cb) => {
    if (path.extname(file.originalname).toLowerCase() !== '.csv') {
      return cb(new Error('Only CSV files are allowed'));
    }
    cb(null, true);
  }
});

/**
 * Map CIC-IDS 2017 CSV columns to our FlowLog schema
 */
function mapCICIDSToFlowLog(row) {
  return {
    flowId: `imported-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date(),
    
    // Basic flow info
    srcAddr: row['Source IP'] || row['Src IP'] || '0.0.0.0',
    dstAddr: row['Destination IP'] || row['Dst IP'] || '0.0.0.0',
    srcPort: parseInt(row['Source Port'] || row['Src Port'] || 0),
    dstPort: parseInt(row['Destination Port'] || row['Dst Port'] || 0),
    protocol: parseInt(row['Protocol'] || 6), // Default to TCP
    
    // Traffic volume
    packets: parseInt(row['Total Fwd Packets'] || row['Total Fwd Packet'] || 0) + 
             parseInt(row['Total Backward Packets'] || row['Total Backward Packet'] || 0),
    bytes: parseInt(row['Total Length of Fwd Packets'] || row['Total Length of Fwd Packet'] || 0) + 
           parseInt(row['Total Length of Bwd Packets'] || row['Total Length of Bwd Packet'] || 0),
    
    // Duration
    duration: parseFloat(row['Flow Duration'] || 0) / 1000000, // Convert microseconds to seconds
    
    // Action (assume ACCEPT if not rejected)
    action: 'ACCEPT',
    
    // TCP flags (if available)
    tcpFlags: [
      row['SYN Flag Count'] > 0 ? 'SYN' : null,
      row['FIN Flag Count'] > 0 ? 'FIN' : null,
      row['RST Flag Count'] > 0 ? 'RST' : null,
      row['PSH Flag Count'] > 0 ? 'PSH' : null,
      row['ACK Flag Count'] > 0 ? 'ACK' : null,
      row['URG Flag Count'] > 0 ? 'URG' : null
    ].filter(Boolean).join(','),
    
    // Label (ground truth)
    actualLabel: row['Label'] === 'BENIGN' ? 'BENIGN' : 'MALWARE',
    patternType: row['Label'] || 'UNKNOWN',
    
    // Analysis status
    analyzed: false,
    detectedAs: 'PENDING'
  };
}

/**
 * Map generic CSV to FlowLog schema
 * Handles various CSV formats
 */
function mapGenericCSVToFlowLog(row) {
  // Try to find source/destination IPs with flexible column names
  const srcAddrCandidates = ['srcAddr', 'src_addr', 'source_ip', 'src_ip', 'sourceAddress'];
  const dstAddrCandidates = ['dstAddr', 'dst_addr', 'destination_ip', 'dst_ip', 'destinationAddress'];
  
  const srcAddr = srcAddrCandidates.find(col => row[col]) || '0.0.0.0';
  const dstAddr = dstAddrCandidates.find(col => row[col]) || '0.0.0.0';
  
  return {
    flowId: `imported-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date(row.timestamp || Date.now()),
    srcAddr: row[srcAddr] || '0.0.0.0',
    dstAddr: row[dstAddr] || '0.0.0.0',
    srcPort: parseInt(row.srcPort || row.src_port || 0),
    dstPort: parseInt(row.dstPort || row.dst_port || 0),
    protocol: parseInt(row.protocol || 6),
    packets: parseInt(row.packets || 1),
    bytes: parseInt(row.bytes || 0),
    duration: parseFloat(row.duration || 0),
    action: row.action || 'ACCEPT',
    tcpFlags: row.tcpFlags || '',
    actualLabel: row.label === 'BENIGN' || row.label === '0' ? 'BENIGN' : 'MALWARE',
    patternType: row.pattern || 'IMPORTED',
    analyzed: false,
    detectedAs: 'PENDING'
  };
}

/**
 * POST /api/csv-import/upload
 * Upload and import CSV file
 */
router.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }
    
    const { format = 'cicids' } = req.body; // cicids, generic, or auto-detect
    const filePath = req.file.path;
    
    console.log(`Processing CSV file: ${req.file.originalname} (${format} format)`);
    
    const flowLogs = [];
    const errors = [];
    let rowCount = 0;
    
    // Parse CSV
    const parsePromise = new Promise((resolve, reject) => {
      fs.createReadStream(filePath)
        .pipe(csv())
        .on('data', (row) => {
          try {
            rowCount++;
            
            // Map based on format
            let flowLog;
            if (format === 'cicids') {
              flowLog = mapCICIDSToFlowLog(row);
            } else {
              flowLog = mapGenericCSVToFlowLog(row);
            }
            
            flowLogs.push(flowLog);
            
            // Batch insert every 1000 rows to avoid memory issues
            if (flowLogs.length >= 1000) {
              FlowLog.insertMany(flowLogs.splice(0, 1000))
                .catch(err => errors.push(err.message));
            }
            
          } catch (err) {
            errors.push(`Row ${rowCount}: ${err.message}`);
          }
        })
        .on('end', () => {
          resolve();
        })
        .on('error', (err) => {
          reject(err);
        });
    });
    
    await parsePromise;
    
    // Insert remaining rows
    if (flowLogs.length > 0) {
      await FlowLog.insertMany(flowLogs);
    }
    
    // Clean up uploaded file
    fs.unlinkSync(filePath);
    
    // Get statistics
    const stats = {
      totalRows: rowCount,
      successfulImports: rowCount - errors.length,
      errors: errors.length,
      benignCount: await FlowLog.countDocuments({ actualLabel: 'BENIGN' }),
      malwareCount: await FlowLog.countDocuments({ actualLabel: 'MALWARE' })
    };
    
    res.json({
      success: true,
      message: `Successfully imported ${stats.successfulImports} flow logs`,
      stats,
      errors: errors.slice(0, 10) // Return first 10 errors
    });
    
  } catch (error) {
    console.error('CSV import error:', error);
    
    // Clean up file on error
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to import CSV',
      error: error.message
    });
  }
});

/**
 * GET /api/csv-import/template
 * Download CSV template
 */
router.get('/template/:format', (req, res) => {
  const { format } = req.params;
  
  let csvContent;
  
  if (format === 'cicids') {
    csvContent = 
      'Source IP,Destination IP,Source Port,Destination Port,Protocol,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets,Flow Duration,Label\n' +
      '192.168.1.100,8.8.8.8,54321,53,17,5,5,300,300,1000000,BENIGN\n' +
      '10.0.1.50,203.0.113.45,48912,4444,6,25,20,5000,3000,5000000,Bot\n';
  } else {
    csvContent = 
      'srcAddr,dstAddr,srcPort,dstPort,protocol,packets,bytes,duration,label\n' +
      '192.168.1.100,8.8.8.8,54321,53,17,10,600,1,BENIGN\n' +
      '10.0.1.50,203.0.113.45,48912,4444,6,45,8000,5,MALWARE\n';
  }
  
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${format}-template.csv"`);
  res.send(csvContent);
});

/**
 * GET /api/csv-import/stats
 * Get import statistics
 */
router.get('/stats', async (req, res) => {
  try {
    const totalImported = await FlowLog.countDocuments({ patternType: 'IMPORTED' });
    const recentImports = await FlowLog.find({ patternType: 'IMPORTED' })
      .sort({ timestamp: -1 })
      .limit(10)
      .select('flowId timestamp srcAddr dstAddr actualLabel');
    
    res.json({
      success: true,
      data: {
        totalImported,
        recentImports
      }
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to get import stats',
      error: error.message
    });
  }
});

module.exports = router;