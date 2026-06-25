// routes/flowLogs.js - DATASET ONLY VERSION
// Removed synthetic log generation - uses real datasets only

const express = require('express');
const router = express.Router();
const FlowLog = require('../models/FlowLog');

/**
 * GET /api/flow-logs
 * Get flow logs with filtering
 */
router.get('/', async (req, res) => {
  try {
    const { 
      limit = 100, 
      skip = 0, 
      label, 
      analyzed,
      source
    } = req.query;
    
    // Build query
    let query = {};
    
    if (label) {
      query.actualLabel = label;
    }
    
    if (analyzed !== undefined) {
      query.analyzed = analyzed === 'true';
    }
    
    if (source) {
      query.source = source;
    }
    
    const flowLogs = await FlowLog.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(skip));
    
    const total = await FlowLog.countDocuments(query);
    
    res.json({
      success: true,
      data: flowLogs,
      pagination: {
        total,
        limit: parseInt(limit),
        skip: parseInt(skip),
        hasMore: total > (parseInt(skip) + parseInt(limit))
      }
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch flow logs',
      error: error.message
    });
  }
});

/**
 * GET /api/flow-logs/:id
 * Get single flow log by ID
 */
router.get('/:id', async (req, res) => {
  try {
    const flowLog = await FlowLog.findById(req.params.id);
    
    if (!flowLog) {
      return res.status(404).json({
        success: false,
        message: 'Flow log not found'
      });
    }
    
    res.json({
      success: true,
      data: flowLog
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch flow log',
      error: error.message
    });
  }
});

/**
 * POST /api/flow-logs/import-csv
 * Import flow logs from uploaded CSV file (CIC-IDS format)
 */
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');
const path = require('path');

// Configure file upload
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
  fileFilter: (req, file, cb) => {
    if (path.extname(file.originalname).toLowerCase() !== '.csv') {
      return cb(new Error('Only CSV files allowed'));
    }
    cb(null, true);
  }
});

router.post('/import-csv', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }
    
    const filePath = req.file.path;
    const flowLogs = [];
    let rowCount = 0;
    
    console.log(`Importing CSV: ${req.file.originalname}`);
    
    // Parse CSV
    await new Promise((resolve, reject) => {
      fs.createReadStream(filePath)
        .pipe(csv())
        .on('data', (row) => {
          rowCount++;
          
          // Map CIC-IDS columns to FlowLog schema
          const flowLog = {
            flowId: `cicids-${Date.now()}-${rowCount}`,
            timestamp: new Date(),
            srcAddr: row['Source IP'] || row['Src IP'] || '0.0.0.0',
            dstAddr: row['Destination IP'] || row['Dst IP'] || '0.0.0.0',
            srcPort: parseInt(row['Source Port'] || row['Src Port'] || 0),
            dstPort: parseInt(row['Destination Port'] || row['Dst Port'] || 0),
            protocol: parseInt(row['Protocol'] || 6),
            packets: parseInt(
              parseFloat(row['Total Fwd Packets'] || row['Total Fwd Packet'] || 0) + 
              parseFloat(row['Total Backward Packets'] || row['Total Backward Packet'] || 0)
            ),
            bytes: parseInt(
              parseFloat(row['Total Length of Fwd Packets'] || row['Total Length of Fwd Packet'] || 0) + 
              parseFloat(row['Total Length of Bwd Packets'] || row['Total Length of Bwd Packet'] || 0)
            ),
            duration: parseFloat(row['Flow Duration'] || 0) / 1000000,
            action: 'ACCEPT',
            tcpFlags: extractTcpFlags(row),
            actualLabel: (row['Label'] || row[' Label'] || '').trim() === 'BENIGN' ? 'BENIGN' : 'MALWARE',
            patternType: mapAttackType(row['Label'] || row[' Label'] || 'UNKNOWN'),
            analyzed: false,
            detectedAs: 'PENDING',
            source: 'CIC-IDS-2017'
          };
          
          flowLogs.push(flowLog);
          
          // Batch insert every 1000 rows
          if (flowLogs.length >= 1000) {
            FlowLog.insertMany(flowLogs.splice(0, 1000)).catch(err => {
              console.error('Batch insert error:', err);
            });
          }
        })
        .on('end', () => resolve())
        .on('error', (err) => reject(err));
    });
    
    // Insert remaining rows
    if (flowLogs.length > 0) {
      await FlowLog.insertMany(flowLogs);
    }
    
    // Clean up uploaded file
    fs.unlinkSync(filePath);
    
    const benignCount = await FlowLog.countDocuments({ 
      source: 'CIC-IDS-2017', 
      actualLabel: 'BENIGN' 
    });
    const malwareCount = await FlowLog.countDocuments({ 
      source: 'CIC-IDS-2017', 
      actualLabel: 'MALWARE' 
    });
    
    res.json({
      success: true,
      message: `Successfully imported ${rowCount} flow logs from dataset`,
      data: {
        totalImported: rowCount,
        benignCount,
        malwareCount,
        source: 'CIC-IDS-2017'
      }
    });
    
  } catch (error) {
    console.error('CSV import error:', error);
    
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

// Helper functions
function extractTcpFlags(row) {
  const flags = [];
  if (parseInt(row['SYN Flag Count'] || 0) > 0) flags.push('SYN');
  if (parseInt(row['FIN Flag Count'] || 0) > 0) flags.push('FIN');
  if (parseInt(row['RST Flag Count'] || 0) > 0) flags.push('RST');
  if (parseInt(row['PSH Flag Count'] || 0) > 0) flags.push('PSH');
  if (parseInt(row['ACK Flag Count'] || 0) > 0) flags.push('ACK');
  if (parseInt(row['URG Flag Count'] || 0) > 0) flags.push('URG');
  return flags.join(',');
}

function mapAttackType(label) {
  label = String(label).trim();
  
  if (label === 'BENIGN') return 'BENIGN';
  if (label.includes('PortScan')) return 'PORT_SCAN';
  if (label.includes('Bot')) return 'C2_BEACONING';
  if (label.includes('Infiltration')) return 'DATA_EXFILTRATION';
  if (label.includes('DoS') || label.includes('DDoS')) return 'DOS_ATTACK';
  if (label.includes('Brute Force') || label.includes('Patator')) return 'BRUTE_FORCE';
  if (label.includes('Web Attack')) return 'WEB_ATTACK';
  
  return 'MALWARE';
}

/**
 * GET /api/flow-logs/stats/overview
 * Get dataset statistics
 */
router.get('/stats/overview', async (req, res) => {
  try {
    const { startDate, endDate, source } = req.query;
    
    let dateFilter = {};
    if (startDate || endDate) {
      dateFilter.timestamp = {};
      if (startDate) dateFilter.timestamp.$gte = new Date(startDate);
      if (endDate) dateFilter.timestamp.$lte = new Date(endDate);
    }
    
    let baseQuery = { ...dateFilter };
    if (source) {
      baseQuery.source = source;
    }
    
    // Total counts
    const totalLogs = await FlowLog.countDocuments(baseQuery);
    const benignLogs = await FlowLog.countDocuments({ ...baseQuery, actualLabel: 'BENIGN' });
    const malwareLogs = await FlowLog.countDocuments({ ...baseQuery, actualLabel: 'MALWARE' });
    
    // Analyzed counts
    const analyzedLogs = await FlowLog.countDocuments({ ...baseQuery, analyzed: true });
    const pendingLogs = await FlowLog.countDocuments({ ...baseQuery, analyzed: false });
    
    // Source distribution
    const sourceDistribution = await FlowLog.aggregate([
      { $match: dateFilter },
      { $group: { _id: '$source', count: { $sum: 1 } } }
    ]);
    
    // Pattern distribution
    const patternDistribution = await FlowLog.aggregate([
      { $match: baseQuery },
      { $group: { _id: '$patternType', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    res.json({
      success: true,
      data: {
        totals: {
          logs: totalLogs,
          benign: benignLogs,
          malware: malwareLogs,
          analyzed: analyzedLogs,
          pending: pendingLogs
        },
        sourceDistribution,
        patternDistribution,
        detectionRate: totalLogs > 0 ? (malwareLogs / totalLogs * 100).toFixed(2) : 0,
        analysisProgress: totalLogs > 0 ? (analyzedLogs / totalLogs * 100).toFixed(2) : 0
      }
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to get statistics',
      error: error.message
    });
  }
});

/**
 * GET /api/flow-logs/stats/timeline
 * Get timeline data for charts
 */
router.get('/stats/timeline', async (req, res) => {
  try {
    const { startDate, endDate, interval = 'hour' } = req.query;
    
    let dateFilter = {};
    if (startDate || endDate) {
      dateFilter.timestamp = {};
      if (startDate) dateFilter.timestamp.$gte = new Date(startDate);
      if (endDate) dateFilter.timestamp.$lte = new Date(endDate);
    }
    
    // Group by time interval
    const timeFormat = interval === 'hour' ? '%Y-%m-%d %H:00' : '%Y-%m-%d';
    
    const timeline = await FlowLog.aggregate([
      { $match: dateFilter },
      {
        $group: {
          _id: {
            time: { $dateToString: { format: timeFormat, date: '$timestamp' } },
            label: '$actualLabel'
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id.time': 1 } }
    ]);
    
    res.json({
      success: true,
      data: timeline
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to get timeline',
      error: error.message
    });
  }
});

/**
 * DELETE /api/flow-logs
 * Delete flow logs
 */
router.delete('/', async (req, res) => {
  try {
    const { source } = req.query;
    
    let query = {};
    if (source) {
      query.source = source;
    }
    
    const result = await FlowLog.deleteMany(query);
    
    res.json({
      success: true,
      message: source 
        ? `Deleted ${result.deletedCount} ${source} flow logs`
        : `Deleted ${result.deletedCount} flow logs`,
      deletedCount: result.deletedCount
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to delete flow logs',
      error: error.message
    });
  }
});

module.exports = router;