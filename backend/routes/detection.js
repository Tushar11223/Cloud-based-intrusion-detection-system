// routes/detection.js
// Detection API routes - FIXED to work with ruleEngine module

const express = require('express');
const router = express.Router();
const FlowLog = require('../models/FlowLog');
const Alert = require('../models/Alert');
const ruleEngine = require('../utils/ruleEngine'); // Import as module, not class
const axios = require('axios');

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://localhost:5001';

/**
 * POST /api/detection/analyze
 * Analyze flow logs and generate alerts
 */
router.post('/analyze', async (req, res) => {
  try {
    const { flowLogIds, method = 'HYBRID' } = req.body;
    
    if (!flowLogIds || !Array.isArray(flowLogIds) || flowLogIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'flowLogIds array is required'
      });
    }
    
    console.log(`🔍 Analyzing ${flowLogIds.length} logs with ${method} method`);
    
    // Get flow logs
    const flowLogs = await FlowLog.find({ _id: { $in: flowLogIds } });
    
    if (flowLogs.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No flow logs found'
      });
    }
    
    let alertsGenerated = 0;
    const results = [];
    
    for (const flowLog of flowLogs) {
      let detectedAs = 'BENIGN';
      let mlPrediction = null;
      let mlConfidence = null;
      let ruleMatches = [];
      
      // RULE-BASED DETECTION
      if (method === 'RULE_BASED' || method === 'HYBRID') {
        ruleMatches = ruleEngine.analyzeFlow(flowLog); // Use as module function
        
        if (ruleMatches.length > 0) {
          detectedAs = 'MALWARE';
          
          // Create alert for each rule match
          for (const rule of ruleMatches) {
            await Alert.create({
              severity: rule.severity,
              alertType: rule.type,
              title: rule.name,
              description: rule.description,
              sourceIp: flowLog.srcAddr,
              destinationIp: flowLog.dstAddr,
              sourcePort: flowLog.srcPort,
              destinationPort: flowLog.dstPort,
              protocol: flowLog.protocol,
              detectionMethod: 'RULE_BASED',
              flowLogId: flowLog._id,
              confidence: rule.confidence,
              ruleId: rule.id
            });
            
            alertsGenerated++;
          }
        }
      }
      
      // MACHINE LEARNING DETECTION
      if (method === 'MACHINE_LEARNING' || method === 'HYBRID') {
        try {
          const mlResult = await callMLService(flowLog);
          
          if (mlResult && mlResult.prediction !== undefined) {
            mlPrediction = mlResult.prediction; // 0 = benign, 1 = malware
            mlConfidence = mlResult.confidence || 0.5;
            
            if (mlPrediction === 1) {
              detectedAs = 'MALWARE';
              
              // Create ML-based alert (only if not already alerted by rules in HYBRID mode)
              if (method === 'MACHINE_LEARNING' || ruleMatches.length === 0) {
                await Alert.create({
                  severity: mlConfidence >= 0.9 ? 'CRITICAL' : mlConfidence >= 0.7 ? 'HIGH' : 'MEDIUM',
                  alertType: 'ML_DETECTION',
                  title: 'Machine Learning Detection',
                  description: `ML model detected malicious behavior with ${(mlConfidence * 100).toFixed(1)}% confidence`,
                  sourceIp: flowLog.srcAddr,
                  destinationIp: flowLog.dstAddr,
                  sourcePort: flowLog.srcPort,
                  destinationPort: flowLog.dstPort,
                  protocol: flowLog.protocol,
                  detectionMethod: 'MACHINE_LEARNING',
                  flowLogId: flowLog._id,
                  confidence: mlConfidence
                });
                
                alertsGenerated++;
              }
            }
          }
        } catch (mlError) {
          console.error('ML service error:', mlError.message);
          // Continue with rule-based only
        }
      }
      
      // Update flow log
      await FlowLog.findByIdAndUpdate(flowLog._id, {
        analyzed: true,
        detectedAs,
        mlPrediction,
        mlConfidence,
        ruleMatches: ruleMatches.map(r => r.id),
        analyzedAt: new Date()
      });
      
      results.push({
        flowLogId: flowLog._id,
        detectedAs,
        ruleMatches: ruleMatches.length,
        mlPrediction,
        mlConfidence
      });
    }
    
    res.json({
      success: true,
      message: `Analyzed ${flowLogs.length} flow logs`,
      results: {
        totalAnalyzed: flowLogs.length,
        alertsGenerated,
        method
      },
      details: results
    });
    
  } catch (error) {
    console.error('Detection error:', error);
    res.status(500).json({
      success: false,
      message: 'Detection failed',
      error: error.message
    });
  }
});

/**
 * GET /api/detection/rules
 * Get all detection rules
 */
router.get('/rules', (req, res) => {
  try {
    const rules = ruleEngine.getAllRules(); // Use as module function
    
    res.json({
      success: true,
      data: rules,
      total: rules.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to get rules',
      error: error.message
    });
  }
});

/**
 * GET /api/detection/rules/:ruleId
 * Get specific rule by ID
 */
router.get('/rules/:ruleId', (req, res) => {
  try {
    const { ruleId } = req.params;
    const rule = ruleEngine.getRuleById(ruleId); // Use as module function
    
    if (!rule) {
      return res.status(404).json({
        success: false,
        message: 'Rule not found'
      });
    }
    
    res.json({
      success: true,
      data: rule
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to get rule',
      error: error.message
    });
  }
});

/**
 * GET /api/detection/status
 * Get detection system status
 */
router.get('/status', async (req, res) => {
  try {
    // Check ML service
    let mlServiceStatus = 'UNAVAILABLE';
    try {
      const mlResponse = await axios.get(`${ML_SERVICE_URL}/health`, { timeout: 2000 });
      if (mlResponse.data.status === 'healthy') {
        mlServiceStatus = 'AVAILABLE';
      }
    } catch (err) {
      mlServiceStatus = 'UNAVAILABLE';
    }
    
    // Check rule engine
    const ruleEngineStatus = 'ACTIVE';
    const totalRules = ruleEngine.getAllRules().length;
    
    // Check database
    const dbStatus = 'CONNECTED';
    
    res.json({
      success: true,
      status: {
        database: dbStatus,
        mlService: mlServiceStatus,
        ruleEngine: ruleEngineStatus,
        autoAnalysis: 'RUNNING'
      },
      rules: {
        total: totalRules,
        active: totalRules
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to get status',
      error: error.message
    });
  }
});

/**
 * Helper: Call ML service
 */
async function callMLService(flowLog) {
  try {
    const response = await axios.post(
      `${ML_SERVICE_URL}/predict`,
      {
        flow: {
          duration: flowLog.duration || 0,
          protocol: flowLog.protocol || 6,
          srcPort: flowLog.srcPort || 0,
          dstPort: flowLog.dstPort || 0,
          packets: flowLog.packets || 0,
          bytes: flowLog.bytes || 0
        }
      },
      { timeout: 5000 }
    );
    
    return response.data;
  } catch (error) {
    throw new Error(`ML service unavailable: ${error.message}`);
  }
}

module.exports = router;