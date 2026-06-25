
const FlowLog = require('../models/FlowLog');
const Alert = require('../models/Alert');
const ruleEngine = require('../utils/ruleEngine');
const axios = require('axios');

class AutoAnalysisService {
  constructor() {
    this.isRunning = false;
    this.checkInterval = 10000; // Check every 10 seconds
    this.timer = null;
    this.analysisMethod = 'HYBRID'; // Default method
    this.mlServiceUrl = process.env.ML_SERVICE_URL || 'http://localhost:5001';
    this.batchSize = 50; // Analyze 50 logs at a time
  }
  
  /**
   * Start auto-analysis service
   */
  start() {
    if (this.isRunning) {
      console.log('⚠️  Auto-analysis already running');
      return;
    }
    
    this.isRunning = true;
    console.log('🤖 Auto-analysis service started');
    console.log(`   Method: ${this.analysisMethod}`);
    console.log(`   Check interval: ${this.checkInterval / 1000}s`);
    console.log(`   Batch size: ${this.batchSize}`);
    
    // Start monitoring
    this.timer = setInterval(() => {
      this.checkAndAnalyze();
    }, this.checkInterval);
    
    // Run first check immediately
    this.checkAndAnalyze();
  }
  
  /**
   * Stop auto-analysis service
   */
  stop() {
    if (!this.isRunning) {
      console.log('⚠️  Auto-analysis not running');
      return;
    }
    
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    
    this.isRunning = false;
    console.log('🛑 Auto-analysis service stopped');
  }
  
  /**
   * Set analysis method (called from dashboard)
   */
  setMethod(method) {
    const validMethods = ['HYBRID', 'RULE_BASED', 'MACHINE_LEARNING'];
    
    if (!validMethods.includes(method)) {
      console.error(`❌ Invalid method: ${method}`);
      return false;
    }
    
    this.analysisMethod = method;
    console.log(`✓ Analysis method changed to: ${method}`);
    return true;
  }
  
  /**
   * Get current settings
   */
  getSettings() {
    return {
      isRunning: this.isRunning,
      analysisMethod: this.analysisMethod,
      checkInterval: this.checkInterval,
      batchSize: this.batchSize
    };
  }
  
  /**
   * Check for pending logs and analyze them
   */
  async checkAndAnalyze() {
    try {
      // Get pending logs
      const pendingLogs = await FlowLog.find({ analyzed: false })
        .limit(this.batchSize)
        .lean();
      
      if (pendingLogs.length === 0) {
        // No logs to analyze
        return;
      }
      
      console.log(`📊 Analyzing ${pendingLogs.length} pending logs (${this.analysisMethod})`);
      
      // Analyze based on selected method
      const results = await this.analyzeLogs(pendingLogs);
      
      console.log(`✓ Analysis complete: ${results.alertsGenerated} alerts generated`);
      
    } catch (error) {
      console.error('❌ Auto-analysis error:', error.message);
    }
  }
  
  /**
   * Analyze logs using selected method
   */
  async analyzeLogs(flowLogs) {
    let totalAlerts = 0;
    
    for (const flowLog of flowLogs) {
      let detectedAs = 'BENIGN';
      let mlPrediction = null;
      let mlConfidence = null;
      let ruleMatches = [];
      let alerts = [];
      
      // RULE-BASED DETECTION
      if (this.analysisMethod === 'RULE_BASED' || this.analysisMethod === 'HYBRID') {
        ruleMatches = ruleEngine.analyzeFlow(flowLog);
        
        if (ruleMatches.length > 0) {
          detectedAs = 'MALWARE';
          
          // Create alerts for each rule match
          for (const rule of ruleMatches) {
            const alert = await Alert.create({
              flowLogId: flowLog._id,
              timestamp: new Date(),
              alertType: rule.type,
              severity: rule.severity,
              title: rule.name,
              description: rule.description,
              sourceIp: flowLog.srcAddr,
              destinationIp: flowLog.dstAddr,
              sourcePort: flowLog.srcPort,
              destinationPort: flowLog.dstPort,
              protocol: flowLog.protocol,
              detectionMethod: 'RULE_BASED',
              ruleId: rule.id,
              confidence: rule.confidence || 0.9
            });
            
            alerts.push(alert);
            totalAlerts++;
          }
        }
      }
      
      // MACHINE LEARNING DETECTION
      if (this.analysisMethod === 'MACHINE_LEARNING' || this.analysisMethod === 'HYBRID') {
        try {
          const mlResult = await this.callMLService(flowLog);
          
          if (mlResult && mlResult.prediction !== undefined) {
            mlPrediction = mlResult.prediction; // 0 = benign, 1 = malware
            mlConfidence = mlResult.confidence || 0.5;
            
            // If ML detects malware
            if (mlPrediction === 1) {
              detectedAs = 'MALWARE';
              
              // Create ML-based alert (only if not already alerted by rules)
              if (this.analysisMethod === 'MACHINE_LEARNING' || ruleMatches.length === 0) {
                const alert = await Alert.create({
                  flowLogId: flowLog._id,
                  timestamp: new Date(),
                  alertType: 'ML_DETECTION',
                  severity: mlConfidence >= 0.9 ? 'CRITICAL' : mlConfidence >= 0.7 ? 'HIGH' : 'MEDIUM',
                  title: 'Machine Learning Detection',
                  description: `ML model detected malicious behavior with ${(mlConfidence * 100).toFixed(1)}% confidence`,
                  sourceIp: flowLog.srcAddr,
                  destinationIp: flowLog.dstAddr,
                  sourcePort: flowLog.srcPort,
                  destinationPort: flowLog.dstPort,
                  protocol: flowLog.protocol,
                  detectionMethod: 'MACHINE_LEARNING',
                  confidence: mlConfidence
                });
                
                alerts.push(alert);
                totalAlerts++;
              }
            }
          }
        } catch (mlError) {
          console.error('ML service error:', mlError.message);
          // Continue with rule-based only if ML fails
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
    }
    
    return {
      totalFlows: flowLogs.length,
      alertsGenerated: totalAlerts
    };
  }
  
  /**
   * Call ML service for prediction
   */
  async callMLService(flowLog) {
    try {
      const response = await axios.post(`${this.mlServiceUrl}/predict`, {
        flow: {
          duration: flowLog.duration || 0,
          protocol: flowLog.protocol || 6,
          srcPort: flowLog.srcPort || 0,
          dstPort: flowLog.dstPort || 0,
          packets: flowLog.packets || 0,
          bytes: flowLog.bytes || 0
        }
      }, {
        timeout: 5000
      });
      
      return response.data;
      
    } catch (error) {
      throw new Error(`ML service unavailable: ${error.message}`);
    }
  }
}

// Singleton instance
let autoAnalysisService = null;

function getAutoAnalysisService() {
  if (!autoAnalysisService) {
    autoAnalysisService = new AutoAnalysisService();
  }
  return autoAnalysisService;
}

module.exports = { AutoAnalysisService, getAutoAnalysisService };