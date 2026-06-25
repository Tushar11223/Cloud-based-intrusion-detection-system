
const express = require('express');
const router = express.Router();
const { getAutoAnalysisService } = require('../services/autoAnalysisService');

/**
 * GET /api/auto-analysis/status
 * Get current auto-analysis status and settings
 */
router.get('/status', (req, res) => {
  try {
    const service = getAutoAnalysisService();
    const settings = service.getSettings();
    
    res.json({
      success: true,
      data: settings
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to get auto-analysis status',
      error: error.message
    });
  }
});

/**
 * POST /api/auto-analysis/start
 * Start auto-analysis service
 */
router.post('/start', (req, res) => {
  try {
    const service = getAutoAnalysisService();
    service.start();
    
    res.json({
      success: true,
      message: 'Auto-analysis service started',
      data: service.getSettings()
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to start auto-analysis',
      error: error.message
    });
  }
});

/**
 * POST /api/auto-analysis/stop
 * Stop auto-analysis service
 */
router.post('/stop', (req, res) => {
  try {
    const service = getAutoAnalysisService();
    service.stop();
    
    res.json({
      success: true,
      message: 'Auto-analysis service stopped',
      data: service.getSettings()
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to stop auto-analysis',
      error: error.message
    });
  }
});

/**
 * POST /api/auto-analysis/set-method
 * Change analysis method (HYBRID, RULE_BASED, MACHINE_LEARNING)
 */
router.post('/set-method', (req, res) => {
  try {
    const { method } = req.body;
    
    if (!method) {
      return res.status(400).json({
        success: false,
        message: 'Method is required (HYBRID, RULE_BASED, or MACHINE_LEARNING)'
      });
    }
    
    const service = getAutoAnalysisService();
    const success = service.setMethod(method);
    
    if (!success) {
      return res.status(400).json({
        success: false,
        message: 'Invalid method. Use HYBRID, RULE_BASED, or MACHINE_LEARNING'
      });
    }
    
    res.json({
      success: true,
      message: `Analysis method changed to ${method}`,
      data: service.getSettings()
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to set analysis method',
      error: error.message
    });
  }
});

/**
 * POST /api/auto-analysis/analyze-now
 * Trigger immediate analysis check (doesn't wait for interval)
 */
router.post('/analyze-now', async (req, res) => {
  try {
    const service = getAutoAnalysisService();
    
    if (!service.isRunning) {
      return res.status(400).json({
        success: false,
        message: 'Auto-analysis service is not running. Start it first.'
      });
    }
    
    // Trigger immediate check
    await service.checkAndAnalyze();
    
    res.json({
      success: true,
      message: 'Immediate analysis triggered'
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to trigger analysis',
      error: error.message
    });
  }
});

module.exports = router;