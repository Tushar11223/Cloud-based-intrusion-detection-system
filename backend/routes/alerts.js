// routes/alerts.js
// API routes for security alert management

const express = require('express');
const router = express.Router();
const Alert = require('../models/Alert');

/**
 * GET /api/alerts
 * Retrieve alerts with pagination and filtering
 */
router.get('/', async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      severity,
      alertType,
      status,
      startDate,
      endDate
    } = req.query;
    
    // Build query
    const query = {};
    if (severity) query.severity = severity;
    if (alertType) query.alertType = alertType;
    if (status) query.status = status;
    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) query.timestamp.$gte = new Date(startDate);
      if (endDate) query.timestamp.$lte = new Date(endDate);
    }
    
    // Execute query with pagination
    const skip = (page - 1) * limit;
    const alerts = await Alert.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .skip(skip);
    
    const total = await Alert.countDocuments(query);
    
    res.json({
      success: true,
      data: alerts,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/alerts/:id
 * Retrieve a specific alert by ID
 */
router.get('/:id', async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.id)
      .populate('flowLogId');
    
    if (!alert) {
      return res.status(404).json({
        success: false,
        error: 'Alert not found'
      });
    }
    
    res.json({
      success: true,
      data: alert
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/alerts
 * Create new alert(s)
 */
router.post('/', async (req, res) => {
  try {
    const alerts = Array.isArray(req.body) ? req.body : [req.body];
    const created = await Alert.insertMany(alerts);
    
    res.status(201).json({
      success: true,
      data: created,
      count: created.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * PATCH /api/alerts/:id
 * Update alert status or add analyst notes
 */
router.patch('/:id', async (req, res) => {
  try {
    const { status, analystNotes } = req.body;
    
    const updateData = {};
    if (status) updateData.status = status;
    if (analystNotes !== undefined) updateData.analystNotes = analystNotes;
    if (status || analystNotes) updateData.analyzed = true;
    
    const alert = await Alert.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    );
    
    if (!alert) {
      return res.status(404).json({
        success: false,
        error: 'Alert not found'
      });
    }
    
    res.json({
      success: true,
      data: alert
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/alerts/stats/overview
 * Get statistical overview of alerts
 */
router.get('/stats/overview', async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    const start = startDate ? new Date(startDate) : new Date(Date.now() - 24*60*60*1000);
    const end = endDate ? new Date(endDate) : new Date();
    
    // Get statistics
    const stats = await Alert.getStatistics(start, end);
    const severityDist = await Alert.getSeverityDistribution(start, end);
    
    // Get total counts
    const totalAlerts = await Alert.countDocuments({
      timestamp: { $gte: start, $lte: end }
    });
    
    // Get status distribution
    const statusDistribution = await Alert.aggregate([
      {
        $match: {
          timestamp: { $gte: start, $lte: end }
        }
      },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);
    
    // Get detection method distribution
    const methodDistribution = await Alert.aggregate([
      {
        $match: {
          timestamp: { $gte: start, $lte: end }
        }
      },
      {
        $group: {
          _id: '$detectionMethod',
          count: { $sum: 1 }
        }
      }
    ]);
    
    // Get average risk score
    const avgRiskScore = await Alert.aggregate([
      {
        $match: {
          timestamp: { $gte: start, $lte: end }
        }
      },
      {
        $group: {
          _id: null,
          avgRisk: { $avg: '$riskScore' }
        }
      }
    ]);
    
    res.json({
      success: true,
      data: {
        timeRange: { start, end },
        totals: {
          alerts: totalAlerts,
          avgRiskScore: avgRiskScore[0]?.avgRisk || 0
        },
        severityDistribution: severityDist,
        statusDistribution: statusDistribution,
        methodDistribution: methodDistribution,
        detailedStats: stats
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/alerts/stats/timeline
 * Get time-series data for alerts
 */
router.get('/stats/timeline', async (req, res) => {
  try {
    const { startDate, endDate, interval = 'hour' } = req.query;
    
    const start = startDate ? new Date(startDate) : new Date(Date.now() - 24*60*60*1000);
    const end = endDate ? new Date(endDate) : new Date();
    
    // Determine grouping format based on interval
    const dateFormat = {
      hour: { $dateToString: { format: '%Y-%m-%d %H:00', date: '$timestamp' } },
      day: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } },
      minute: { $dateToString: { format: '%Y-%m-%d %H:%M', date: '$timestamp' } }
    };
    
    const timeline = await Alert.aggregate([
      {
        $match: {
          timestamp: { $gte: start, $lte: end }
        }
      },
      {
        $group: {
          _id: {
            time: dateFormat[interval] || dateFormat.hour,
            severity: '$severity'
          },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { '_id.time': 1 }
      }
    ]);
    
    res.json({
      success: true,
      data: timeline
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/alerts/recent
 * Get most recent alerts
 */
router.get('/recent/list', async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    
    const alerts = await Alert.find()
      .sort({ timestamp: -1 })
      .limit(parseInt(limit));
    
    res.json({
      success: true,
      data: alerts
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * DELETE /api/alerts
 * Delete all alerts (for testing/demo reset)
 */
router.delete('/', async (req, res) => {
  try {
    const result = await Alert.deleteMany({});
    
    res.json({
      success: true,
      message: 'All alerts deleted',
      deletedCount: result.deletedCount
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;