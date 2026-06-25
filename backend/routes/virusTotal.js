// routes/virusTotal.js
// API routes for VirusTotal IP analysis

const express = require('express');
const router = express.Router();
const { getVirusTotalService } = require('../services/virusTotalService');

/**
 * GET /api/virustotal/ip/:ipAddress
 * Get VirusTotal report for an IP address
 */
router.get('/ip/:ipAddress', async (req, res) => {
  try {
    const { ipAddress } = req.params;
    
    // Validate IP address format
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ipAddress)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid IP address format'
      });
    }
    
    console.log(`📊 VirusTotal lookup: ${ipAddress}`);
    
    const vtService = getVirusTotalService();
    const report = await vtService.getIPReport(ipAddress);
    
    if (!report.success) {
      return res.status(500).json({
        success: false,
        message: report.error || 'Failed to fetch VirusTotal report'
      });
    }
    
    const formatted = vtService.formatReport(report);
    
    res.json({
      success: true,
      data: formatted
    });
    
  } catch (error) {
    console.error('VirusTotal API error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch VirusTotal data',
      error: error.message
    });
  }
});

/**
 * POST /api/virustotal/bulk
 * Get VirusTotal reports for multiple IPs
 */
router.post('/bulk', async (req, res) => {
  try {
    const { ipAddresses } = req.body;
    
    if (!Array.isArray(ipAddresses) || ipAddresses.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an array of IP addresses'
      });
    }
    
    if (ipAddresses.length > 10) {
      return res.status(400).json({
        success: false,
        message: 'Maximum 10 IP addresses allowed per request'
      });
    }
    
    console.log(`📊 VirusTotal bulk lookup: ${ipAddresses.length} IPs`);
    
    const vtService = getVirusTotalService();
    const results = [];
    
    for (const ip of ipAddresses) {
      const report = await vtService.getIPReport(ip);
      const formatted = vtService.formatReport(report);
      results.push({
        ip,
        ...formatted
      });
      
      // Rate limiting: wait 15 seconds between requests (free API limit)
      if (ipAddresses.indexOf(ip) < ipAddresses.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 15000));
      }
    }
    
    res.json({
      success: true,
      data: results
    });
    
  } catch (error) {
    console.error('VirusTotal bulk API error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch VirusTotal data',
      error: error.message
    });
  }
});

/**
 * GET /api/virustotal/status
 * Check VirusTotal API status
 */
router.get('/status', (req, res) => {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  
  res.json({
    success: true,
    configured: !!apiKey,
    message: apiKey 
      ? 'VirusTotal API is configured and ready'
      : 'VirusTotal API key not set. Add VIRUSTOTAL_API_KEY to environment variables.'
  });
});

module.exports = router;