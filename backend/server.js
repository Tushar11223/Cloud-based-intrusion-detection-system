// server.js - UPDATED with auto-analysis
// Add this to your existing server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/malware_detection';

mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('✓ MongoDB connected successfully');
    
    // START AUTO-ANALYSIS SERVICE AFTER DB CONNECTION
    const { getAutoAnalysisService } = require('./services/autoAnalysisService');
    const autoAnalysis = getAutoAnalysisService();
    autoAnalysis.start();
    
  })
  .catch(err => {
    console.error('✗ MongoDB connection failed:', err.message);
    process.exit(1);
  });

// Routes
const flowLogsRoutes = require('./routes/flowLogs');
const alertsRoutes = require('./routes/alerts');
const detectionRoutes = require('./routes/detection');
const autoAnalysisRoutes = require('./routes/autoAnalysis'); // NEW
const virusTotalRoutes = require('./routes/virusTotal'); // NEW (if you added VirusTotal)

app.use('/api/flow-logs', flowLogsRoutes);
app.use('/api/alerts', alertsRoutes);
app.use('/api/detection', detectionRoutes);
app.use('/api/auto-analysis', autoAnalysisRoutes); // NEW
app.use('/api/virustotal', virusTotalRoutes); // NEW (if you added VirusTotal)

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log('╔═══════════════════════════════════════════════════════╗');
  console.log('║  Cloud-Based Malware Detection System - Backend      ║');
  console.log('╚═══════════════════════════════════════════════════════╝');
  console.log(`✓ Server running on port ${PORT}`);
  console.log(`✓ Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`✓ API endpoint: http://localhost:${PORT}`);
  console.log(`✓ ML Service URL: ${process.env.ML_SERVICE_URL || 'http://localhost:5001'}`);
  console.log('Available endpoints:');
  console.log(`  - GET  http://localhost:${PORT}/health`);
  console.log(`  - GET  http://localhost:${PORT}/api/flow-logs`);
  console.log(`  - GET  http://localhost:${PORT}/api/alerts`);
  console.log(`  - GET  http://localhost:${PORT}/api/auto-analysis/status`);
  console.log(`  - POST http://localhost:${PORT}/api/auto-analysis/set-method`);
  console.log('Press Ctrl+C to stop the server');
  console.log('═══════════════════════════════════════════════════════');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down gracefully...');
  
  // Stop auto-analysis
  const { getAutoAnalysisService } = require('./services/autoAnalysisService');
  const autoAnalysis = getAutoAnalysisService();
  autoAnalysis.stop();
  
  // Close MongoDB
  mongoose.connection.close(() => {
    console.log('✓ MongoDB connection closed');
    process.exit(0);
  });
});