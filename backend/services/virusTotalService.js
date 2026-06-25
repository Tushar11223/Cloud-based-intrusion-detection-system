// services/virusTotalService.js
// VirusTotal API Integration for IP Analysis

const axios = require('axios');

class VirusTotalService {
  constructor(apiKey) {
    this.apiKey = apiKey || process.env.VIRUSTOTAL_API_KEY;
    this.baseURL = 'https://www.virustotal.com/api/v3';
    
    if (!this.apiKey) {
      console.warn('⚠️  VirusTotal API key not set. Set VIRUSTOTAL_API_KEY environment variable.');
    }
  }
  
  /**
   * Get IP address report from VirusTotal
   */
  async getIPReport(ipAddress) {
    if (!this.apiKey) {
      return {
        success: false,
        error: 'VirusTotal API key not configured'
      };
    }
    
    try {
      console.log(`🔍 Querying VirusTotal for IP: ${ipAddress}`);
      
      const response = await axios.get(
        `${this.baseURL}/ip_addresses/${ipAddress}`,
        {
          headers: {
            'x-apikey': this.apiKey
          }
        }
      );
      
      const data = response.data.data;
      const attributes = data.attributes;
      
      // Extract useful information
      const report = {
        success: true,
        ip: ipAddress,
        reputation: attributes.reputation || 0,
        malicious: attributes.last_analysis_stats?.malicious || 0,
        suspicious: attributes.last_analysis_stats?.suspicious || 0,
        harmless: attributes.last_analysis_stats?.harmless || 0,
        undetected: attributes.last_analysis_stats?.undetected || 0,
        total_votes: {
          harmless: attributes.total_votes?.harmless || 0,
          malicious: attributes.total_votes?.malicious || 0
        },
        country: attributes.country || 'Unknown',
        as_owner: attributes.as_owner || 'Unknown',
        network: attributes.network || 'Unknown',
        regional_internet_registry: attributes.regional_internet_registry || 'Unknown',
        whois: attributes.whois || 'Not available',
        whois_date: attributes.whois_date || null,
        last_analysis_date: attributes.last_analysis_date || null,
        
        // Threat classification
        is_malicious: (attributes.last_analysis_stats?.malicious || 0) > 0,
        is_suspicious: (attributes.last_analysis_stats?.suspicious || 0) > 0,
        
        // Detailed analysis results
        analysis_results: this.parseAnalysisResults(attributes.last_analysis_results),
        
        // Tags and categories
        tags: attributes.tags || [],
        
        // Link to full report
        virustotal_url: `https://www.virustotal.com/gui/ip-address/${ipAddress}`
      };
      
      return report;
      
    } catch (error) {
      console.error('VirusTotal API error:', error.message);
      
      if (error.response) {
        if (error.response.status === 404) {
          return {
            success: true,
            ip: ipAddress,
            message: 'IP not found in VirusTotal database',
            is_malicious: false,
            is_suspicious: false
          };
        } else if (error.response.status === 429) {
          return {
            success: false,
            error: 'VirusTotal API rate limit exceeded. Please try again later.'
          };
        }
      }
      
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  /**
   * Parse analysis results from security vendors
   */
  parseAnalysisResults(results) {
    if (!results) return [];
    
    const parsed = [];
    
    for (const [vendor, result] of Object.entries(results)) {
      if (result.category === 'malicious' || result.category === 'suspicious') {
        parsed.push({
          vendor: vendor,
          category: result.category,
          result: result.result,
          method: result.method
        });
      }
    }
    
    return parsed.slice(0, 10); // Return top 10 detections
  }
  
  /**
   * Get threat assessment summary
   */
  getThreatLevel(report) {
    if (!report.success) return 'UNKNOWN';
    
    const malicious = report.malicious || 0;
    const suspicious = report.suspicious || 0;
    
    if (malicious >= 5) return 'CRITICAL';
    if (malicious >= 2) return 'HIGH';
    if (malicious >= 1 || suspicious >= 5) return 'MEDIUM';
    if (suspicious >= 1) return 'LOW';
    
    return 'SAFE';
  }
  
  /**
   * Format report for display
   */
  formatReport(report) {
    if (!report.success) {
      return {
        error: report.error,
        message: 'Failed to fetch VirusTotal report'
      };
    }
    
    const threatLevel = this.getThreatLevel(report);
    
    return {
      ip: report.ip,
      threatLevel,
      summary: {
        malicious: report.malicious,
        suspicious: report.suspicious,
        harmless: report.harmless,
        undetected: report.undetected
      },
      location: {
        country: report.country,
        asn: report.as_owner,
        network: report.network
      },
      reputation: report.reputation,
      tags: report.tags,
      detections: report.analysis_results,
      virustotalUrl: report.virustotal_url,
      lastAnalysis: report.last_analysis_date ? new Date(report.last_analysis_date * 1000).toISOString() : null
    };
  }
}

// Singleton instance
let virusTotalService = null;

function getVirusTotalService() {
  if (!virusTotalService) {
    virusTotalService = new VirusTotalService(process.env.VIRUSTOTAL_API_KEY);
  }
  return virusTotalService;
}

module.exports = { VirusTotalService, getVirusTotalService };