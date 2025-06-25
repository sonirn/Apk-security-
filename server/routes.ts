import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertApkAnalysisSchema, type Vulnerability, type AnalysisResult, type SecurityCheck } from "@shared/schema";
import { z } from "zod";
import multer from "multer";
import path from "path";
import fs from "fs";
import { APKAnalyzer } from "./apk-analyzer";

// Configure multer for APK file uploads
const upload = multer({
  dest: 'uploads/',
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/vnd.android.package-archive' || 
        file.originalname.endsWith('.apk')) {
      cb(null, true);
    } else {
      cb(new Error('Only APK files are allowed'));
    }
  }
});

async function performRealAnalysis(apkPath: string): Promise<{
  packageName: string;
  version: string;
  targetSdk: number;
  permissions: string[];
  securityScore: number;
  criticalIssues: number;
  warningIssues: number;
  vulnerabilities: Vulnerability[];
  analysisResults: AnalysisResult;
  fixedApkPath?: string;
}> {
  try {
    const analyzer = new APKAnalyzer(apkPath);
    const results = await analyzer.analyzeAPK();
    
    // Calculate security score based on vulnerabilities
    const criticalCount = results.vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = results.vulnerabilities.filter(v => v.severity === 'high').length;
    const mediumCount = results.vulnerabilities.filter(v => v.severity === 'medium').length;
    const lowCount = results.vulnerabilities.filter(v => v.severity === 'low').length;
    
    const securityScore = Math.max(0, 100 - (criticalCount * 20) - (highCount * 15) - (mediumCount * 10) - (lowCount * 5));
    
    return {
      packageName: results.packageInfo?.manifest?.application?.[0]?.$.package || "com.unknown.app",
      version: results.packageInfo?.manifest?.application?.[0]?.$.versionName || "1.0.0",
      targetSdk: parseInt(results.packageInfo?.manifest?.application?.[0]?.$.targetSdkVersion) || 30,
      permissions: results.packageInfo?.manifest?.["uses-permission"]?.map((p: any) => p.$.name) || [],
      securityScore,
      criticalIssues: criticalCount + highCount,
      warningIssues: mediumCount + lowCount,
      vulnerabilities: results.vulnerabilities,
      analysisResults: results.analysisResults,
      fixedApkPath: results.fixedApkPath
    };
  } catch (error) {
    console.error('Analysis failed:', error);
    throw new Error('Failed to analyze APK file');
  }
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Initialize default security categories on startup
  try {
    await storage.initializeDefaultCategories();
  } catch (error) {
    console.error('Failed to initialize default categories:', error);
  }

  // Get all APK analyses
  app.get("/api/analyses", async (req, res) => {
    try {
      const analyses = await storage.getAllApkAnalyses();
      res.json(analyses);
    } catch (error) {
      console.error('Database error:', error);
      res.status(500).json({ message: "Failed to fetch analyses" });
    }
  });

  // Get specific APK analysis
  app.get("/api/analyses/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid analysis ID" });
      }
      
      const analysis = await storage.getApkAnalysis(id);
      
      if (!analysis) {
        return res.status(404).json({ message: "Analysis not found" });
      }
      
      res.json(analysis);
    } catch (error) {
      console.error('Database error:', error);
      res.status(500).json({ message: "Failed to fetch analysis" });
    }
  });

  // Upload APK file and create analysis
  app.post("/api/upload", upload.single('apk'), async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No APK file uploaded" });
      }

      const analysis = await storage.createApkAnalysis({
        fileName: req.file.originalname,
        fileSize: req.file.size,
        analysisStatus: "analyzing",
        packageName: null,
        version: null,
        targetSdk: null,
        permissions: null,
        securityScore: null,
        criticalIssues: 0,
        warningIssues: 0,
        vulnerabilities: null,
        analysisResults: null,
      });

      // Perform real analysis processing
      setImmediate(async () => {
        try {
          const analysisResults = await performRealAnalysis(req.file!.path);
          
          await storage.updateApkAnalysis(analysis.id, {
            analysisStatus: "completed",
            packageName: analysisResults.packageName,
            version: analysisResults.version,
            targetSdk: analysisResults.targetSdk,
            permissions: analysisResults.permissions,
            securityScore: analysisResults.securityScore,
            criticalIssues: analysisResults.criticalIssues,
            warningIssues: analysisResults.warningIssues,
            vulnerabilities: analysisResults.vulnerabilities,
            analysisResults: analysisResults.analysisResults,
            fixedApkPath: analysisResults.fixedApkPath,
          });
        } catch (error) {
          console.error('Analysis failed:', error);
          try {
            await storage.updateApkAnalysis(analysis.id, {
              analysisStatus: "failed"
            });
          } catch (updateError) {
            console.error('Failed to update analysis status:', updateError);
          }
        } finally {
          // Clean up uploaded file after processing
          setTimeout(() => {
            if (fs.existsSync(req.file!.path)) {
              fs.unlink(req.file!.path, (err) => {
                if (err) console.error("Error deleting uploaded file:", err);
              });
            }
          }, 5000); // Delay to ensure analysis is complete
        }
      });

      // Note: File cleanup handled in finally block after analysis

      res.json(analysis);
    } catch (error) {
      console.error('Upload error:', error);
      res.status(500).json({ message: "Failed to upload and analyze APK" });
    }
  });

  // Get security categories
  app.get("/api/categories", async (req, res) => {
    try {
      const categories = await storage.getAllSecurityCategories();
      res.json(categories);
    } catch (error) {
      console.error('Database error:', error);
      res.status(500).json({ message: "Failed to fetch security categories" });
    }
  });

  // Download fixed APK
  app.get("/api/analyses/:id/download-fixed", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const analysis = await storage.getApkAnalysis(id);
      
      if (!analysis || !analysis.fixedApkPath) {
        return res.status(404).json({ message: "Fixed APK not found" });
      }
      
      if (!fs.existsSync(analysis.fixedApkPath)) {
        return res.status(404).json({ message: "Fixed APK file not found" });
      }
      
      res.download(analysis.fixedApkPath, `fixed_${analysis.fileName}`);
    } catch (error) {
      res.status(500).json({ message: "Failed to download fixed APK" });
    }
  });

  // Download detailed report
  app.get("/api/analyses/:id/download-report", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const analysis = await storage.getApkAnalysis(id);
      
      if (!analysis) {
        return res.status(404).json({ message: "Analysis not found" });
      }
      
      const detailedReport = {
        executiveSummary: {
          applicationName: analysis.fileName,
          packageName: analysis.packageName,
          version: analysis.version,
          analysisDate: analysis.uploadTime,
          overallRiskLevel: (analysis.criticalIssues || 0) > 0 ? "HIGH" : (analysis.warningIssues || 0) > 0 ? "MEDIUM" : "LOW",
          securityScore: analysis.securityScore,
          totalVulnerabilities: analysis.vulnerabilities?.length || 0,
          criticalFindings: analysis.criticalIssues || 0,
          riskFactors: analysis.vulnerabilities?.filter(v => v.severity === 'critical').map(v => v.title) || []
        },
        analysisMetadata: {
          id: analysis.id,
          fileName: analysis.fileName,
          fileSize: `${(analysis.fileSize / (1024 * 1024)).toFixed(2)} MB`,
          uploadTime: analysis.uploadTime,
          analysisStatus: analysis.analysisStatus,
          analysisEngine: "SecureAPK Analyzer v2.0",
          reportVersion: "1.0",
          generatedAt: new Date().toISOString(),
          analyst: "Automated Security Analysis Engine"
        },
        applicationProfile: {
          packageInformation: {
            packageName: analysis.packageName,
            versionName: analysis.version,
            versionCode: analysis.targetSdk,
            targetSdkVersion: analysis.targetSdk,
            minSdkVersion: "Unknown",
            compileSdkVersion: "Unknown"
          },
          permissions: {
            total: analysis.permissions?.length || 0,
            dangerous: analysis.permissions?.filter(p => 
              p.includes('WRITE_EXTERNAL_STORAGE') || 
              p.includes('READ_PHONE_STATE') || 
              p.includes('ACCESS_FINE_LOCATION') ||
              p.includes('CAMERA') ||
              p.includes('RECORD_AUDIO')
            ).length || 0,
            list: analysis.permissions || [],
            riskAssessment: (analysis.permissions?.length || 0) > 10 ? "High permission usage detected" : "Normal permission usage"
          },
          components: {
            activities: "Unknown",
            services: "Unknown", 
            receivers: "Unknown",
            providers: "Unknown"
          }
        },
        securityAssessment: {
          overallScore: analysis.securityScore,
          riskLevel: (analysis.criticalIssues || 0) > 0 ? "HIGH" : (analysis.warningIssues || 0) > 0 ? "MEDIUM" : "LOW",
          criticalIssues: analysis.criticalIssues || 0,
          warningIssues: analysis.warningIssues || 0,
          passedChecks: Object.values(analysis.analysisResults || {}).filter(r => r.status === 'passed').length,
          failedChecks: Object.values(analysis.analysisResults || {}).filter(r => r.status === 'critical' || r.status === 'failed').length
        },
        vulnerabilityFindings: {
          summary: {
            total: analysis.vulnerabilities?.length || 0,
            critical: analysis.vulnerabilities?.filter(v => v.severity === 'critical').length || 0,
            high: analysis.vulnerabilities?.filter(v => v.severity === 'high').length || 0,
            medium: analysis.vulnerabilities?.filter(v => v.severity === 'medium').length || 0,
            low: analysis.vulnerabilities?.filter(v => v.severity === 'low').length || 0
          },
          detailedFindings: analysis.vulnerabilities?.map(vuln => ({
            id: vuln.id,
            title: vuln.title,
            severity: vuln.severity,
            category: vuln.category,
            description: vuln.description,
            location: vuln.location,
            cvssScore: vuln.cvssScore,
            impact: getImpactDescription(vuln.severity),
            exploitability: getExploitabilityRating(vuln.severity),
            remediation: vuln.recommendation,
            references: getSecurityReferences(vuln.category)
          })) || []
        },
        categoryAnalysis: analysis.analysisResults || {},
        complianceCheck: {
          owasp: {
            mobile2024: getOWASPCompliance(analysis.vulnerabilities || []),
            apiSecurity: getAPISecurityCompliance(analysis.analysisResults?.apiTesting)
          },
          pci: {
            applicable: analysis.permissions?.includes('com.android.vending.BILLING') || false,
            status: "Requires manual review for payment processing"
          },
          gdpr: {
            dataCollection: analysis.permissions?.some(p => p.includes('READ_CONTACTS') || p.includes('LOCATION')) || false,
            privacyAssessment: "Manual privacy policy review required"
          }
        },
        remediationPlan: {
          immediate: getImmediateActions(analysis.vulnerabilities || []),
          shortTerm: [
            "Implement comprehensive input validation framework",
            "Enable security headers for all web communications",
            "Implement certificate pinning for API calls",
            "Add runtime application self-protection (RASP)"
          ],
          longTerm: [
            "Integrate security testing into CI/CD pipeline",
            "Implement threat modeling for new features",
            "Regular penetration testing and security audits",
            "Security awareness training for development team",
            "Establish incident response procedures"
          ],
          technicalDebt: [
            "Update deprecated cryptographic algorithms",
            "Remove debug code from production builds",
            "Implement proper session management",
            "Review and minimize application permissions"
          ]
        },
        testingRecommendations: {
          staticAnalysis: "Integrate SAST tools in build pipeline",
          dynamicAnalysis: "Implement DAST for runtime testing",
          interactiveAnalysis: "Use IAST for real-time feedback",
          manualTesting: "Conduct quarterly penetration testing",
          codeReview: "Implement security-focused code review process"
        },
        appendices: {
          toolInformation: {
            name: "SecureAPK Analyzer",
            version: "2.0",
            methodology: "OWASP MSTG, NIST Cybersecurity Framework",
            analysisDepth: "Comprehensive static and behavioral analysis"
          },
          glossary: {
            "XSS": "Cross-Site Scripting - Injection of malicious scripts",
            "CSRF": "Cross-Site Request Forgery - Unauthorized commands transmission",
            "SSRF": "Server-Side Request Forgery - Server-side application vulnerabilities",
            "IDOR": "Insecure Direct Object References - Access control vulnerabilities",
            "RCE": "Remote Code Execution - Arbitrary code execution vulnerabilities"
          },
          references: [
            "OWASP Mobile Security Testing Guide",
            "NIST Cybersecurity Framework",
            "CWE/SANS Top 25 Most Dangerous Software Errors",
            "Google Android Security Guidelines"
          ]
        }
      };
      
      const reportContent = JSON.stringify(detailedReport, null, 2);
      const reportFileName = `security-report-${analysis.fileName}-${Date.now()}.json`;
      
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="${reportFileName}"`);
      res.send(reportContent);
    } catch (error) {
      console.error('Report generation error:', error);
      res.status(500).json({ message: "Failed to generate report" });
    }
  });

  // Helper functions for report generation
  function getImpactDescription(severity: string): string {
    switch (severity) {
      case 'critical': return 'Immediate risk to application security and user data';
      case 'high': return 'Significant security risk requiring prompt attention';
      case 'medium': return 'Moderate security risk that should be addressed';
      case 'low': return 'Minor security concern for future consideration';
      default: return 'Impact assessment required';
    }
  }

  function getExploitabilityRating(severity: string): string {
    switch (severity) {
      case 'critical': return 'Easily exploitable with minimal skill required';
      case 'high': return 'Exploitable with common tools and techniques';
      case 'medium': return 'Requires moderate technical skill to exploit';
      case 'low': return 'Difficult to exploit or limited impact';
      default: return 'Exploitability assessment required';
    }
  }

  function getSecurityReferences(category: string): string[] {
    const references: Record<string, string[]> = {
      'Cross-Site Scripting': ['CWE-79', 'OWASP XSS Prevention'],
      'Cross-Site Request Forgery': ['CWE-352', 'OWASP CSRF Prevention'],
      'Server-Side Request Forgery': ['CWE-918', 'OWASP SSRF Prevention'],
      'Insecure Direct Object References': ['CWE-639', 'OWASP Access Control'],
      'Remote Code Execution': ['CWE-94', 'OWASP Code Injection Prevention'],
      'Broken Access Control': ['CWE-284', 'OWASP Access Control Cheat Sheet']
    };
    return references[category] || ['General security references available'];
  }

  function getOWASPCompliance(vulnerabilities: any[]): string {
    const owaspIssues = vulnerabilities.filter(v => 
      ['XSS', 'CSRF', 'SSRF', 'IDOR', 'RCE', 'Access Control'].includes(v.category)
    );
    return owaspIssues.length === 0 ? 'Compliant' : `${owaspIssues.length} OWASP issues found`;
  }

  function getAPISecurityCompliance(apiTesting: any): string {
    if (!apiTesting) return 'Not assessed';
    return apiTesting.status === 'passed' ? 'Compliant' : 'Issues identified';
  }

  function getImmediateActions(vulnerabilities: any[]): string[] {
    const actions = [];
    const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical');
    
    if (criticalVulns.some(v => v.category.includes('XSS'))) {
      actions.push('Implement XSS protection and input sanitization');
    }
    if (criticalVulns.some(v => v.category.includes('SQL'))) {
      actions.push('Replace string concatenation with parameterized queries');
    }
    if (criticalVulns.some(v => v.category.includes('RCE'))) {
      actions.push('Remove or secure command execution functionality');
    }
    if (criticalVulns.some(v => v.category.includes('Access Control'))) {
      actions.push('Implement proper authorization checks');
    }
    
    if (actions.length === 0) {
      actions.push('Continue monitoring and maintain current security posture');
    }
    
    return actions;
  }

  // Delete APK analysis
  app.delete("/api/analyses/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const analysis = await storage.getApkAnalysis(id);
      
      if (!analysis) {
        return res.status(404).json({ message: "Analysis not found" });
      }
      
      // Clean up files
      if (analysis.fixedApkPath && fs.existsSync(analysis.fixedApkPath)) {
        fs.unlinkSync(analysis.fixedApkPath);
      }
      
      const deleted = await storage.deleteApkAnalysis(id);
      
      if (!deleted) {
        return res.status(404).json({ message: "Analysis not found" });
      }
      
      res.json({ message: "Analysis deleted successfully" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete analysis" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
