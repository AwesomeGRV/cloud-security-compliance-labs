#!/usr/bin/env node

/**
 * Cloud Security Labs - Automated Lab Validation System
 * 
 * This script validates labs for:
 * - Documentation completeness
 * - Code quality and best practices
 * - Security compliance
 * - Functional testing
 * - Consistency standards
 */

const fs = require('fs');
const path = require('path');

class LabValidator {
  constructor() {
    this.validationRules = {
      documentation: {
        required: ['README.md'],
        recommended: ['diagram.png', 'architecture.md'],
        checks: [
          'hasTitle',
          'hasDescription',
          'hasPrerequisites',
          'hasLearningObjectives',
          'hasSteps',
          'hasValidation'
        ]
      },
      code: {
        checks: [
          'hasNoHardcodedSecrets',
          'hasProperErrorHandling',
          'followsNamingConventions',
          'hasComments',
          'usesSecureDefaults'
        ]
      },
      security: {
        checks: [
          'hasSecurityControls',
          'usesPrincipleOfLeastPrivilege',
          'hasEncryption',
          'hasMonitoring',
          'hasBackupPlan'
        ]
      },
      structure: {
        required: ['README.md'],
        checks: [
          'hasLogicalFlow',
          'hasClearSections',
          'hasConsistentFormatting',
          'hasWorkingLinks'
        ]
      }
    };

    this.validationResults = {
      passed: 0,
      failed: 0,
      warnings: 0,
      total: 0,
      details: []
    };
  }

  /**
   * Validate a single lab
   */
  async validateLab(labPath) {
    const labResults = {
      path: labPath,
      status: 'pending',
      checks: [],
      score: 0,
      issues: [],
      recommendations: []
    };

    try {
      // Check documentation
      await this.validateDocumentation(labPath, labResults);
      
      // Check code quality
      await this.validateCode(labPath, labResults);
      
      // Check security compliance
      await this.validateSecurity(labPath, labResults);
      
      // Check structure
      await this.validateStructure(labPath, labResults);

      // Calculate overall score
      labResults.score = this.calculateScore(labResults.checks);
      labResults.status = labResults.score >= 80 ? 'passed' : 'failed';

    } catch (error) {
      labResults.status = 'error';
      labResults.issues.push({
        type: 'error',
        message: `Validation failed: ${error.message}`
      });
    }

    return labResults;
  }

  /**
   * Validate documentation requirements
   */
  async validateDocumentation(labPath, results) {
    const readmePath = path.join(labPath, 'README.md');
    
    if (!fs.existsSync(readmePath)) {
      results.issues.push({
        type: 'error',
        category: 'documentation',
        message: 'README.md is missing'
      });
      return;
    }

    const content = fs.readFileSync(readmePath, 'utf8');
    
    // Check for required sections
    const requiredSections = [
      { name: 'Title', pattern: /^#\s+.+$/m, check: 'hasTitle' },
      { name: 'Description', pattern: />\s+.+/, check: 'hasDescription' },
      { name: 'Prerequisites', pattern: /##\s*Prerequisites/i, check: 'hasPrerequisites' },
      { name: 'Learning Objectives', pattern: /##\s*Learning\s+Objectives/i, check: 'hasLearningObjectives' },
      { name: 'Steps', pattern: /##\s*Steps|##\s*Instructions/i, check: 'hasSteps' },
      { name: 'Validation', pattern: /##\s*Validation|##\s*Testing/i, check: 'hasValidation' }
    ];

    requiredSections.forEach(section => {
      const passed = section.pattern.test(content);
      results.checks.push({
        category: 'documentation',
        check: section.check,
        status: passed ? 'passed' : 'failed',
        message: passed ? `${section.name} found` : `${section.name} missing`
      });

      if (!passed) {
        results.issues.push({
          type: 'error',
          category: 'documentation',
          message: `Missing ${section.name.toLowerCase()} section`
        });
      }
    });

    // Check for recommended files
    const recommendedFiles = ['diagram.png', 'architecture.md', 'examples/'];
    recommendedFiles.forEach(file => {
      const filePath = path.join(labPath, file);
      if (fs.existsSync(filePath)) {
        results.checks.push({
          category: 'documentation',
          check: 'hasRecommendedFiles',
          status: 'passed',
          message: `Recommended file ${file} found`
        });
      }
    });
  }

  /**
   * Validate code quality
   */
  async validateCode(labPath, results) {
    const files = fs.readdirSync(labPath);
    const codeFiles = files.filter(file => this.isCodeFile(file));

    for (const file of codeFiles) {
      const filePath = path.join(labPath, file);
      const content = fs.readFileSync(filePath, 'utf8');
      
      // Check for hardcoded secrets
      if (this.hasHardcodedSecrets(content)) {
        results.issues.push({
          type: 'error',
          category: 'security',
          message: `Hardcoded secrets found in ${file}`,
          recommendation: 'Use environment variables or secret management'
        });
        results.checks.push({
          category: 'code',
          check: 'hasNoHardcodedSecrets',
          status: 'failed',
          file: file
        });
      } else {
        results.checks.push({
          category: 'code',
          check: 'hasNoHardcodedSecrets',
          status: 'passed',
          file: file
        });
      }

      // Check for error handling
      if (this.hasErrorHandling(content)) {
        results.checks.push({
          category: 'code',
          check: 'hasProperErrorHandling',
          status: 'passed',
          file: file
        });
      } else {
        results.issues.push({
          type: 'warning',
          category: 'code',
          message: `Missing error handling in ${file}`,
          recommendation: 'Add try-catch blocks or error handling logic'
        });
      }

      // Check naming conventions
      if (this.followsNamingConventions(content, file)) {
        results.checks.push({
          category: 'code',
          check: 'followsNamingConventions',
          status: 'passed',
          file: file
        });
      }

      // Check for comments
      if (this.hasComments(content)) {
        results.checks.push({
          category: 'code',
          check: 'hasComments',
          status: 'passed',
          file: file
        });
      }

      // Check secure defaults
      if (this.usesSecureDefaults(content)) {
        results.checks.push({
          category: 'code',
          check: 'usesSecureDefaults',
          status: 'passed',
          file: file
        });
      }
    }
  }

  /**
   * Validate security compliance
   */
  async validateSecurity(labPath, results) {
    const files = fs.readdirSync(labPath);
    
    // Check Terraform files for security
    const terraformFiles = files.filter(file => file.endsWith('.tf'));
    for (const file of terraformFiles) {
      const filePath = path.join(labPath, file);
      const content = fs.readFileSync(filePath, 'utf8');

      // Check for security controls
      if (this.hasSecurityControls(content)) {
        results.checks.push({
          category: 'security',
          check: 'hasSecurityControls',
          status: 'passed',
          file: file
        });
      }

      // Check principle of least privilege
      if (this.usesPrincipleOfLeastPrivilege(content)) {
        results.checks.push({
          category: 'security',
          check: 'usesPrincipleOfLeastPrivilege',
          status: 'passed',
          file: file
        });
      }

      // Check encryption
      if (this.hasEncryption(content)) {
        results.checks.push({
          category: 'security',
          check: 'hasEncryption',
          status: 'passed',
          file: file
        });
      }

      // Check monitoring
      if (this.hasMonitoring(content)) {
        results.checks.push({
          category: 'security',
          check: 'hasMonitoring',
          status: 'passed',
          file: file
        });
      }
    }
  }

  /**
   * Validate lab structure
   */
  async validateStructure(labPath, results) {
    const readmePath = path.join(labPath, 'README.md');
    if (fs.existsSync(readmePath)) {
      const content = fs.readFileSync(readmePath, 'utf8');

      // Check logical flow
      if (this.hasLogicalFlow(content)) {
        results.checks.push({
          category: 'structure',
          check: 'hasLogicalFlow',
          status: 'passed'
        });
      }

      // Check clear sections
      if (this.hasClearSections(content)) {
        results.checks.push({
          category: 'structure',
          check: 'hasClearSections',
          status: 'passed'
        });
      }

      // Check consistent formatting
      if (this.hasConsistentFormatting(content)) {
        results.checks.push({
          category: 'structure',
          check: 'hasConsistentFormatting',
          status: 'passed'
        });
      }

      // Check working links
      const linkIssues = this.checkLinks(content);
      if (linkIssues.length === 0) {
        results.checks.push({
          category: 'structure',
          check: 'hasWorkingLinks',
          status: 'passed'
        });
      } else {
        linkIssues.forEach(issue => {
          results.issues.push({
            type: 'warning',
            category: 'structure',
            message: `Link issue: ${issue}`
          });
        });
      }
    }
  }

  /**
   * Helper methods for validation checks
   */
  hasHardcodedSecrets(content) {
    const secretPatterns = [
      /password\s*=\s*["'][^"']+["']/i,
      /secret\s*=\s*["'][^"']+["']/i,
      /key\s*=\s*["'][^"']+["']/i,
      /token\s*=\s*["'][^"']+["']/i,
      /api_key\s*=\s*["'][^"']+["']/i
    ];
    return secretPatterns.some(pattern => pattern.test(content));
  }

  hasErrorHandling(content) {
    const errorPatterns = [
      /try\s*{/,
      /catch\s*\(/,
      /error/,
      /throw/,
      /fail/
    ];
    return errorPatterns.some(pattern => pattern.test(content));
  }

  followsNamingConventions(content, filename) {
    // Basic naming convention checks
    if (filename.endsWith('.tf')) {
      return /^[a-z0-9_]+$/.test(content); // Terraform naming
    }
    return true; // Default pass for other files
  }

  hasComments(content) {
    const commentPatterns = [
      /#/,
      /\/\*/,
      /\/\//,
      /<!--/
    ];
    return commentPatterns.some(pattern => pattern.test(content));
  }

  usesSecureDefaults(content) {
    const securePatterns = [
      /https:/,
      /ssl/,
      /tls/,
      /encrypted/,
      /secure/
    ];
    return securePatterns.some(pattern => pattern.test(content));
  }

  hasSecurityControls(content) {
    const securityPatterns = [
      /network_security_group/i,
      /firewall/i,
      /security_group/i,
      /iam/i,
      /rbac/i
    ];
    return securityPatterns.some(pattern => pattern.test(content));
  }

  usesPrincipleOfLeastPrivilege(content) {
    const privilegePatterns = [
      /least_privilege/i,
      /minimum_access/i,
      /role_based/i,
      /permissions/i
    ];
    return privilegePatterns.some(pattern => pattern.test(content));
  }

  hasEncryption(content) {
    const encryptionPatterns = [
      /encryption/i,
      /encrypt/i,
      /kms/i,
      /key_vault/i
    ];
    return encryptionPatterns.some(pattern => pattern.test(content));
  }

  hasMonitoring(content) {
    const monitoringPatterns = [
      /monitor/i,
      /log/i,
      /alert/i,
      /metric/i
    ];
    return monitoringPatterns.some(pattern => pattern.test(content));
  }

  hasLogicalFlow(content) {
    // Check for logical progression: intro -> prerequisites -> steps -> validation
    const sections = [
      /#\s+.+/,
      /##\s*Prerequisites/i,
      /##\s*Steps|##\s*Instructions/i,
      /##\s*Validation|##\s*Testing/i
    ];
    
    let lastIndex = -1;
    for (const section of sections) {
      const match = content.match(section);
      if (match) {
        const currentIndex = content.indexOf(match[0]);
        if (currentIndex < lastIndex) {
          return false; // Sections out of order
        }
        lastIndex = currentIndex;
      }
    }
    return true;
  }

  hasClearSections(content) {
    // Check for proper heading structure
    const headings = content.match(/^#+\s+.+$/gm);
    if (!headings) return false;
    
    // Should have at least H1 and H2 headings
    const h1Count = headings.filter(h => h.startsWith('# ')).length;
    const h2Count = headings.filter(h => h.startsWith('## ')).length;
    
    return h1Count >= 1 && h2Count >= 2;
  }

  hasConsistentFormatting(content) {
    // Check for consistent heading spacing
    const headings = content.match(/^#+\s*.+$/gm);
    if (!headings) return true;
    
    // All headings should have a space after #
    return headings.every(heading => heading.match(/^#+\s/));
  }

  checkLinks(content) {
    const linkPattern = /\[([^\]]+)\]\(([^)]+)\)/g;
    const issues = [];
    let match;

    while ((match = linkPattern.exec(content)) !== null) {
      const link = match[2];
      if (link.startsWith('http')) {
        // External link - could be checked with HTTP request
        // For now, just validate format
        if (!link.match(/^https?:\/\/.+\..+/)) {
          issues.push(`Invalid URL format: ${link}`);
        }
      }
    }

    return issues;
  }

  /**
   * Check if file is a code file
   */
  isCodeFile(filename) {
    const codeExtensions = ['.js', '.py', '.tf', '.yml', '.yaml', '.json', '.sh', '.ps1', '.bicep'];
    return codeExtensions.some(ext => filename.endsWith(ext));
  }

  /**
   * Calculate validation score
   */
  calculateScore(checks) {
    if (checks.length === 0) return 0;
    
    const passed = checks.filter(check => check.status === 'passed').length;
    return Math.round((passed / checks.length) * 100);
  }

  /**
   * Generate validation report
   */
  async generateReport(rootDir) {
    const report = {
      timestamp: new Date().toISOString(),
      summary: {
        total: 0,
        passed: 0,
        failed: 0,
        errors: 0
      },
      labs: [],
      commonIssues: {},
      recommendations: []
    };

    // Scan for labs
    const labs = this.findLabs(rootDir);
    report.summary.total = labs.length;

    // Validate each lab
    for (const labPath of labs) {
      const results = await this.validateLab(labPath);
      report.labs.push(results);

      if (results.status === 'passed') {
        report.summary.passed++;
      } else if (results.status === 'error') {
        report.summary.errors++;
      } else {
        report.summary.failed++;
      }

      // Track common issues
      results.issues.forEach(issue => {
        const key = `${issue.category}:${issue.type}`;
        report.commonIssues[key] = (report.commonIssues[key] || 0) + 1;
      });
    }

    // Generate recommendations
    report.recommendations = this.generateRecommendations(report);

    return report;
  }

  /**
   * Find all lab directories
   */
  findLabs(rootDir) {
    const labs = [];
    
    function scanDirectory(dir, depth = 0) {
      if (depth > 3) return; // Prevent infinite recursion

      try {
        const items = fs.readdirSync(dir);

        items.forEach(item => {
          const itemPath = path.join(dir, item);
          const stat = fs.statSync(itemPath);

          if (stat.isDirectory()) {
            if (fs.existsSync(path.join(itemPath, 'README.md'))) {
              labs.push(itemPath);
            } else {
              scanDirectory(itemPath, depth + 1);
            }
          }
        });
      } catch (error) {
        console.error(`Error scanning directory ${dir}:`, error.message);
      }
    }

    scanDirectory(rootDir);
    return labs;
  }

  /**
   * Generate recommendations based on validation results
   */
  generateRecommendations(report) {
    const recommendations = [];

    // Analyze common issues
    Object.entries(report.commonIssues).forEach(([issue, count]) => {
      const [category, type] = issue.split(':');
      
      if (count > report.summary.total * 0.3) { // If issue affects >30% of labs
        switch (category) {
          case 'documentation':
            recommendations.push({
              priority: 'high',
              category: 'documentation',
              message: `Improve documentation standards - ${type} issues found in ${count} labs`
            });
            break;
          case 'security':
            recommendations.push({
              priority: 'high',
              category: 'security',
              message: `Address security concerns - ${type} issues found in ${count} labs`
            });
            break;
          case 'code':
            recommendations.push({
              priority: 'medium',
              category: 'code',
              message: `Improve code quality - ${type} issues found in ${count} labs`
            });
            break;
        }
      }
    });

    return recommendations;
  }

  /**
   * Save validation report
   */
  saveReport(report, outputPath) {
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
    console.log(`Validation report saved to ${outputPath}`);
  }

  /**
   * Generate markdown report
   */
  generateMarkdownReport(report) {
    let markdown = `# Cloud Security Labs - Validation Report\n\n`;
    markdown += `**Generated:** ${new Date(report.timestamp).toLocaleString()}\n\n`;

    // Summary
    markdown += `## Summary\n\n`;
    markdown += `| Metric | Count | Percentage |\n`;
    markdown += `|--------|-------|------------|\n`;
    markdown += `| Total Labs | ${report.summary.total} | 100% |\n`;
    markdown += `| ✅ Passed | ${report.summary.passed} | ${Math.round((report.summary.passed / report.summary.total) * 100)}% |\n`;
    markdown += `| ❌ Failed | ${report.summary.failed} | ${Math.round((report.summary.failed / report.summary.total) * 100)}% |\n`;
    markdown += `| 🚫 Errors | ${report.summary.errors} | ${Math.round((report.summary.errors / report.summary.total) * 100)}% |\n\n`;

    // Recommendations
    if (report.recommendations.length > 0) {
      markdown += `## Recommendations\n\n`;
      report.recommendations.forEach(rec => {
        const priority = rec.priority === 'high' ? '🔴' : rec.priority === 'medium' ? '🟡' : '🟢';
        markdown += `${priority} **${rec.category}**: ${rec.message}\n\n`;
      });
    }

    // Lab details
    markdown += `## Lab Details\n\n`;
    report.labs.forEach(lab => {
      const status = lab.status === 'passed' ? '✅' : lab.status === 'failed' ? '❌' : '🚫';
      markdown += `### ${status} ${lab.path}\n\n`;
      markdown += `**Score:** ${lab.score}/100\n\n`;
      
      if (lab.issues.length > 0) {
        markdown += `**Issues:**\n`;
        lab.issues.forEach(issue => {
          const icon = issue.type === 'error' ? '🚫' : '⚠️';
          markdown += `- ${icon} ${issue.message}\n`;
        });
        markdown += `\n`;
      }
    });

    return markdown;
  }
}

// CLI interface
if (require.main === module) {
  const validator = new LabValidator();
  const rootDir = process.argv[2] || '.';
  
  console.log('Validating labs...');
  validator.generateReport(rootDir).then(report => {
    // Save JSON report
    validator.saveReport(report, path.join(rootDir, 'lab-validation-report.json'));
    
    // Generate and save markdown report
    const markdownReport = validator.generateMarkdownReport(report);
    fs.writeFileSync(path.join(rootDir, 'lab-validation-report.md'), markdownReport);
    
    console.log('Validation complete!');
    console.log(`Total labs: ${report.summary.total}`);
    console.log(`Passed: ${report.summary.passed}`);
    console.log(`Failed: ${report.summary.failed}`);
    console.log(`Errors: ${report.summary.errors}`);
  });
}

module.exports = LabValidator;
