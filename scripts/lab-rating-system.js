#!/usr/bin/env node

/**
 * Cloud Security Labs - Difficulty Rating System
 * 
 * This script analyzes and rates labs based on multiple factors:
 * - Technical complexity
 * - Prerequisites required
 * - Time commitment
 * - Tools and services used
 * - Learning objectives depth
 */

const fs = require('fs');
const path = require('path');

class LabRatingSystem {
  constructor() {
    this.difficultyLevels = {
      BEGINNER: { score: 1-2, color: '#10B981', icon: '🟢' },
      INTERMEDIATE: { score: 3-4, color: '#3B82F6', icon: '🔵' },
      ADVANCED: { score: 5-6, color: '#8B5CF6', icon: '🟣' },
      EXPERT: { score: 7-8, color: '#EF4444', icon: '🔴' }
    };

    this.complexityFactors = {
      services: { weight: 0.25 },
      prerequisites: { weight: 0.20 },
      timeRequired: { weight: 0.15 },
      technicalDepth: { weight: 0.20 },
      steps: { weight: 0.10 },
      dependencies: { weight: 0.10 }
    };
  }

  /**
   * Analyze a lab directory and calculate difficulty rating
   */
  analyzeLab(labPath) {
    const labMetadata = this.extractLabMetadata(labPath);
    const difficultyScore = this.calculateDifficultyScore(labMetadata);
    const difficultyLevel = this.determineDifficultyLevel(difficultyScore);
    
    return {
      path: labPath,
      metadata: labMetadata,
      score: difficultyScore,
      level: difficultyLevel,
      recommendations: this.generateRecommendations(labMetadata, difficultyLevel)
    };
  }

  /**
   * Extract metadata from lab files
   */
  extractLabMetadata(labPath) {
    const metadata = {
      title: '',
      description: '',
      services: [],
      prerequisites: [],
      estimatedTime: 0,
      steps: 0,
      technicalDepth: 0,
      dependencies: [],
      files: []
    };

    try {
      const files = fs.readdirSync(labPath);
      metadata.files = files;

      // Read README.md for basic information
      const readmePath = path.join(labPath, 'README.md');
      if (fs.existsSync(readmePath)) {
        const readmeContent = fs.readFileSync(readmePath, 'utf8');
        metadata.title = this.extractTitle(readmeContent);
        metadata.description = this.extractDescription(readmeContent);
        metadata.prerequisites = this.extractPrerequisites(readmeContent);
        metadata.estimatedTime = this.extractTimeEstimate(readmeContent);
        metadata.steps = this.countSteps(readmeContent);
      }

      // Analyze code files for technical complexity
      files.forEach(file => {
        if (this.isCodeFile(file)) {
          const filePath = path.join(labPath, file);
          const content = fs.readFileSync(filePath, 'utf8');
          metadata.services.push(...this.extractServices(content));
          metadata.dependencies.push(...this.extractDependencies(content));
          metadata.technicalDepth += this.calculateTechnicalDepth(content);
        }
      });

      // Remove duplicates
      metadata.services = [...new Set(metadata.services)];
      metadata.dependencies = [...new Set(metadata.dependencies)];

    } catch (error) {
      console.error(`Error analyzing lab ${labPath}:`, error.message);
    }

    return metadata;
  }

  /**
   * Calculate overall difficulty score
   */
  calculateDifficultyScore(metadata) {
    let score = 0;

    // Services complexity
    score += Math.min(metadata.services.length * 0.5, 3) * this.complexityFactors.services.weight;

    // Prerequisites
    score += Math.min(metadata.prerequisites.length * 0.3, 2) * this.complexityFactors.prerequisites.weight;

    // Time required (convert hours to score)
    score += Math.min(metadata.estimatedTime * 0.2, 2) * this.complexityFactors.timeRequired.weight;

    // Technical depth
    score += Math.min(metadata.technicalDepth * 0.1, 3) * this.complexityFactors.technicalDepth.weight;

    // Number of steps
    score += Math.min(metadata.steps * 0.05, 1.5) * this.complexityFactors.steps.weight;

    // Dependencies
    score += Math.min(metadata.dependencies.length * 0.2, 1.5) * this.complexityFactors.dependencies.weight;

    return Math.round(score * 10) / 10;
  }

  /**
   * Determine difficulty level based on score
   */
  determineDifficultyLevel(score) {
    if (score <= 2) return 'BEGINNER';
    if (score <= 4) return 'INTERMEDIATE';
    if (score <= 6) return 'ADVANCED';
    return 'EXPERT';
  }

  /**
   * Generate recommendations based on lab analysis
   */
  generateRecommendations(metadata, difficultyLevel) {
    const recommendations = [];

    if (metadata.prerequisites.length > 3) {
      recommendations.push('Consider completing prerequisite labs first');
    }

    if (metadata.estimatedTime > 4) {
      recommendations.push('Plan for multiple sessions to complete this lab');
    }

    if (metadata.services.length > 5) {
      recommendations.push('Familiarize yourself with multiple cloud services');
    }

    if (difficultyLevel === 'EXPERT') {
      recommendations.push('Ensure solid understanding of advanced security concepts');
    }

    return recommendations;
  }

  /**
   * Extract title from README content
   */
  extractTitle(content) {
    const match = content.match(/^#\s+(.+)$/m);
    return match ? match[1] : '';
  }

  /**
   * Extract description from README content
   */
  extractDescription(content) {
    const lines = content.split('\n');
    let description = '';
    let foundTitle = false;

    for (const line of lines) {
      if (line.startsWith('# ')) {
        foundTitle = true;
        continue;
      }
      if (foundTitle && line.trim()) {
        description = line.replace(/^>/, '').trim();
        break;
      }
    }

    return description;
  }

  /**
   * Extract prerequisites from README content
   */
  extractPrerequisites(content) {
    const prerequisites = [];
    const prereqSection = content.match(/##\s*Prerequisites\s*\n([\s\S]*?)(?=\n##|\n$)/i);
    
    if (prereqSection) {
      const lines = prereqSection[1].split('\n');
      lines.forEach(line => {
        if (line.match(/^[-*+]\s+/)) {
          prerequisites.push(line.replace(/^[-*+]\s+/, '').trim());
        }
      });
    }

    return prerequisites;
  }

  /**
   * Extract time estimate from README content
   */
  extractTimeEstimate(content) {
    const timeMatch = content.match(/(\d+)\s*(hour|hr|minute|min)/i);
    if (timeMatch) {
      const value = parseInt(timeMatch[1]);
      const unit = timeMatch[2].toLowerCase();
      return unit.includes('hour') || unit.includes('hr') ? value : value / 60;
    }
    return 2; // Default 2 hours
  }

  /**
   * Count steps in README content
   */
  countSteps(content) {
    const stepMatches = content.match(/^(\d+\.|[-*+])\s+/gm);
    return stepMatches ? stepMatches.length : 0;
  }

  /**
   * Check if file is a code file
   */
  isCodeFile(filename) {
    const codeExtensions = ['.js', '.py', '.tf', '.yml', '.yaml', '.json', '.sh', '.ps1', '.bicep'];
    return codeExtensions.some(ext => filename.endsWith(ext));
  }

  /**
   * Extract cloud services from code content
   */
  extractServices(content) {
    const services = [];
    
    // Azure services
    const azureServices = [
      'VirtualMachine', 'StorageAccount', 'NetworkSecurityGroup', 'KeyVault',
      'ApplicationGateway', 'LoadBalancer', 'VirtualNetwork', 'Subnet',
      'AzureFirewall', 'DDoSProtection', 'Monitor', 'LogAnalytics'
    ];
    
    // AWS services
    const awsServices = [
      'EC2', 'S3', 'VPC', 'SecurityGroup', 'IAM', 'CloudWatch',
      'CloudTrail', 'GuardDuty', 'KMS', 'Lambda'
    ];

    // GCP services
    const gcpServices = [
      'ComputeEngine', 'CloudStorage', 'VPC', 'Firewall', 'IAM',
      'CloudMonitoring', 'CloudLogging', 'SecurityCommandCenter'
    ];

    [...azureServices, ...awsServices, ...gcpServices].forEach(service => {
      if (content.includes(service)) {
        services.push(service);
      }
    });

    return services;
  }

  /**
   * Extract dependencies from code content
   */
  extractDependencies(content) {
    const dependencies = [];
    
    // Terraform providers
    const providerMatches = content.match(/provider\s+"([^"]+)"/g);
    if (providerMatches) {
      providerMatches.forEach(match => {
        const provider = match.match(/"([^"]+)"/)[1];
        dependencies.push(provider);
      });
    }

    // npm packages
    const npmMatches = content.match(/"([^"]+)":\s*"[^"]+"/g);
    if (npmMatches) {
      npmMatches.forEach(match => {
        const pkg = match.match(/"([^"]+)":/)[1];
        dependencies.push(pkg);
      });
    }

    return dependencies;
  }

  /**
   * Calculate technical depth based on code complexity
   */
  calculateTechnicalDepth(content) {
    let depth = 0;

    // Count lines of code
    const lines = content.split('\n').filter(line => line.trim() && !line.trim().startsWith('#'));
    depth += Math.min(lines.length / 10, 2);

    // Count conditional statements
    const conditionals = (content.match(/if|else|switch|case/g) || []).length;
    depth += Math.min(conditionals * 0.2, 1);

    // Count functions/methods
    const functions = (content.match(/function|def|resource|module/g) || []).length;
    depth += Math.min(functions * 0.3, 1);

    // Count variables/parameters
    const variables = (content.match(/variable|parameter|let|const|var/g) || []).length;
    depth += Math.min(variables * 0.1, 1);

    return Math.round(depth * 10) / 10;
  }

  /**
   * Generate difficulty report for all labs
   */
  generateReport(rootDir) {
    const report = {
      generated: new Date().toISOString(),
      summary: {
        totalLabs: 0,
        beginner: 0,
        intermediate: 0,
        advanced: 0,
        expert: 0
      },
      labs: []
    };

    this.scanDirectory(rootDir, report);

    return report;
  }

  /**
   * Recursively scan directory for labs
   */
  scanDirectory(dir, report, depth = 0) {
    if (depth > 3) return; // Prevent infinite recursion

    try {
      const items = fs.readdirSync(dir);

      items.forEach(item => {
        const itemPath = path.join(dir, item);
        const stat = fs.statSync(itemPath);

        if (stat.isDirectory()) {
          // Check if this looks like a lab directory
          if (this.isLabDirectory(itemPath)) {
            const labAnalysis = this.analyzeLab(itemPath);
            report.labs.push(labAnalysis);
            report.summary.totalLabs++;
            report.summary[labAnalysis.level.toLowerCase()]++;
          } else {
            this.scanDirectory(itemPath, report, depth + 1);
          }
        }
      });
    } catch (error) {
      console.error(`Error scanning directory ${dir}:`, error.message);
    }
  }

  /**
   * Check if directory is a lab directory
   */
  isLabDirectory(dirPath) {
    const files = fs.readdirSync(dirPath);
    return files.includes('README.md') || files.includes('main.tf') || files.includes('index.js');
  }

  /**
   * Save report to JSON file
   */
  saveReport(report, outputPath) {
    const reportData = {
      ...report,
      summary: {
        ...report.summary,
        averageDifficulty: report.labs.length > 0 
          ? (report.labs.reduce((sum, lab) => sum + lab.score, 0) / report.labs.length).toFixed(1)
          : 0
      }
    };

    fs.writeFileSync(outputPath, JSON.stringify(reportData, null, 2));
    console.log(`Report saved to ${outputPath}`);
  }

  /**
   * Generate markdown report
   */
  generateMarkdownReport(report) {
    let markdown = `# Cloud Security Labs - Difficulty Rating Report\n\n`;
    markdown += `**Generated:** ${new Date(report.generated).toLocaleString()}\n\n`;

    // Summary section
    markdown += `## Summary\n\n`;
    markdown += `| Metric | Count |\n`;
    markdown += `|--------|-------|\n`;
    markdown += `| Total Labs | ${report.summary.totalLabs} |\n`;
    markdown += `| 🟢 Beginner | ${report.summary.beginner} |\n`;
    markdown += `| 🔵 Intermediate | ${report.summary.intermediate} |\n`;
    markdown += `| 🟣 Advanced | ${report.summary.advanced} |\n`;
    markdown += `| 🔴 Expert | ${report.summary.expert} |\n\n`;

    // Labs by difficulty
    markdown += `## Labs by Difficulty\n\n`;

    Object.keys(this.difficultyLevels).forEach(level => {
      const levelLabs = report.labs.filter(lab => lab.level === level);
      if (levelLabs.length > 0) {
        markdown += `### ${level} ${this.difficultyLevels[level].icon}\n\n`;
        levelLabs.forEach(lab => {
          markdown += `- **${lab.metadata.title}** (Score: ${lab.score})\n`;
          markdown += `  - Path: \`${lab.path}\`\n`;
          markdown += `  - Services: ${lab.metadata.services.join(', ')}\n`;
          markdown += `  - Time: ${lab.metadata.estimatedTime}h\n`;
          if (lab.recommendations.length > 0) {
            markdown += `  - Recommendations: ${lab.recommendations.join('; ')}\n`;
          }
          markdown += `\n`;
        });
      }
    });

    return markdown;
  }
}

// CLI interface
if (require.main === module) {
  const rater = new LabRatingSystem();
  const rootDir = process.argv[2] || '.';
  
  console.log('Analyzing labs...');
  const report = rater.generateReport(rootDir);
  
  // Save JSON report
  rater.saveReport(report, path.join(rootDir, 'lab-difficulty-report.json'));
  
  // Generate and save markdown report
  const markdownReport = rater.generateMarkdownReport(report);
  fs.writeFileSync(path.join(rootDir, 'lab-difficulty-report.md'), markdownReport);
  
  console.log('Analysis complete!');
  console.log(`Found ${report.summary.totalLabs} labs:`);
  console.log(`- Beginner: ${report.summary.beginner}`);
  console.log(`- Intermediate: ${report.summary.intermediate}`);
  console.log(`- Advanced: ${report.summary.advanced}`);
  console.log(`- Expert: ${report.summary.expert}`);
}

module.exports = LabRatingSystem;
