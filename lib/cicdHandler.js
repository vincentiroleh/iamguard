import chalk from 'chalk';
import fs from 'fs';

export class CICDHandler {
  constructor(config = {}) {
    this.config = {
      failOnCritical: process.env.IAM_FAIL_ON_CRITICAL === 'true' || config.failOnCritical || true,
      failOnHigh: process.env.IAM_FAIL_ON_HIGH === 'true' || config.failOnHigh || false,
      maxMediumIssues: parseInt(process.env.IAM_MAX_MEDIUM_ISSUES) || config.maxMediumIssues || 10,
      maxLowIssues: parseInt(process.env.IAM_MAX_LOW_ISSUES) || config.maxLowIssues || 50,
      enableExitCodes: process.env.IAM_ENABLE_EXIT_CODES !== 'false' && (config.enableExitCodes !== false),
      outputFormat: process.env.IAM_OUTPUT_FORMAT || config.outputFormat || 'json',
      suppressBanner: process.env.IAM_SUPPRESS_BANNER === 'true' || config.suppressBanner || false
    };
  }

  /**
   * Analyze findings and determine appropriate exit code
   */
  analyzeFindings(securityFindings) {
    const allFindings = Object.values(securityFindings).flat();
    
    const summary = {
      critical: allFindings.filter(f => f.severity === 'CRITICAL').length,
      high: allFindings.filter(f => f.severity === 'HIGH').length,
      medium: allFindings.filter(f => f.severity === 'MEDIUM').length,
      low: allFindings.filter(f => f.severity === 'LOW').length,
      total: allFindings.length
    };

    const analysis = {
      summary,
      shouldFail: false,
      exitCode: 0,
      reason: 'No security issues found'
    };

    // Check failure conditions
    if (this.config.failOnCritical && summary.critical > 0) {
      analysis.shouldFail = true;
      analysis.exitCode = 1;
      analysis.reason = `Critical security issues found: ${summary.critical}`;
    } else if (this.config.failOnHigh && summary.high > 0) {
      analysis.shouldFail = true;
      analysis.exitCode = 2;
      analysis.reason = `High severity issues found: ${summary.high}`;
    } else if (summary.medium > this.config.maxMediumIssues) {
      analysis.shouldFail = true;
      analysis.exitCode = 3;
      analysis.reason = `Too many medium severity issues: ${summary.medium} (max: ${this.config.maxMediumIssues})`;
    } else if (summary.low > this.config.maxLowIssues) {
      analysis.shouldFail = true;
      analysis.exitCode = 4;
      analysis.reason = `Too many low severity issues: ${summary.low} (max: ${this.config.maxLowIssues})`;
    }

    return analysis;
  }

  /**
   * Generate CI/CD friendly output
   */
  generateCICDOutput(analysis, accountInfo = null) {
    const output = {
      timestamp: new Date().toISOString(),
      account: accountInfo?.accountId || 'unknown',
      scan_result: analysis.shouldFail ? 'FAILED' : 'PASSED',
      exit_code: analysis.exitCode,
      reason: analysis.reason,
      summary: analysis.summary,
      recommendations: this.generateRecommendations(analysis)
    };

    // Write CI/CD specific output file
    const cicdOutputFile = `iam_cicd_result_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    fs.writeFileSync(cicdOutputFile, JSON.stringify(output, null, 2));

    return { output, outputFile: cicdOutputFile };
  }

  /**
   * Generate actionable recommendations for CI/CD
   */
  generateRecommendations(analysis) {
    const recommendations = [];

    if (analysis.summary.critical > 0) {
      recommendations.push({
        priority: 'IMMEDIATE',
        action: 'Address critical security issues before deployment',
        details: `${analysis.summary.critical} critical issues require immediate attention`
      });
    }

    if (analysis.summary.high > 0) {
      recommendations.push({
        priority: 'HIGH',
        action: 'Review and remediate high severity issues',
        details: `${analysis.summary.high} high severity issues found`
      });
    }

    if (analysis.summary.medium > this.config.maxMediumIssues) {
      recommendations.push({
        priority: 'MEDIUM',
        action: 'Reduce medium severity issues',
        details: `Consider addressing ${analysis.summary.medium - this.config.maxMediumIssues} additional medium issues`
      });
    }

    return recommendations;
  }

  /**
   * Print CI/CD friendly console output
   */
  printCICDSummary(analysis, quiet = false) {
    if (!quiet && !this.config.suppressBanner) {
      console.log(chalk.cyan('\n🔍 IAM Security Scan Results'));
      console.log(chalk.gray('=' .repeat(50)));
    }

    // Status indicator
    const statusColor = analysis.shouldFail ? chalk.red : chalk.green;
    const statusIcon = analysis.shouldFail ? '❌' : '✅';
    
    console.log(statusColor(`${statusIcon} Scan Status: ${analysis.shouldFail ? 'FAILED' : 'PASSED'}`));
    
    if (analysis.shouldFail) {
      console.log(chalk.red(`   Reason: ${analysis.reason}`));
    }

    // Summary
    if (!quiet) {
      console.log(chalk.yellow('\n📊 Issue Summary:'));
      console.log(chalk.red(`   Critical: ${analysis.summary.critical}`));
      console.log(chalk.yellow(`   High: ${analysis.summary.high}`));
      console.log(chalk.blue(`   Medium: ${analysis.summary.medium}`));
      console.log(chalk.green(`   Low: ${analysis.summary.low}`));
      console.log(chalk.gray(`   Total: ${analysis.summary.total}`));
    }

    // Exit code info
    if (this.config.enableExitCodes && !quiet) {
      console.log(chalk.gray(`\n🔢 Exit Code: ${analysis.exitCode}`));
      this.printExitCodeReference();
    }
  }

  /**
   * Print exit code reference for CI/CD users
   */
  printExitCodeReference() {
    console.log(chalk.gray('\n📋 Exit Code Reference:'));
    console.log(chalk.gray('   0 = Success (no blocking issues)'));
    console.log(chalk.gray('   1 = Critical security issues found'));
    console.log(chalk.gray('   2 = High severity issues found'));
    console.log(chalk.gray('   3 = Too many medium severity issues'));
    console.log(chalk.gray('   4 = Too many low severity issues'));
  }

  /**
   * Handle process exit based on analysis
   */
  handleExit(analysis) {
    if (this.config.enableExitCodes && analysis.shouldFail) {
      console.log(chalk.red(`\n🚫 Exiting with code ${analysis.exitCode} due to security policy violations`));
      process.exit(analysis.exitCode);
    }
  }

  /**
   * Generate environment-specific configuration suggestions
   */
  generateEnvConfigSuggestions() {
    return {
      development: {
        IAM_FAIL_ON_CRITICAL: 'false',
        IAM_FAIL_ON_HIGH: 'false',
        IAM_MAX_MEDIUM_ISSUES: '20'
      },
      staging: {
        IAM_FAIL_ON_CRITICAL: 'true',
        IAM_FAIL_ON_HIGH: 'false',
        IAM_MAX_MEDIUM_ISSUES: '10'
      },
      production: {
        IAM_FAIL_ON_CRITICAL: 'true',
        IAM_FAIL_ON_HIGH: 'true',
        IAM_MAX_MEDIUM_ISSUES: '5'
      }
    };
  }
}