import fs from "fs";
import {
  IAMClient,
  ListUsersCommand,
  ListPoliciesCommand,
  ListRolesCommand,
  GetPolicyVersionCommand,
  ListAttachedUserPoliciesCommand,
  GetRoleCommand,
  ListAccessKeysCommand,
  GetAccountPasswordPolicyCommand,
  ListMFADevicesCommand,
  GetLoginProfileCommand
} from "@aws-sdk/client-iam";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import chalk from "chalk";
import { RateLimiter, RetryHandler } from './rateLimiter.js';
import { SECURITY_RULES, DANGEROUS_ACTIONS, evaluateCompliance } from './securityRules.js';
import { CICDHandler } from './cicdHandler.js';

// Initialize AWS clients with retry configuration
const clientConfig = {
  maxAttempts: 3,
  retryMode: 'adaptive'
};

const iamClient = new IAMClient(clientConfig);
const stsClient = new STSClient(clientConfig);

// Rate limiter and retry handler
const rateLimiter = new RateLimiter(10, 1000); // 10 requests per second
const retryHandler = new RetryHandler(3, 1000);

// Configuration constants with environment variable support
const DAYS_THRESHOLD = parseInt(process.env.IAM_INACTIVE_DAYS_THRESHOLD) || 30;
const ACCESS_KEY_AGE_THRESHOLD = parseInt(process.env.IAM_ACCESS_KEY_AGE_THRESHOLD) || 90;

// Enhanced security findings structure
const securityFindings = {
  publicPolicies: [],
  inactiveUsers: [],
  inactiveRoles: [],
  accessKeyIssues: [],
  adminAccessUsers: [],
  passwordPolicyIssues: [],
  mfaIssues: [],
  consoleAccessIssues: [],
  complianceIssues: []
};

// Validation helper
function validateAWSResponse(response, context) {
  if (!response) {
    throw new Error(`Empty response received from AWS for ${context}`);
  }
  return response;
}

// Date handling helper
function calculateDaysSince(date) {
  if (!date) return null;
  return Math.floor((Date.now() - new Date(date).getTime()) / (1000 * 60 * 60 * 24));
}

function isInactive(lastUsed) {
  const daysSince = calculateDaysSince(lastUsed);
  return daysSince === null || daysSince > DAYS_THRESHOLD;
}

/**
 * Enhanced policy analysis to check for dangerous permissions
 */
function analyzePolicyStatement(statement, policyName) {
  const risks = [];

  // Check for dangerous actions
  const dangerousActions = ['*', 'iam:*', 'organizations:*', 's3:*', 'lambda:*', 'ec2:*'];
  const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];

  actions.forEach(action => {
    if (dangerousActions.some(dangerous => action === dangerous || action.endsWith(':*'))) {
      risks.push({
        type: 'DANGEROUS_ACTION',
        detail: `Policy contains dangerous action: ${action}`,
        severity: 'HIGH'
      });
    }
  });

  // Check for resource wildcards
  const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
  resources.forEach(resource => {
    if (resource === '*') {
      risks.push({
        type: 'WILDCARD_RESOURCE',
        detail: 'Policy uses wildcard resource',
        severity: 'HIGH'
      });
    }
  });

  // Check for NotAction
  if (statement.NotAction) {
    risks.push({
      type: 'NOT_ACTION',
      detail: 'Policy uses NotAction, which can be difficult to reason about',
      severity: 'MEDIUM'
    });
  }

  return risks;
}

/**
 * Fetches all IAM policies with pagination support
 */
export async function fetchIamPolicies() {
  console.log(chalk.blue("\n🔍 Fetching IAM Policies..."));
  const policies = [];
  let isTruncated = true;
  let marker;

  try {
    while (isTruncated) {
      const command = new ListPoliciesCommand({
        Scope: "Local",
        Marker: marker
      });

      const response = validateAWSResponse(
        await iamClient.send(command),
        'ListPoliciesCommand'
      );

      policies.push(...(response.Policies || []));
      isTruncated = response.IsTruncated;
      marker = response.Marker;
    }

    console.log(chalk.green(`✅ Found ${policies.length} IAM policies`));
    return policies;
  } catch (error) {
    console.error(chalk.red("❌ Error fetching IAM policies:"), error.message);
    throw error;
  }
}

/**
 * Enhanced IAM policy analysis with detailed risk assessment
 */
export async function analyzeIamPolicies(policies) {
  console.log(chalk.yellow("\n🔍 Analyzing IAM Policies for Security Risks...\n"));

  for (const policy of policies) {
    const versionCommand = new GetPolicyVersionCommand({
      PolicyArn: policy.Arn,
      VersionId: policy.DefaultVersionId,
    });

    try {
      const policyDetails = await iamClient.send(versionCommand);
      const policyDocument = JSON.parse(decodeURIComponent(policyDetails.PolicyVersion.Document));

      for (const statement of policyDocument.Statement) {
        const risks = analyzePolicyStatement(statement, policy.PolicyName);

        if (risks.length > 0) {
          securityFindings.publicPolicies.push({
            policy: policy.PolicyName,
            risks: risks,
            severity: risks.some(r => r.severity === 'HIGH') ? 'HIGH' : 'MEDIUM',
            recommendation: 'Review and restrict permissions according to least privilege principle'
          });

          console.log(chalk.red(`⚠️ Policy '${policy.PolicyName}' has security risks:`));
          risks.forEach(risk => console.log(chalk.yellow(`  - ${risk.detail}`)));
        }
      }
    } catch (error) {
      console.error(chalk.red(`Error analyzing policy '${policy.PolicyName}':`), error.message);
    }
  }

  console.log(chalk.green("\n✅ IAM Policy Analysis Completed!\n"));
}

/**
 * Check for administrator access
 */
async function checkAdministratorAccess(userName) {
  try {
    const { AttachedPolicies } = await iamClient.send(
      new ListAttachedUserPoliciesCommand({ UserName: userName })
    );

    const adminPolicies = AttachedPolicies.filter(
      policy => policy.PolicyName === 'AdministratorAccess'
    );

    if (adminPolicies.length > 0) {
      securityFindings.adminAccessUsers.push({
        user: userName,
        severity: 'HIGH',
        recommendation: 'Review if administrator access is necessary'
      });
      console.log(chalk.red(`⚠️ User '${userName}' has administrator access`));
    }
  } catch (error) {
    console.error(chalk.red(`Error checking admin access for user '${userName}':`), error);
  }
}

/**
 * Check access keys age and rotation
 */
async function checkAccessKeys(userName) {
  try {
    const { AccessKeyMetadata } = await iamClient.send(
      new ListAccessKeysCommand({ UserName: userName })
    );

    for (const key of AccessKeyMetadata) {
      const keyAge = calculateDaysSince(key.CreateDate);

      if (keyAge > ACCESS_KEY_AGE_THRESHOLD) {
        securityFindings.accessKeyIssues.push({
          user: userName,
          keyId: key.AccessKeyId,
          age: keyAge,
          severity: keyAge > ACCESS_KEY_AGE_THRESHOLD * 2 ? 'HIGH' : 'MEDIUM',
          recommendation: 'Rotate access key'
        });
        console.log(chalk.yellow(`⚠️ User '${userName}' has access key older than ${ACCESS_KEY_AGE_THRESHOLD} days`));
      }
    }
  } catch (error) {
    console.error(chalk.red(`Error checking access keys for user '${userName}':`), error);
  }
}

/**
 * Check MFA configuration for users
 */
async function checkMFAConfiguration(userName) {
  try {
    await rateLimiter.acquire();
    const { MFADevices } = await retryHandler.execute(
      () => iamClient.send(new ListMFADevicesCommand({ UserName: userName })),
      `MFA check for user ${userName}`
    );

    if (MFADevices.length === 0) {
      securityFindings.mfaIssues.push({
        user: userName,
        severity: 'HIGH',
        recommendation: 'Enable MFA for enhanced security'
      });
      console.log(chalk.red(`⚠️ User '${userName}' does not have MFA enabled`));
    }
  } catch (error) {
    console.error(chalk.red(`Error checking MFA for user '${userName}':`), error.message);
  }
}

/**
 * Check console access and login profile
 */
async function checkConsoleAccess(userName) {
  try {
    await rateLimiter.acquire();
    await retryHandler.execute(
      () => iamClient.send(new GetLoginProfileCommand({ UserName: userName })),
      `Console access check for user ${userName}`
    );
    
    // If we get here, user has console access - check if they need it
    const { AttachedPolicies } = await iamClient.send(
      new ListAttachedUserPoliciesCommand({ UserName: userName })
    );

    const hasServiceOnlyPolicies = AttachedPolicies.some(policy => 
      policy.PolicyName.includes('Service') || 
      policy.PolicyName.includes('API') ||
      policy.PolicyName.includes('Programmatic')
    );

    if (hasServiceOnlyPolicies) {
      securityFindings.consoleAccessIssues.push({
        user: userName,
        severity: 'MEDIUM',
        recommendation: 'Review if console access is necessary for service accounts'
      });
      console.log(chalk.yellow(`⚠️ User '${userName}' has console access but appears to be a service account`));
    }
  } catch (error) {
    if (error.name !== 'NoSuchEntityException') {
      console.error(chalk.red(`Error checking console access for user '${userName}':`), error.message);
    }
  }
}

/**
 * Enhanced IAM Users check with additional security controls
 */
export async function checkIamUsers() {
  console.log("\n🔍 Checking IAM Users for Security Risks...");

  try {
    const { Users } = await retryHandler.execute(
      () => iamClient.send(new ListUsersCommand({})),
      'Fetching IAM users'
    );
    
    if (!Users || Users.length === 0) {
      console.log("✅ No IAM users found.");
      return;
    }

    console.log(chalk.blue(`Found ${Users.length} IAM users to analyze`));

    for (const user of Users) {
      const userName = user.UserName;
      console.log(`🔹 Checking user: ${userName}`);

      // Run checks with rate limiting
      await Promise.all([
        checkAdministratorAccess(userName),
        checkAccessKeys(userName),
        checkMFAConfiguration(userName),
        checkConsoleAccess(userName)
      ]);

      if (isInactive(user.PasswordLastUsed)) {
        securityFindings.inactiveUsers.push({
          user: userName,
          lastUsed: user.PasswordLastUsed || 'Never',
          severity: 'MEDIUM',
          recommendation: 'Consider removing inactive user'
        });
        console.log(chalk.yellow(`⚠️ Inactive user detected: ${userName}`));
      }
    }

    console.log("\n✅ IAM User Check Completed!");
  } catch (error) {
    console.error(chalk.red("❌ Error checking IAM users:"), error.message);
    throw error;
  }
}

/**
 * Check IAM roles for security issues
 */
export async function checkIamRoles() {
  console.log("\n🔍 Checking IAM Roles for Security Risks...");

  try {
    const { Roles } = await iamClient.send(new ListRolesCommand({}));

    for (const role of Roles) {
      const roleName = role.RoleName;
      console.log(`🔹 Checking role: ${roleName}`);

      try {
        const roleDetails = await iamClient.send(
          new GetRoleCommand({ RoleName: roleName })
        );

        // Check trust relationships
        const trustPolicy = JSON.parse(decodeURIComponent(roleDetails.Role.AssumeRolePolicyDocument));
        for (const statement of trustPolicy.Statement) {
          if (statement.Principal === "*" ||
            (statement.Principal.AWS && statement.Principal.AWS.includes("*"))) {
            console.log(chalk.red(`⚠️ Role '${roleName}' has overly permissive trust relationship`));
            securityFindings.inactiveRoles.push({
              role: roleName,
              issue: 'Overly permissive trust relationship',
              severity: 'HIGH',
              recommendation: 'Restrict trust relationship to specific principals'
            });
          }
        }

        // Check role usage
        if (isInactive(role.RoleLastUsed?.LastUsedDate)) {
          console.log(chalk.yellow(`⚠️ Inactive role detected: ${roleName}`));
          securityFindings.inactiveRoles.push({
            role: roleName,
            lastUsed: role.RoleLastUsed?.LastUsedDate || 'Never',
            severity: 'LOW',
            recommendation: 'Review and remove if unnecessary'
          });
        }
      } catch (error) {
        console.error(chalk.red(`Error checking role '${roleName}':`), error);
      }
    }

    console.log("\n✅ IAM Role Check Completed!");
  } catch (error) {
    console.error(chalk.red("❌ Error checking IAM roles:"), error);
    throw error;
  }
}

/**
 * Check password policy
 */
export async function checkPasswordPolicy() {
  console.log("\n🔍 Checking Password Policy...");

  try {
    const { PasswordPolicy } = await iamClient.send(
      new GetAccountPasswordPolicyCommand({})
    );

    if (!PasswordPolicy.RequireUppercaseCharacters ||
      !PasswordPolicy.RequireLowercaseCharacters ||
      !PasswordPolicy.RequireNumbers ||
      !PasswordPolicy.RequireSymbols ||
      PasswordPolicy.MinimumPasswordLength < 14 ||
      !PasswordPolicy.PasswordReusePrevention) {

      securityFindings.passwordPolicyIssues.push({
        severity: 'HIGH',
        recommendation: 'Strengthen password policy to meet security best practices',
        details: PasswordPolicy
      });
      console.log(chalk.red("⚠️ Password policy does not meet security best practices"));
    }

    console.log("\n✅ Password Policy Check Completed!");
  } catch (error) {
    if (error.name === 'NoSuchEntityException') {
      securityFindings.passwordPolicyIssues.push({
        severity: 'CRITICAL',
        recommendation: 'Set up an IAM password policy following AWS security best practices',
        details: 'No password policy is configured'
      });
      console.log(chalk.red("⚠️ No password policy is configured"));
      return;
    }
    console.error(chalk.red("❌ Error checking password policy:"), error);
    throw error;
  }
}


/**
 * Generate HTML report content
 */
function generateHtmlReport(report) {
  const severityColors = {
    CRITICAL: '#FF0000',
    HIGH: '#FF6B6B',
    MEDIUM: '#FFA500',
    LOW: '#4CAF50'
  };

  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>IAM Security Report</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            h1, h2 {
                color: #333;
            }
            .summary-box {
                background-color: #f8f9fa;
                border-radius: 4px;
                padding: 15px;
                margin-bottom: 20px;
            }
            .finding {
                border-left: 4px solid #ddd;
                padding: 10px;
                margin-bottom: 10px;
                background-color: #fff;
            }
            .severity {
                font-weight: bold;
                padding: 3px 8px;
                border-radius: 3px;
                color: white;
                margin-right: 10px;
            }
            .timestamp {
                color: #666;
                font-size: 0.9em;
            }
            .recommendation {
                background-color: #e7f3fe;
                padding: 10px;
                border-radius: 4px;
                margin-top: 5px;
            }
            .category {
                margin-bottom: 30px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>IAM Security Report</h1>
            <div class="timestamp">Generated on: ${new Date(report.scanDate).toLocaleString()}</div>
            
            <div class="summary-box">
                <h2>Summary</h2>
                <p>Total Issues: ${report.summary.totalIssues}</p>
                <p>
                    <span class="severity" style="background-color: ${severityColors.CRITICAL}">
                        Critical: ${report.summary.criticalIssues}
                    </span>
                    <span class="severity" style="background-color: ${severityColors.HIGH}">
                        High: ${report.summary.highSeverityIssues}
                    </span>
                    <span class="severity" style="background-color: ${severityColors.MEDIUM}">
                        Medium: ${report.summary.mediumSeverityIssues}
                    </span>
                    <span class="severity" style="background-color: ${severityColors.LOW}">
                        Low: ${report.summary.lowSeverityIssues}
                    </span>
                </p>
            </div>

            ${Object.entries(report.findings)
      .filter(([_, findings]) => findings.length > 0)
      .map(([category, findings]) => `
                <div class="category">
                    <h2>${category.replace(/([A-Z])/g, ' $1').trim()}</h2>
                    ${findings.map(finding => `
                        <div class="finding">
                            <span class="severity" style="background-color: ${severityColors[finding.severity]}">
                                ${finding.severity}
                            </span>
                            ${finding.user ? `<strong>User:</strong> ${finding.user}<br>` : ''}
                            ${finding.role ? `<strong>Role:</strong> ${finding.role}<br>` : ''}
                            ${finding.policy ? `<strong>Policy:</strong> ${finding.policy}<br>` : ''}
                            ${finding.lastUsed ? `<strong>Last Used:</strong> ${finding.lastUsed}<br>` : ''}
                            ${finding.details ? `<p><strong>Details:</strong> ${finding.details}</p>` : ''}
                            <div class="recommendation">
                                <strong>📝 Recommendation:</strong><br>
                                ${finding.recommendation}
                            </div>
                        </div>
                    `).join('')}
                </div>
            `).join('')}
        </div>
    </body>
    </html>
  `;

  return html;
}

/**
 * Enhanced security report generation with more details and formatting
 */
/**
 * Get AWS account information
 */
export async function getAccountInfo() {
  try {
    const { Account, Arn } = await retryHandler.execute(
      () => stsClient.send(new GetCallerIdentityCommand({})),
      'Getting account information'
    );
    
    console.log(chalk.blue(`\n🏢 Scanning AWS Account: ${Account}`));
    console.log(chalk.gray(`   Identity: ${Arn}`));
    
    return { accountId: Account, identity: Arn };
  } catch (error) {
    console.error(chalk.red("❌ Error getting account information:"), error.message);
    throw error;
  }
}

/**
 * Generate CSV report content
 */
function generateCsvReport(report) {
  const csvRows = [
    ['Category', 'Resource', 'Severity', 'Issue', 'Recommendation', 'Last Used', 'Age (Days)']
  ];

  Object.entries(report.findings).forEach(([category, findings]) => {
    findings.forEach(finding => {
      csvRows.push([
        category.replace(/([A-Z])/g, ' $1').trim(),
        finding.user || finding.role || finding.policy || 'N/A',
        finding.severity,
        finding.issue || finding.detail || 'Security risk detected',
        finding.recommendation,
        finding.lastUsed || 'N/A',
        finding.age || 'N/A'
      ]);
    });
  });

  return csvRows.map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
}

/**
 * Enhanced security report generation with multiple formats and CI/CD support
 */
export async function generateSecurityReport(accountInfo = null, options = {}) {
  // Add compliance evaluation
  const allFindings = Object.values(securityFindings).flat();
  const complianceResults = evaluateCompliance(allFindings, 'CIS');
  
  securityFindings.complianceIssues = complianceResults.filter(result => !result.compliant);

  const report = {
    scanDate: new Date().toISOString(),
    accountInfo: accountInfo || { accountId: 'Unknown', identity: 'Unknown' },
    findings: securityFindings,
    compliance: {
      framework: 'CIS AWS Foundations Benchmark',
      results: complianceResults,
      overallScore: Math.round((complianceResults.filter(r => r.compliant).length / complianceResults.length) * 100)
    },
    summary: {
      totalIssues: Object.values(securityFindings).flat().length,
      criticalIssues: Object.values(securityFindings)
        .flat()
        .filter(finding => finding.severity === 'CRITICAL').length,
      highSeverityIssues: Object.values(securityFindings)
        .flat()
        .filter(finding => finding.severity === 'HIGH').length,
      mediumSeverityIssues: Object.values(securityFindings)
        .flat()
        .filter(finding => finding.severity === 'MEDIUM').length,
      lowSeverityIssues: Object.values(securityFindings)
        .flat()
        .filter(finding => finding.severity === 'LOW').length
    }
  };

  // Generate timestamp for filenames
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  // Save JSON report
  const jsonFilePath = `iam_security_report_${timestamp}.json`;
  fs.writeFileSync(jsonFilePath, JSON.stringify(report, null, 2));

  // Generate and save HTML report
  const htmlFilePath = `iam_security_report_${timestamp}.html`;
  const htmlContent = generateHtmlReport(report);
  fs.writeFileSync(htmlFilePath, htmlContent);

  // Generate and save CSV report
  const csvFilePath = `iam_security_report_${timestamp}.csv`;
  const csvContent = generateCsvReport(report);
  fs.writeFileSync(csvFilePath, csvContent);

  // CI/CD Integration
  const cicdHandler = new CICDHandler(options.cicdConfig);
  const analysis = cicdHandler.analyzeFindings(securityFindings);
  const { output: cicdOutput, outputFile: cicdOutputFile } = cicdHandler.generateCICDOutput(analysis, accountInfo);

  // Console output
  if (options.cicdMode) {
    cicdHandler.printCICDSummary(analysis, options.quiet);
    console.log(chalk.blue(`\n📄 CI/CD Report: ${cicdOutputFile}`));
  } else {
    console.log(chalk.green(`\n✅ Security Reports Generated:`));
    console.log(chalk.blue(`   JSON Report: ${jsonFilePath}`));
    console.log(chalk.blue(`   HTML Report: ${htmlFilePath}`));
    console.log(chalk.blue(`   CSV Report: ${csvFilePath}`));
    console.log(chalk.blue(`   CI/CD Report: ${cicdOutputFile}`));
  }
  
  if (report.compliance && !options.quiet) {
    console.log(chalk.cyan(`\n🏆 Compliance Score: ${report.compliance.overallScore}% (${report.compliance.framework})`));
  }
  
  if (!options.cicdMode || !options.quiet) {
    console.log(chalk.yellow(`\n📊 Summary:`));
    console.log(chalk.red(`   Critical Issues: ${report.summary.criticalIssues}`));
    console.log(chalk.yellow(`   High Severity Issues: ${report.summary.highSeverityIssues}`));
    console.log(chalk.blue(`   Medium Severity Issues: ${report.summary.mediumSeverityIssues}`));
    console.log(chalk.green(`   Low Severity Issues: ${report.summary.lowSeverityIssues}`));
  }

  // Try to open HTML report in default browser
  try {
    if (process.platform === 'darwin') { // macOS
      require('child_process').exec(`open ${htmlFilePath}`);
    } else if (process.platform === 'win32') { // Windows
      require('child_process').exec(`start ${htmlFilePath}`);
    } else { // Linux
      // Check if xdg-open is available
      const { execSync } = require('child_process');
      try {
        execSync('which xdg-open');
        require('child_process').exec(`xdg-open ${htmlFilePath}`);
      } catch (error) {
        console.log(chalk.yellow('\nNote: Unable to open report automatically.'));
        console.log(chalk.yellow('To open the report, you can:'));
        console.log(chalk.blue('1. Install xdg-utils:'));
        console.log(chalk.gray('   sudo apt-get install xdg-utils'));
        console.log(chalk.blue('2. Or open manually with your browser:'));
        console.log(chalk.gray(`   firefox ${htmlFilePath}`));
        console.log(chalk.gray(`   google-chrome ${htmlFilePath}`));
        console.log(chalk.gray(`   Or navigate to the file in your file manager:\n   ${process.cwd()}/${htmlFilePath}`));
      }
    }
  } catch (error) {
    console.log(chalk.yellow('\nNote: HTML report generated but couldn\'t open automatically.'));
    console.log(chalk.yellow('You can open it manually at:'));
    console.log(chalk.blue(`${process.cwd()}/${htmlFilePath}`));
  }

  // Return analysis for CI/CD integration
  return analysis;

}

