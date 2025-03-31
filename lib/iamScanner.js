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
  GetAccountPasswordPolicyCommand
} from "@aws-sdk/client-iam";
import chalk from "chalk";

// Initialize AWS IAM client
const iamClient = new IAMClient();

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
  passwordPolicyIssues: []
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
 * Enhanced IAM Users check with additional security controls
 */
export async function checkIamUsers() {
  console.log("\n🔍 Checking IAM Users for Security Risks...");

  try {
    const { Users } = await iamClient.send(new ListUsersCommand({}));
    if (!Users || Users.length === 0) {
      console.log("✅ No IAM users found.");
      return;
    }

    for (const user of Users) {
      const userName = user.UserName;
      console.log(`🔹 Checking user: ${userName}`);

      await checkAdministratorAccess(userName);
      await checkAccessKeys(userName);

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
    console.error(chalk.red("❌ Error checking IAM users:"), error);
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
 * Enhanced security report generation with more details and formatting
 */
export function generateSecurityReport() {
  const report = {
    scanDate: new Date().toISOString(),
    findings: securityFindings,
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

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filePath = `iam_security_report_${timestamp}.json`;
  fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
  
  console.log(chalk.green(`\n✅ Security Report Generated: ${filePath}`));
  console.log(chalk.yellow(`📊 Summary:`));
  console.log(chalk.red(`   Critical Issues: ${report.summary.criticalIssues}`));
  console.log(chalk.yellow(`   High Severity Issues: ${report.summary.highSeverityIssues}`));
  console.log(chalk.blue(`   Medium Severity Issues: ${report.summary.mediumSeverityIssues}`));
  console.log(chalk.green(`   Low Severity Issues: ${report.summary.lowSeverityIssues}`));
}
