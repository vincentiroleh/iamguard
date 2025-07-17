// Security rules and compliance checks
export const SECURITY_RULES = {
  // CIS AWS Foundations Benchmark rules
  CIS: {
    '1.3': {
      name: 'Ensure credentials unused for 90 days or greater are disabled',
      check: (user) => {
        const daysSinceLastUsed = calculateDaysSince(user.PasswordLastUsed);
        return daysSinceLastUsed > 90;
      },
      severity: 'HIGH'
    },
    '1.4': {
      name: 'Ensure access keys are rotated every 90 days',
      check: (accessKey) => {
        const keyAge = calculateDaysSince(accessKey.CreateDate);
        return keyAge > 90;
      },
      severity: 'HIGH'
    },
    '1.8': {
      name: 'Ensure IAM password policy requires minimum length of 14 or greater',
      check: (passwordPolicy) => {
        return passwordPolicy.MinimumPasswordLength < 14;
      },
      severity: 'MEDIUM'
    }
  },

  // NIST guidelines
  NIST: {
    'AC-2': {
      name: 'Account Management - Remove inactive accounts',
      check: (user) => {
        const daysSinceLastUsed = calculateDaysSince(user.PasswordLastUsed);
        return daysSinceLastUsed > 30;
      },
      severity: 'MEDIUM'
    }
  }
};

export const DANGEROUS_ACTIONS = [
  '*',
  'iam:*',
  'organizations:*',
  's3:*',
  'lambda:*',
  'ec2:*',
  'rds:*',
  'dynamodb:*',
  'cloudformation:*',
  'sts:AssumeRole'
];

export const SENSITIVE_RESOURCES = [
  '*',
  'arn:aws:iam::*:root',
  'arn:aws:s3:::*/*'
];

function calculateDaysSince(date) {
  if (!date) return null;
  return Math.floor((Date.now() - new Date(date).getTime()) / (1000 * 60 * 60 * 24));
}

export function evaluateCompliance(findings, framework = 'CIS') {
  const rules = SECURITY_RULES[framework] || {};
  const complianceResults = [];

  Object.entries(rules).forEach(([ruleId, rule]) => {
    const applicableFindings = findings.filter(finding => {
      try {
        return rule.check(finding);
      } catch (error) {
        return false;
      }
    });

    complianceResults.push({
      ruleId,
      ruleName: rule.name,
      severity: rule.severity,
      compliant: applicableFindings.length === 0,
      affectedResources: applicableFindings.length,
      framework
    });
  });

  return complianceResults;
}