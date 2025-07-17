# IAMGuard

A command-line tool for scanning and analyzing AWS IAM configurations for security risks.

## Features

- 🔍 **Policy Analysis**: Scan IAM policies for dangerous permissions and security risks
- 👥 **User Security**: Check IAM users for inactive accounts, MFA status, and access patterns
- 🔐 **Role Assessment**: Analyze IAM roles for overly permissive trust relationships
- 🔑 **Access Key Management**: Monitor access key age and rotation compliance
- 🛡️ **MFA Enforcement**: Identify users without multi-factor authentication
- 📋 **Compliance Checks**: CIS AWS Foundations Benchmark compliance validation
- 📊 **Multi-Format Reports**: Generate JSON, HTML, and CSV security reports
- 🏢 **Multi-Account Support**: Scan across different AWS accounts and regions
- ⚡ **Rate Limiting**: Built-in AWS API rate limiting and retry logic
- 🎯 **Configurable Thresholds**: Customize security thresholds via configuration

## Prerequisites

- Node.js 14 or higher
- AWS credentials configured
- AWS IAM permissions to read IAM configurations

## Installation

```bash
npm install -g iamguard
```

## Usage

### CLI Commands

```bash
# Scan IAM policies
iamguard scan

# Check IAM users
iamguard check-users

# Check IAM roles
iamguard check-roles

# Check password policy
iamguard check-password-policy

# Generate comprehensive report
iamguard generate-report

# Generate report with minimal output
iamguard generate-report -q
```

### Quick Start Commands (NPM Scripts)

For development and quick access, use these npm scripts:

```bash
# Quick security scan with minimal output
npm run scan:quick

# Full comprehensive security report
npm run scan:full

# CI/CD optimized scans
npm run scan:cicd        # CI/CD mode with exit codes
npm run scan:cicd-strict # Strict mode (fail on critical + high)

# Check specific components
npm run check:users    # Analyze IAM users
npm run check:roles    # Analyze IAM roles  
npm run check:policies # Analyze IAM policies

# Development commands
npm run lint          # Run ESLint code quality checks
npm start            # Run the main CLI tool
```

## Configuration

### AWS Credentials

Make sure you have AWS credentials configured either through:

- AWS CLI (`aws configure`)
- Environment variables:
   - AWS_ACCESS_KEY_ID
   - AWS_SECRET_ACCESS_KEY
   - AWS_REGION
- IAM roles (when running on EC2)
- AWS SSO profiles

### Scanner Configuration

Copy `.env.example` to `.env` and customize settings:

```bash
cp .env.example .env
```

Key configuration options:
- `IAM_INACTIVE_DAYS_THRESHOLD`: Days before marking users as inactive (default: 30)
- `IAM_ACCESS_KEY_AGE_THRESHOLD`: Days before flagging old access keys (default: 90)
- `IAM_MAX_CONCURRENT_REQUESTS`: API rate limiting (default: 10)
- `IAM_COMPLIANCE_FRAMEWORK`: Compliance framework to use (CIS, NIST, SOC2)

## CI/CD Integration

IAMGuard is designed to work seamlessly in CI/CD pipelines with configurable exit codes and failure thresholds.

### CI/CD Mode

Enable CI/CD mode for automated security gates:

```bash
# Basic CI/CD scan with exit codes
iamguard generate-report --cicd

# Fail on critical issues only
iamguard generate-report --cicd --fail-on-critical

# Fail on high severity issues
iamguard generate-report --cicd --fail-on-high

# Set custom thresholds
iamguard generate-report --cicd --max-medium 5 --max-low 20
```

### Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | Success - No blocking security issues |
| 1 | Critical security issues found |
| 2 | High severity issues found |
| 3 | Too many medium severity issues |
| 4 | Too many low severity issues |

### Environment Variables for CI/CD

```bash
# Failure thresholds
export IAM_FAIL_ON_CRITICAL=true
export IAM_FAIL_ON_HIGH=false
export IAM_MAX_MEDIUM_ISSUES=10
export IAM_MAX_LOW_ISSUES=50

# CI/CD behavior
export IAM_ENABLE_EXIT_CODES=true
export IAM_SUPPRESS_BANNER=true
```

### GitHub Actions Example

```yaml
name: IAM Security Scan
on: [push, pull_request]

jobs:
  iam-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install IAMGuard
        run: npm install -g iamguard
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Run IAM Security Scan
        run: iamguard generate-report --cicd --fail-on-critical
        env:
          IAM_MAX_MEDIUM_ISSUES: 5
          IAM_SUPPRESS_BANNER: true
      
      - name: Upload Security Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: iam-security-report
          path: iam_*.json
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    
    environment {
        IAM_FAIL_ON_CRITICAL = 'true'
        IAM_MAX_MEDIUM_ISSUES = '10'
        IAM_SUPPRESS_BANNER = 'true'
    }
    
    stages {
        stage('IAM Security Scan') {
            steps {
                script {
                    sh 'npm install -g iamguard'
                    
                    withCredentials([
                        string(credentialsId: 'aws-access-key', variable: 'AWS_ACCESS_KEY_ID'),
                        string(credentialsId: 'aws-secret-key', variable: 'AWS_SECRET_ACCESS_KEY')
                    ]) {
                        def exitCode = sh(
                            script: 'iamguard generate-report --cicd --quiet',
                            returnStatus: true
                        )
                        
                        if (exitCode == 1) {
                            error("Critical IAM security issues found!")
                        } else if (exitCode > 0) {
                            unstable("IAM security issues detected (exit code: ${exitCode})")
                        }
                    }
                    
                    archiveArtifacts artifacts: 'iam_*.json'
                }
            }
        }
    }
}
```

### GitLab CI Example

```yaml
iam-security-scan:
  image: node:18
  stage: security
  variables:
    IAM_FAIL_ON_CRITICAL: "true"
    IAM_MAX_MEDIUM_ISSUES: "5"
    IAM_SUPPRESS_BANNER: "true"
  before_script:
    - npm install -g iamguard
  script:
    - iamguard generate-report --cicd --quiet
  artifacts:
    when: always
    reports:
      junit: iam_cicd_result_*.json
    paths:
      - iam_*.json
  only:
    - main
    - develop
```

### Environment-Specific Configuration

**Development Environment:**
```bash
export IAM_FAIL_ON_CRITICAL=false
export IAM_FAIL_ON_HIGH=false
export IAM_MAX_MEDIUM_ISSUES=20
```

**Staging Environment:**
```bash
export IAM_FAIL_ON_CRITICAL=true
export IAM_FAIL_ON_HIGH=false
export IAM_MAX_MEDIUM_ISSUES=10
```

**Production Environment:**
```bash
export IAM_FAIL_ON_CRITICAL=true
export IAM_FAIL_ON_HIGH=true
export IAM_MAX_MEDIUM_ISSUES=5
```

## Required IAM Permissions

The following IAM permissions are required:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountPasswordPolicy",
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListPolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:ListAttachedUserPolicies",
                "iam:ListAccessKeys",
                "iam:ListMFADevices",
                "iam:GetLoginProfile",
                "iam:GetRole",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

##  License

[MIT License](./LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.