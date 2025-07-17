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
                "iam:GetPolicyVersion"
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