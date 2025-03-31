# IAMGuard

A command-line tool for scanning and analyzing AWS IAM configurations for security risks.

## Features

- 🔍 Scan IAM policies for security risks
- 👥 Check IAM users for security best practices
- 🔐 Analyze IAM roles for potential vulnerabilities
- 🔑 Verify password policy compliance
- 📊 Generate comprehensive security reports

## Prerequisites

- Node.js 14 or higher
- AWS credentials configured
- AWS IAM permissions to read IAM configurations

## Installation

```bash
npm install -g iamguard
```

## Usage



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

## AWS Credentials

Make sure you have AWS credentials configured either through:

- AWS CLI ( `aws configure`)

- Environment variables:

   - AWS_ACCESS_KEY_ID
   - AWS_SECRET_ACCESS_KEY
   - AWS_REGION

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