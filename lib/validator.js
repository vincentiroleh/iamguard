import chalk from 'chalk';

export class ConfigValidator {
  static validateThresholds(config) {
    const errors = [];
    
    if (config.thresholds) {
      if (config.thresholds.inactiveDays < 1 || config.thresholds.inactiveDays > 365) {
        errors.push('inactiveDays must be between 1 and 365');
      }
      
      if (config.thresholds.accessKeyAge < 30 || config.thresholds.accessKeyAge > 365) {
        errors.push('accessKeyAge must be between 30 and 365');
      }
      
      if (config.thresholds.passwordMinLength < 8 || config.thresholds.passwordMinLength > 128) {
        errors.push('passwordMinLength must be between 8 and 128');
      }
    }
    
    return errors;
  }

  static validateScanningConfig(config) {
    const errors = [];
    
    if (config.scanning) {
      if (config.scanning.maxConcurrentRequests < 1 || config.scanning.maxConcurrentRequests > 50) {
        errors.push('maxConcurrentRequests must be between 1 and 50');
      }
      
      if (config.scanning.retryAttempts < 0 || config.scanning.retryAttempts > 10) {
        errors.push('retryAttempts must be between 0 and 10');
      }
      
      if (config.scanning.timeout < 5000 || config.scanning.timeout > 300000) {
        errors.push('timeout must be between 5000ms and 300000ms');
      }
    }
    
    return errors;
  }

  static validate(config) {
    const errors = [
      ...this.validateThresholds(config),
      ...this.validateScanningConfig(config)
    ];
    
    if (errors.length > 0) {
      console.error(chalk.red('❌ Configuration validation errors:'));
      errors.forEach(error => console.error(chalk.red(`   - ${error}`)));
      throw new Error('Invalid configuration');
    }
    
    console.log(chalk.green('✅ Configuration validated successfully'));
    return true;
  }
}

export class PermissionValidator {
  static requiredPermissions = [
    'iam:GetAccountPasswordPolicy',
    'iam:ListUsers',
    'iam:ListRoles', 
    'iam:ListPolicies',
    'iam:GetPolicy',
    'iam:GetPolicyVersion',
    'iam:ListAttachedUserPolicies',
    'iam:ListAccessKeys',
    'iam:ListMFADevices',
    'iam:GetLoginProfile',
    'iam:GetRole',
    'sts:GetCallerIdentity'
  ];

  static async validatePermissions(iamClient, stsClient) {
    console.log(chalk.blue('🔐 Validating IAM permissions...'));
    
    const missingPermissions = [];
    
    // Test basic permissions by trying actual calls
    try {
      await stsClient.send(new GetCallerIdentityCommand({}));
    } catch (error) {
      missingPermissions.push('sts:GetCallerIdentity');
    }
    
    try {
      await iamClient.send(new ListUsersCommand({ MaxItems: 1 }));
    } catch (error) {
      if (error.name === 'AccessDenied') {
        missingPermissions.push('iam:ListUsers');
      }
    }
    
    if (missingPermissions.length > 0) {
      console.warn(chalk.yellow('⚠️ Some permissions may be missing:'));
      missingPermissions.forEach(perm => console.warn(chalk.yellow(`   - ${perm}`)));
      console.warn(chalk.yellow('This may affect scan completeness.'));
    } else {
      console.log(chalk.green('✅ Basic permissions validated'));
    }
    
    return missingPermissions;
  }
}