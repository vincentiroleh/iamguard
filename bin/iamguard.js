#!/usr/bin/env node

import { Command } from "commander";
import chalk from "chalk";
import {
  fetchIamPolicies,
  analyzeIamPolicies,
  checkIamUsers,
  checkIamRoles,
  checkPasswordPolicy,
  generateSecurityReport,
  getAccountInfo
} from "../lib/iamScanner.js";
import { checkAwsCredentials, handleError } from './utils.js';
import { spinner } from './spinner.js';
import { CICDHandler } from '../lib/cicdHandler.js';

const program = new Command();

// Read version from package.json
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJson = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf8'));
const VERSION = packageJson.version;

const banner = `
╔═══════════════════════════════════════╗
║             IAM Guard                  ║
║       Security Scan Tool v${VERSION}        ║
╚═══════════════════════════════════════╝
`;

try {
  program
    .name("iamguard")
    .description(chalk.cyan(banner))
    .version(VERSION);

  program
    .command("scan")
    .description("Scan IAM policies for security risks")
    .option("-q, --quiet", "Suppress detailed output")
    .action(async (options) => {
      try {
        if (!options.quiet) {
          console.log(chalk.cyan(banner));
        }

        // Check AWS credentials
        const credentialsSpinner = spinner.start('Checking AWS credentials...');
        await checkAwsCredentials();
        spinner.succeed(credentialsSpinner, 'AWS credentials verified');

        const scanSpinner = spinner.start('Starting IAM security scan...');
        const startTime = Date.now();
        const policies = await fetchIamPolicies();

        if (policies.length === 0) {
          spinner.info(scanSpinner, "⚠️ No IAM policies found.");
          return;
        }

        spinner.succeed(scanSpinner, 'Policies fetched, analyzing...');
        
        const analysisSpinner = spinner.start('Analyzing IAM policies...');
        await analyzeIamPolicies(policies);
        
        const duration = ((Date.now() - startTime) / 1000).toFixed(2);
        spinner.succeed(analysisSpinner, `✅ Scan completed in ${duration} seconds`);
      } catch (error) {
        spinner.fail(scanSpinner, "Error during policy scan");
        console.error(chalk.red(error.message));
        process.exit(1);
      }
    });

  program
    .command("check-users")
    .description("Check IAM users for security risks")
    .option("-q, --quiet", "Suppress detailed output")
    .action(async (options) => {
      try {
        if (!options.quiet) {
          console.log(chalk.cyan(banner));
        }

        // Check AWS credentials
        const credentialsSpinner = spinner.start('Checking AWS credentials...');
        await checkAwsCredentials();
        spinner.succeed(credentialsSpinner, 'AWS credentials verified');

        const userSpinner = spinner.start('Checking IAM users...');
        const startTime = Date.now();
        
        await checkIamUsers();
        
        const duration = ((Date.now() - startTime) / 1000).toFixed(2);
        spinner.succeed(userSpinner, `✅ User check completed in ${duration} seconds`);
      } catch (error) {
        spinner.fail(userSpinner, "Error during user check");
        console.error(chalk.red(error.message));
        process.exit(1);
      }
    });

  program
    .command("check-roles")
    .description("Check IAM roles for security risks")
    .option("-q, --quiet", "Suppress detailed output")
    .action(async (options) => {
      try {
        if (!options.quiet) {
          console.log(chalk.cyan(banner));
        }

        // Check AWS credentials
        const credentialsSpinner = spinner.start('Checking AWS credentials...');
        await checkAwsCredentials();
        spinner.succeed(credentialsSpinner, 'AWS credentials verified');

        const roleSpinner = spinner.start('Checking IAM roles...');
        const startTime = Date.now();
        
        await checkIamRoles();
        
        const duration = ((Date.now() - startTime) / 1000).toFixed(2);
        spinner.succeed(roleSpinner, `✅ Role check completed in ${duration} seconds`);
      } catch (error) {
        spinner.fail(roleSpinner, "Error during role check");
        console.error(chalk.red(error.message));
        process.exit(1);
      }
    });

  program
    .command("check-password-policy")
    .description("Check IAM password policy configuration")
    .option("-q, --quiet", "Suppress detailed output")
    .action(async (options) => {
      try {
        if (!options.quiet) {
          console.log(chalk.cyan(banner));
        }

        // Check AWS credentials
        const credentialsSpinner = spinner.start('Checking AWS credentials...');
        await checkAwsCredentials();
        spinner.succeed(credentialsSpinner, 'AWS credentials verified');

        const policySpinner = spinner.start('Checking IAM password policy...');
        const startTime = Date.now();
        
        await checkPasswordPolicy();
        
        const duration = ((Date.now() - startTime) / 1000).toFixed(2);
        spinner.succeed(policySpinner, `✅ Password policy check completed in ${duration} seconds`);
      } catch (error) {
        spinner.fail(policySpinner, "Error checking password policy");
        console.error(chalk.red(error.message));
        process.exit(1);
      }
    });

  program
    .command("generate-report")
    .description("Run all checks and generate a comprehensive security report")
    .option("-q, --quiet", "Suppress detailed output")
    .option("-f, --format <type>", "Output format (json)", "json")
    .option("--cicd", "Enable CI/CD mode with exit codes")
    .option("--fail-on-critical", "Exit with code 1 on critical issues")
    .option("--fail-on-high", "Exit with code 2 on high severity issues")
    .option("--max-medium <number>", "Maximum allowed medium severity issues", "10")
    .option("--max-low <number>", "Maximum allowed low severity issues", "50")
    .action(async (options) => {
      try {
        if (!options.quiet) {
          console.log(chalk.cyan(banner));
        }

        // Check AWS credentials
        const credentialsSpinner = spinner.start('Checking AWS credentials...');
        await checkAwsCredentials();
        spinner.succeed(credentialsSpinner, 'AWS credentials verified');

        const reportSpinner = spinner.start('Starting comprehensive IAM security scan...');
        const startTime = Date.now();
        let success = true;
        let accountInfo = null;

        try {
          spinner.info(reportSpinner, 'Getting account information...');
          accountInfo = await getAccountInfo();
        } catch (error) {
          console.warn(chalk.yellow('Warning: Could not retrieve account information'));
        }

        try {
          spinner.info(reportSpinner, 'Fetching and analyzing IAM policies...');
          const policies = await fetchIamPolicies();
          await analyzeIamPolicies(policies);
        } catch (error) {
          success = false;
          spinner.fail(reportSpinner, "Error during policy scan");
          console.error(chalk.red(error.message));
        }

        try {
          spinner.info(reportSpinner, 'Checking IAM users...');
          await checkIamUsers();
        } catch (error) {
          success = false;
          spinner.fail(reportSpinner, "Error during user check");
          console.error(chalk.red(error.message));
        }

        try {
          spinner.info(reportSpinner, 'Checking IAM roles...');
          await checkIamRoles();
        } catch (error) {
          success = false;
          spinner.fail(reportSpinner, "Error during role check");
          console.error(chalk.red(error.message));
        }

        try {
          spinner.info(reportSpinner, 'Checking password policy...');
          await checkPasswordPolicy();
        } catch (error) {
          success = false;
          spinner.fail(reportSpinner, "Error during password policy check");
          console.error(chalk.red(error.message));
        }

        spinner.info(reportSpinner, 'Generating security report...');
        
        // Configure CI/CD options
        const cicdConfig = {
          failOnCritical: options.failOnCritical || options.cicd,
          failOnHigh: options.failOnHigh,
          maxMediumIssues: parseInt(options.maxMedium),
          maxLowIssues: parseInt(options.maxLow),
          enableExitCodes: options.cicd,
          suppressBanner: options.cicd && options.quiet
        };

        const reportOptions = {
          cicdMode: options.cicd,
          cicdConfig: cicdConfig,
          quiet: options.quiet
        };

        const analysis = await generateSecurityReport(accountInfo, reportOptions);

        const duration = ((Date.now() - startTime) / 1000).toFixed(2);

        if (success) {
          spinner.succeed(reportSpinner, `✅ Security scan completed successfully in ${duration} seconds`);
        } else {
          spinner.warn(reportSpinner, `⚠️ Security scan completed with some errors in ${duration} seconds`);
        }

        // Handle CI/CD exit codes
        if (options.cicd && analysis) {
          const cicdHandler = new CICDHandler(cicdConfig);
          cicdHandler.handleExit(analysis);
        } else if (!success) {
          process.exit(1);
        }
      } catch (error) {
        spinner.fail(reportSpinner, "Error generating security report");
        console.error(chalk.red(error.message));
        process.exit(1);
      }
    });

  program.addHelpText('after', `
  Examples:
    $ iamguard scan                    # Scan IAM policies
    $ iamguard check-users             # Check IAM users
    $ iamguard check-roles             # Check IAM roles
    $ iamguard check-password-policy   # Check password policy
    $ iamguard generate-report         # Generate comprehensive report
    $ iamguard generate-report -q      # Generate report with minimal output
  `);

  program.parse(process.argv);

  if (!process.argv.slice(2).length) {
    program.outputHelp();
  }

} catch (error) {
  handleError(error);
}
