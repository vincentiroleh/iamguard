import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import chalk from 'chalk';

export async function checkAwsCredentials() {
    try {
        const sts = new STSClient({ region: process.env.AWS_REGION });
        await sts.send(new GetCallerIdentityCommand({}));
        return true;
    } catch (error) {
        console.error(chalk.red('AWS credentials are not properly configured'));
        console.log(chalk.yellow('Please configure your AWS credentials:'));
        console.log('  • AWS_ACCESS_KEY_ID');
        console.log('  • AWS_SECRET_ACCESS_KEY');
        console.log('  • AWS_REGION');
        console.log(chalk.red(`Detailed error: ${error.message}`));
        throw new Error('Invalid AWS credentials');
    }
}

export function handleError(error) {
    if (error.name === 'CredentialsError') {
        console.error(chalk.red('AWS credentials not found or invalid'));
    } else if (error.name === 'AccessDenied') {
        console.error(chalk.red('Insufficient permissions to perform IAM operations'));
    } else {
        console.error(chalk.red(`Error: ${error.message}`));
    }
    process.exit(1);
}

