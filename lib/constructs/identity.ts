import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cognito from 'aws-cdk-lib/aws-cognito';

export interface WorkforceIdentityProps {
  readonly slug: string;
  readonly workloadName: string;
  readonly allowedOrigins: string[];
}

/**
 * Workforce / patient identity with the controls the HIPAA Security Rule NPRM would make mandatory:
 * MFA for every user, strong passwords, adaptive threat protection (compromised-credential and
 * risk-based blocking), and short-lived sessions that implement "automatic logoff" (§164.312(a)(2)(iii)).
 */
export class WorkforceIdentity extends Construct {
  public readonly userPool: cognito.UserPool;
  public readonly client: cognito.UserPoolClient;

  constructor(scope: Construct, id: string, props: WorkforceIdentityProps) {
    super(scope, id);

    this.userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: `${props.slug}-${props.workloadName}`,
      selfSignUpEnabled: false, // staff/patient accounts are provisioned by the organization
      signInAliases: { email: true },
      signInCaseSensitive: false,
      autoVerify: { email: true },
      mfa: cognito.Mfa.REQUIRED,
      mfaSecondFactor: { sms: false, otp: true }, // TOTP only; SMS is phishable/SIM-swappable
      passwordPolicy: {
        minLength: 14,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
        tempPasswordValidity: cdk.Duration.days(3),
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      // Plus feature plan enables threat protection (adaptive auth, compromised-credentials blocking).
      featurePlan: cognito.FeaturePlan.PLUS,
      standardThreatProtectionMode: cognito.StandardThreatProtectionMode.FULL_FUNCTION,
      deletionProtection: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.client = this.userPool.addClient('WebClient', {
      userPoolClientName: `${props.workloadName}-web`,
      authFlows: { userSrp: true },
      generateSecret: false,
      preventUserExistenceErrors: true,
      enableTokenRevocation: true,
      // Automatic logoff: access/ID tokens expire after 30 minutes; refresh after an 8-hour shift.
      accessTokenValidity: cdk.Duration.minutes(30),
      idTokenValidity: cdk.Duration.minutes(30),
      refreshTokenValidity: cdk.Duration.hours(8),
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
        callbackUrls: props.allowedOrigins.length ? props.allowedOrigins : ['https://localhost'],
        logoutUrls: props.allowedOrigins.length ? props.allowedOrigins : ['https://localhost'],
      },
    });

    new cdk.CfnOutput(this, 'UserPoolId', { value: this.userPool.userPoolId });
    new cdk.CfnOutput(this, 'UserPoolClientId', { value: this.client.userPoolClientId });
  }
}
