import * as path from 'node:path';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as ecrAssets from 'aws-cdk-lib/aws-ecr-assets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as ssm from 'aws-cdk-lib/aws-ssm';

export interface TenantIsolationStackProps extends cdk.StackProps {
  readonly secretPrefix: string;
}

export class TenantIsolationStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: TenantIsolationStackProps) {
    super(scope, id, props);

    // No NAT gateway anywhere in this stack. The database sits in isolated
    // subnets with no route out, and the one thing that needs the internet (the
    // proof runner, to pull its image from ECR) gets a public IP in a public
    // subnet instead. That is $0/month rather than $36.
    const vpc = new ec2.Vpc(this, 'Vpc', {
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [
        { name: 'public', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
        { name: 'data', subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 26 },
      ],
    });

    // ============================================================ shared data
    //
    // One bucket, one table, one key, one database. Every tenant's data lives
    // in the same place. That is the pooled model, and it is what makes
    // isolation a security problem rather than an accounting one.

    const bucket = new s3.Bucket(this, 'TenantData', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const table = new dynamodb.TableV2(this, 'TenantItems', {
      partitionKey: { name: 'tenant', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billing: dynamodb.Billing.onDemand(),
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const key = new kms.Key(this, 'TenantKey', {
      description: 'Per-tenant envelope encryption, scoped by encryption context',
      enableKeyRotation: false,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pendingWindow: cdk.Duration.days(7),
    });

    const dbPassword = cdk.SecretValue.ssmSecure(`${props.secretPrefix}/db-password`);
    const dbPasswordParam = ssm.StringParameter.fromSecureStringParameterAttributes(this, 'DbPassword', {
      parameterName: `${props.secretPrefix}/db-password`,
    });
    const appDbPasswordParam = ssm.StringParameter.fromSecureStringParameterAttributes(this, 'AppDbPassword', {
      parameterName: `${props.secretPrefix}/app-db-password`,
    });

    const database = new rds.DatabaseInstance(this, 'Database', {
      engine: rds.DatabaseInstanceEngine.postgres({
        version: rds.PostgresEngineVersion.of('18.4', '18'),
      }),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE4_GRAVITON, ec2.InstanceSize.MICRO),
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      credentials: rds.Credentials.fromPassword('dbmaster', dbPassword),
      // 'isolation' is a reserved word in the RDS PostgreSQL engine and the
      // create fails on it, which is a fun thing to find out ten minutes in.
      databaseName: 'tenancy',
      allocatedStorage: 20,
      storageEncrypted: true,
      publiclyAccessible: false,
      multiAz: false,
      backupRetention: cdk.Duration.days(0),
      deleteAutomatedBackups: true,
      deletionProtection: false,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ====================================================== the proof runner
    //
    // A one-off Fargate task that holds credentials for nothing except the
    // right to become a tenant. It is the stand-in for your application server.
    const cluster = new ecs.Cluster(this, 'Cluster', { vpc });

    const runnerLogs = new logs.LogGroup(this, 'RunnerLogs', {
      logGroupName: `/ecs/${cdk.Stack.of(this).stackName}/proofs`,
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const runnerTaskRole = new iam.Role(this, 'RunnerTaskRole', {
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      description: 'The application server identity: can vend tenant credentials, nothing else',
    });

    // ================================================== the ABAC tenant role
    //
    // One role for every tenant. The tenant is not in the role; it arrives as a
    // session tag and the policies read it back with ${aws:PrincipalTag/tenant}.
    // Add a ten-thousandth tenant and nothing here changes.
    const tenantRole = new iam.Role(this, 'TenantAccessRole', {
      assumedBy: new iam.ArnPrincipal(runnerTaskRole.roleArn),
      maxSessionDuration: cdk.Duration.hours(1),
      description: 'Assumed with a tenant session tag; every policy is scoped by that tag',
    });

    // Assuming the role is not enough. Attaching a session tag is a separate
    // action, and without it the tag never lands, ${aws:PrincipalTag/tenant}
    // never resolves, and the session can reach nothing.
    tenantRole.assumeRolePolicy?.addStatements(
      new iam.PolicyStatement({
        actions: ['sts:TagSession'],
        principals: [new iam.ArnPrincipal(runnerTaskRole.roleArn)],
        conditions: {
          // The tag must be present and must be a plain tenant identifier.
          // A caller cannot assume the role untagged and hope for the best.
          StringLike: { 'aws:RequestTag/tenant': '*' },
        },
      }),
    );

    runnerTaskRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ['sts:AssumeRole', 'sts:TagSession'],
        resources: [tenantRole.roleArn],
      }),
    );

    // Fail closed: if the session somehow has no tenant tag, deny everything.
    // The resource ARNs below would not match anyway, but stating it makes the
    // intent reviewable instead of implied.
    const mustBeTagged = new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['s3:*', 'dynamodb:*', 'kms:*'],
      resources: ['*'],
      conditions: { Null: { 'aws:PrincipalTag/tenant': 'true' } },
    });

    // --- S3 -----------------------------------------------------------------
    //
    // Two statements, because S3 splits the permission in two. Object actions
    // are scoped by putting the tag inside the resource ARN. Listing is an
    // action on the bucket, not on an object, so the ARN cannot carry the
    // tenant and the scoping has to come from the s3:prefix condition instead.
    //
    // Grant ListBucket without that condition and a tenant cannot read anyone
    // else's files but can enumerate every filename in the system.
    const s3Objects = new iam.PolicyStatement({
      actions: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
      resources: [`${bucket.bucketArn}/\${aws:PrincipalTag/tenant}/*`],
    });

    const s3List = new iam.PolicyStatement({
      actions: ['s3:ListBucket'],
      resources: [bucket.bucketArn],
      conditions: {
        StringLike: { 's3:prefix': ['${aws:PrincipalTag/tenant}/*'] },
      },
    });

    // --- DynamoDB -----------------------------------------------------------
    //
    // dynamodb:LeadingKeys constrains the partition key of every item the
    // request touches. Note what is absent: Scan. A Scan reads across
    // partitions, so LeadingKeys cannot constrain it, and the only safe answer
    // is to not grant it.
    const ddb = new iam.PolicyStatement({
      actions: [
        'dynamodb:GetItem',
        'dynamodb:BatchGetItem',
        'dynamodb:PutItem',
        'dynamodb:UpdateItem',
        'dynamodb:DeleteItem',
        'dynamodb:Query',
      ],
      resources: [table.tableArn],
      conditions: {
        'ForAllValues:StringEquals': {
          'dynamodb:LeadingKeys': ['${aws:PrincipalTag/tenant}'],
        },
      },
    });

    // --- KMS ----------------------------------------------------------------
    //
    // The encryption context is authenticated additional data: it is bound into
    // the ciphertext at encrypt time and cannot be changed afterwards. Pinning
    // it to the principal tag means a tenant holding another tenant's ciphertext
    // still cannot read it, because it can only ask KMS to decrypt under its own
    // context and the ciphertext will not match.
    const kmsUse = new iam.PolicyStatement({
      actions: ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey'],
      resources: [key.keyArn],
      conditions: {
        StringEquals: { 'kms:EncryptionContext:tenant': '${aws:PrincipalTag/tenant}' },
      },
    });

    for (const statement of [mustBeTagged, s3Objects, s3List, ddb, kmsUse]) {
      tenantRole.addToPolicy(statement);
    }

    // A KMS key policy is not optional the way an S3 bucket policy is: without
    // an entry here, an identity policy granting kms:Decrypt does nothing.
    key.addToResourcePolicy(
      new iam.PolicyStatement({
        principals: [new iam.ArnPrincipal(tenantRole.roleArn)],
        actions: ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey'],
        resources: ['*'],
        conditions: {
          StringEquals: { 'kms:EncryptionContext:tenant': '${aws:PrincipalTag/tenant}' },
        },
      }),
    );

    // --- the runner's own task definition -----------------------------------
    const image = new ecrAssets.DockerImageAsset(this, 'ProofsImage', {
      directory: path.join(__dirname, '..', '..', 'proofs'),
      platform: ecrAssets.Platform.LINUX_ARM64,
    });

    const executionRole = new iam.Role(this, 'ExecutionRole', {
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonECSTaskExecutionRolePolicy'),
      ],
    });
    dbPasswordParam.grantRead(executionRole);
    appDbPasswordParam.grantRead(executionRole);

    const taskDefinition = new ecs.FargateTaskDefinition(this, 'ProofsTask', {
      cpu: 512,
      memoryLimitMiB: 1024,
      runtimePlatform: {
        cpuArchitecture: ecs.CpuArchitecture.ARM64,
        operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
      },
      executionRole,
      taskRole: runnerTaskRole,
    });

    taskDefinition.addContainer('proofs', {
      image: ecs.ContainerImage.fromDockerImageAsset(image),
      logging: ecs.LogDrivers.awsLogs({ streamPrefix: 'proofs', logGroup: runnerLogs }),
      environment: {
        BUCKET: bucket.bucketName,
        TABLE: table.tableName,
        KMS_KEY_ID: key.keyArn,
        TENANT_ROLE_ARN: tenantRole.roleArn,
        DB_HOST: database.dbInstanceEndpointAddress,
        DB_PORT: database.dbInstanceEndpointPort,
        DB_NAME: 'tenancy',
        DB_MASTER_USER: 'dbmaster',
        AWS_REGION: this.region,
      },
      secrets: {
        DB_MASTER_PASSWORD: ecs.Secret.fromSsmParameter(dbPasswordParam),
        APP_DB_PASSWORD: ecs.Secret.fromSsmParameter(appDbPasswordParam),
      },
    });

    const runnerSg = new ec2.SecurityGroup(this, 'RunnerSg', {
      vpc,
      description: 'Proof runner',
      allowAllOutbound: true,
    });
    database.connections.allowDefaultPortFrom(runnerSg, 'proof runner to PostgreSQL');

    // ---------------------------------------------------------------- outputs
    new cdk.CfnOutput(this, 'ClusterName', { value: cluster.clusterName });
    new cdk.CfnOutput(this, 'TaskDefinition', { value: taskDefinition.family });
    new cdk.CfnOutput(this, 'PublicSubnets', {
      value: vpc.selectSubnets({ subnetType: ec2.SubnetType.PUBLIC }).subnetIds.join(','),
    });
    new cdk.CfnOutput(this, 'RunnerSecurityGroup', { value: runnerSg.securityGroupId });
    new cdk.CfnOutput(this, 'BucketName', { value: bucket.bucketName });
    new cdk.CfnOutput(this, 'TableName', { value: table.tableName });
    new cdk.CfnOutput(this, 'LogGroup', { value: runnerLogs.logGroupName });
  }
}
