#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { TenantIsolationStack } from '../lib/tenant-isolation-stack';

const app = new cdk.App();

new TenantIsolationStack(app, 'TenantIsolation', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? 'us-west-2',
  },
  secretPrefix: '/tenant-isolation',
  description: 'Tenant isolation enforced by IAM session tags and PostgreSQL row-level security',
});

cdk.Tags.of(app).add('Project', 'multi-tenant-isolation-aws');
cdk.Tags.of(app).add('Owner', process.env.OWNER_TAG ?? 'you@example.com');
