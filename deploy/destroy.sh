#!/usr/bin/env bash
set -euo pipefail
STACK="${STACK_NAME:-TenantIsolation}"
REGION="${AWS_REGION:-us-west-2}"
PREFIX="${SECRET_PREFIX:-/tenant-isolation}"

BUCKET=$(aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue" --output text 2>/dev/null || true)
if [ -n "${BUCKET:-}" ] && [ "$BUCKET" != "None" ]; then
  echo "emptying s3://${BUCKET}"
  aws s3 rm "s3://${BUCKET}" --recursive --region "$REGION" >/dev/null || true
fi

(cd "$(dirname "$0")/../infra" && npx cdk destroy "$STACK" --force)

aws ssm delete-parameters --names "${PREFIX}/db-password" "${PREFIX}/app-db-password" \
  --region "$REGION" >/dev/null || true

echo
echo "remaining in ${REGION}:"
echo "  RDS instances: $(aws rds describe-db-instances --region "$REGION" --query 'length(DBInstances)' --output text)"
echo "  ECS clusters:  $(aws ecs list-clusters --region "$REGION" --query 'length(clusterArns)' --output text)"
echo "  KMS keys pending deletion have a 7 day window; check with:"
echo "    aws kms list-keys --region $REGION"
