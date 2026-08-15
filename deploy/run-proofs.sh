#!/usr/bin/env bash
# Runs the proof suite as a one-off Fargate task and prints its output.
set -euo pipefail

STACK="${STACK_NAME:-TenantIsolation}"
REGION="${AWS_REGION:-us-west-2}"

out() {
  aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text
}

CLUSTER=$(out ClusterName); FAMILY=$(out TaskDefinition)
SUBNETS=$(out PublicSubnets); SG=$(out RunnerSecurityGroup); LOGS=$(out LogGroup)

# A public IP, not a NAT gateway. The task needs to reach ECR and the AWS APIs;
# giving it an address is free and a NAT gateway is $36 a month.
TASK_ARN=$(aws ecs run-task \
  --cluster "$CLUSTER" --task-definition "$FAMILY" --launch-type FARGATE \
  --region "$REGION" \
  --network-configuration "awsvpcConfiguration={subnets=[${SUBNETS}],securityGroups=[${SG}],assignPublicIp=ENABLED}" \
  --query 'tasks[0].taskArn' --output text)

TASK_ID="${TASK_ARN##*/}"
echo "task ${TASK_ID} running..."
aws ecs wait tasks-stopped --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$REGION"

EXIT_CODE=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$REGION" \
  --query 'tasks[0].containers[0].exitCode' --output text)

aws logs get-log-events --log-group-name "$LOGS" --log-stream-name "proofs/proofs/${TASK_ID}" \
  --region "$REGION" --start-from-head --query 'events[].message' --output text \
  | tr '\t' '\n'

echo
echo "exit code ${EXIT_CODE}"
[ "$EXIT_CODE" = "0" ]
