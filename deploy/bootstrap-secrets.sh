#!/usr/bin/env bash
# Two database passwords as SSM SecureStrings: the master (used only to run
# migrations) and the one the application logs in with. Run once, before the
# first deploy.
set -euo pipefail

PREFIX="${SECRET_PREFIX:-/tenant-isolation}"
REGION="${AWS_REGION:-us-west-2}"

put() {
  aws ssm put-parameter --name "$1" --value "$2" --type SecureString \
    --overwrite --region "$REGION" >/dev/null
  echo "wrote $1"
}

# RDS rejects '/', '@', '"' and spaces in master passwords.
gen() { head -c 48 /dev/urandom | base64 | tr -d '/@" =+' | head -c 32; }

put "${PREFIX}/db-password" "$(gen)"
put "${PREFIX}/app-db-password" "$(gen)"
