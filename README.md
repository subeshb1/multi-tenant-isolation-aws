# Multi-tenant isolation on AWS

A deployable stack that enforces tenant isolation in the infrastructure rather
than in application code, plus a suite that tries to break it and reports every
attempt.

Four shared resources hold every tenant's data: one S3 bucket, one DynamoDB
table, one KMS key, one PostgreSQL database. Nothing in here is a
`where('tenant_id', $id)`. The isolation is in IAM policies keyed on a session
tag and in PostgreSQL row-level security policies, which means it holds even
when the application is wrong.

Companion code for the blog post
[Tenant isolation on AWS for a multi-tenant SaaS](https://www.subeshbhandari.com/blog/multi-tenant-saas-isolation-on-aws).

## The idea

The usual way to isolate tenants is a filter in the application:

```php
Invoice::where('tenant_id', auth()->user()->tenant_id)->get();
```

This works until someone forgets it. It is one line, it appears in hundreds of
places, and every one of them is load-bearing. Nothing about a missing filter
looks wrong in review, and nothing about it fails in testing, because in
development there is only one tenant.

Push the boundary down instead. Give the request credentials that cannot reach
another tenant, and give the database a policy it applies to every query
whether or not the application asked. Then a forgotten filter returns nothing
instead of returning everything, and a SQL injection returns the attacker's own
rows.

None of this depends on the language. The examples in `laravel/` are PHP
because the stack that prompted this was Laravel, but the enforcement is in
Postgres and IAM. A Rails, Django, Go or Node application on the same
infrastructure gets exactly the same guarantees with the same two hooks.

## What is in here

```
infra/       CDK stack: VPC, RDS PostgreSQL, S3, DynamoDB, KMS, the ABAC role
proofs/      schema.sql (roles + RLS policies) and run.py (the attack suite)
laravel/     the ~60 lines of application code that plug into all of it
deploy/      bootstrap-secrets.sh, run-proofs.sh, destroy.sh
```

## The four mechanisms

### 1. One IAM role for every tenant, scoped by a session tag

There is a single `TenantAccessRole`. The tenant is not baked into it; it
arrives as a session tag at `AssumeRole` time and the policies read it back:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
  "Resource": "arn:aws:s3:::tenant-data/${aws:PrincipalTag/tenant}/*"
}
```

Ten tenants or ten thousand, that is the same policy and the same role. The
alternative, a role per tenant, hits the 5,000-role account limit and turns
onboarding into an IAM deployment.

Vending is three lines:

```python
sts.assume_role(
    RoleArn=TENANT_ROLE_ARN,
    RoleSessionName=f"tenant-{tenant}",
    Tags=[{"Key": "tenant", "Value": tenant}],
)
```

The security of the whole scheme reduces to who may call that, and whether they
choose the `tenant` argument. In a real system it runs behind authentication and
the value comes from the validated token, never from the request.

Note the two separate permissions involved: assuming the role and tagging the
session are different actions, and `sts:TagSession` has to be granted in both
the trust policy and the caller's policy. Without it the tag never lands, and
the session can reach nothing at all, which is the correct failure.

### 2. S3 needs two statements, not one

Object access is scoped by putting the tag in the resource ARN. Listing is an
action on the bucket, not on an object, so its ARN cannot carry the tenant and
the scoping has to come from a condition:

```json
{
  "Effect": "Allow",
  "Action": ["s3:ListBucket"],
  "Resource": "arn:aws:s3:::tenant-data",
  "Condition": { "StringLike": { "s3:prefix": ["${aws:PrincipalTag/tenant}/*"] } }
}
```

Grant `ListBucket` without that condition and a tenant cannot read anybody
else's files but can enumerate every filename in your system, which for most
SaaS products is itself the leak.

### 3. DynamoDB `LeadingKeys`, and the action you must not grant

```json
"Condition": {
  "ForAllValues:StringEquals": {
    "dynamodb:LeadingKeys": ["${aws:PrincipalTag/tenant}"]
  }
}
```

This constrains the partition key of every item a request touches. What matters
as much is what the policy leaves out: `dynamodb:Scan`. A scan reads across
partitions, so `LeadingKeys` cannot constrain it, and the only safe answer is
not to grant it.

### 4. KMS encryption context

Each tenant's data is encrypted under the shared key with an encryption context
of `{"tenant": "acme"}`, and the policy pins that context to the principal tag.
The context is authenticated additional data, bound into the ciphertext at
encrypt time. A tenant that somehow obtains another tenant's ciphertext, from a
backup, a log line or a mislabelled row, still cannot read it: it can only ask
KMS to decrypt under its own context, and the ciphertext will not match.

### 5. PostgreSQL row-level security

The one that matters most for a shared-database SaaS.

```sql
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON invoices
    USING      (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
```

Four details carry the weight:

- **`FORCE`, not just `ENABLE`.** `ENABLE` exempts the table owner. If the
  application connects as the owner, and it usually does because that is the
  user the migrations ran as, the policies are ignored entirely and everything
  looks like it works. `proofs/run.py` demonstrates this: the same policy on
  two identical tables shows the owner 3 rows on the forced table and all 7 on
  the unforced one.
- **`WITH CHECK`, not just `USING`.** `USING` filters reads. Without
  `WITH CHECK`, a tenant can read only its own rows and write rows labelled
  with anyone's `tenant_id`.
- **`current_setting(..., true)`.** The second argument makes it return NULL
  instead of raising when the setting is absent, and `tenant_id = NULL` is NULL,
  so a connection that never set a tenant sees nothing. Fail closed.
- **The application's role owns nothing and is `NOBYPASSRLS`.** It cannot
  `DISABLE ROW LEVEL SECURITY`, cannot `DROP POLICY`, and cannot `SET ROLE` to
  the owner. All three are checked.

### 6. The bug this actually ships as: `SET` instead of `SET LOCAL`

Setting the tenant at session level works perfectly for one request. Then the
connection goes back into the pool and the next request, belonging to a
different customer, inherits it. The policy does exactly what it was told; it
was told the wrong tenant. This is worse under Octane or PgBouncer in
transaction mode, where connection reuse is the whole point.

`SET LOCAL` is scoped to the transaction, so the fix is to run the request
inside one. See `laravel/ScopeToTenant.php`.

## Deploy and run the proofs

```bash
export AWS_REGION=us-west-2
./deploy/bootstrap-secrets.sh

cd infra && npm install
export CDK_DEFAULT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
export CDK_DEFAULT_REGION=$AWS_REGION
npx cdk deploy

cd .. && ./deploy/run-proofs.sh
```

`run-proofs.sh` launches a one-off Fargate task, waits for it, and prints its
output. The task holds no permissions of its own beyond the right to assume the
tenant role, which is the same position your application server is in.

Exit code is 0 only if every isolation check held.

## Clean up

```bash
./deploy/destroy.sh
```

The KMS key enters a 7 day pending-deletion window rather than disappearing
immediately; that is a KMS floor, not a choice in the stack.

## Cost

No NAT gateway and no load balancer, so this is cheap to run for an afternoon:
an RDS `db.t4g.micro` at about $0.016/hour, one Fargate task for the couple of
minutes the proofs take, and rounding error for S3, DynamoDB on-demand and KMS.
Under a dollar for a full deploy-verify-destroy cycle.
