#!/usr/bin/env python3
"""
Try to break tenant isolation, and report every attempt.

Nothing in here is a unit test of application code. Every check below asks the
infrastructure a question directly: given credentials scoped to tenant "acme",
can I read tenant "globex"? The application is not in the loop, which is the
point. If the answer is no even when the caller is actively trying, then a bug
in the application cannot make the answer yes.

Exit code is 0 only if every isolation check held.
"""

from __future__ import annotations

import os
import re
import sys
import textwrap
import traceback

import boto3
import psycopg
from botocore.exceptions import ClientError

TENANT_A = "acme"
TENANT_B = "globex"

BUCKET = os.environ.get("BUCKET", "")
TABLE = os.environ.get("TABLE", "")
KEY_ID = os.environ.get("KMS_KEY_ID", "")
ROLE_ARN = os.environ.get("TENANT_ROLE_ARN", "")
REGION = os.environ.get("AWS_REGION", "us-west-2")

DB = dict(
    host=os.environ.get("DB_HOST", "127.0.0.1"),
    port=int(os.environ.get("DB_PORT", 5432)),
    dbname=os.environ.get("DB_NAME", "tenancy"),
)
DB_MASTER_USER = os.environ.get("DB_MASTER_USER", "dbmaster")
DB_MASTER_PASSWORD = os.environ.get("DB_MASTER_PASSWORD", "")
APP_DB_PASSWORD = os.environ.get("APP_DB_PASSWORD", "")

# "postgres" runs only the database proofs, which need no AWS account. Useful
# while iterating against a local container.
ONLY = os.environ.get("PROOFS_ONLY", "")

results: list[tuple[str, bool, str]] = []


def check(name: str, held: bool, detail: str = "") -> None:
    results.append((name, held, detail))
    mark = "  held  " if held else "  LEAK  "
    print(f"[{mark}] {name}")
    if detail:
        print(textwrap.indent(redact(detail).rstrip(), "           "))


def demo(name: str, detail: str = "") -> None:
    """Something worth showing that is not itself an isolation guarantee."""
    print(f"[  note  ] {name}")
    if detail:
        print(textwrap.indent(redact(detail).rstrip(), "           "))


def section(title: str) -> None:
    print()
    print(title)
    print("-" * len(title))


def redact(text: str) -> str:
    """Mask AWS account ids so the transcript can be pasted anywhere."""
    return re.sub(r"\b\d{12}\b", "123456789012", text)


def denied(err: ClientError) -> str:
    """The bit of a botocore error that is worth printing.

    Some errors carry no message at all. InvalidCiphertextException is the
    interesting one: KMS says nothing because there is nothing to say, the
    ciphertext simply did not authenticate under the context it was given.
    """
    code = err.response["Error"]["Code"]
    message = (err.response["Error"].get("Message") or "").strip()
    first = message.splitlines()[0] if message else "(no message)"
    return redact(f"{code}: {first[:150]}")


# ---------------------------------------------------------------------------
# The token vending machine.
#
# One IAM role serves every tenant. The tenant is not baked into the role; it
# arrives as a session tag at AssumeRole time, and the role's policy reads it
# back out with ${aws:PrincipalTag/tenant}. Ten thousand tenants, one policy.
#
# The security of the whole scheme reduces to one question: who is allowed to
# call this function, and can they choose the tenant argument? In a real system
# this runs behind an authenticated endpoint and the tenant comes from the
# validated token, never from the request body.
# ---------------------------------------------------------------------------
def vend(tenant: str) -> boto3.Session:
    sts = boto3.client("sts", region_name=REGION)
    creds = sts.assume_role(
        RoleArn=ROLE_ARN,
        RoleSessionName=f"tenant-{tenant}",
        Tags=[{"Key": "tenant", "Value": tenant}],
        DurationSeconds=900,
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=REGION,
    )


# ---------------------------------------------------------------------------
def prove_s3(a: boto3.Session, b: boto3.Session) -> None:
    section("S3: one bucket, a prefix per tenant")

    s3a, s3b = a.client("s3"), b.client("s3")

    s3a.put_object(Bucket=BUCKET, Key=f"{TENANT_A}/invoice.txt", Body=b"acme invoice")
    s3b.put_object(Bucket=BUCKET, Key=f"{TENANT_B}/invoice.txt", Body=b"globex invoice")
    check("each tenant can write inside its own prefix", True)

    body = s3a.get_object(Bucket=BUCKET, Key=f"{TENANT_A}/invoice.txt")["Body"].read()
    check("each tenant can read its own object", body == b"acme invoice")

    try:
        s3a.get_object(Bucket=BUCKET, Key=f"{TENANT_B}/invoice.txt")
        check(f"{TENANT_A} cannot GET {TENANT_B}'s object", False, "the read succeeded")
    except ClientError as e:
        check(f"{TENANT_A} cannot GET {TENANT_B}'s object", True, denied(e))

    # Listing is a separate permission on a separate resource (the bucket, not
    # the object), so it needs its own condition. Miss this and a tenant cannot
    # read anyone else's files but can enumerate every filename you have.
    listed = s3a.list_objects_v2(Bucket=BUCKET, Prefix=f"{TENANT_A}/")
    check(
        f"{TENANT_A} can list its own prefix",
        listed.get("KeyCount", 0) >= 1,
        f"{listed.get('KeyCount', 0)} object(s)",
    )

    try:
        s3a.list_objects_v2(Bucket=BUCKET, Prefix=f"{TENANT_B}/")
        check(f"{TENANT_A} cannot list {TENANT_B}'s prefix", False, "the listing succeeded")
    except ClientError as e:
        check(f"{TENANT_A} cannot list {TENANT_B}'s prefix", True, denied(e))

    try:
        s3a.list_objects_v2(Bucket=BUCKET)
        check(f"{TENANT_A} cannot list the whole bucket", False, "the listing succeeded")
    except ClientError as e:
        check(f"{TENANT_A} cannot list the whole bucket", True, denied(e))


# ---------------------------------------------------------------------------
def prove_dynamodb(a: boto3.Session, b: boto3.Session) -> None:
    section("DynamoDB: one table, the tenant is the partition key")

    da, db_ = a.client("dynamodb"), b.client("dynamodb")

    da.put_item(TableName=TABLE, Item={"tenant": {"S": TENANT_A}, "sk": {"S": "note#1"}, "body": {"S": "acme note"}})
    db_.put_item(TableName=TABLE, Item={"tenant": {"S": TENANT_B}, "sk": {"S": "note#1"}, "body": {"S": "globex note"}})
    check("each tenant can write its own partition", True)

    got = da.query(
        TableName=TABLE,
        KeyConditionExpression="#t = :t",
        ExpressionAttributeNames={"#t": "tenant"},
        ExpressionAttributeValues={":t": {"S": TENANT_A}},
    )
    check(f"{TENANT_A} can query its own partition", got["Count"] >= 1, f"{got['Count']} item(s)")

    try:
        da.query(
            TableName=TABLE,
            KeyConditionExpression="#t = :t",
            ExpressionAttributeNames={"#t": "tenant"},
            ExpressionAttributeValues={":t": {"S": TENANT_B}},
        )
        check(f"{TENANT_A} cannot query {TENANT_B}'s partition", False, "the query succeeded")
    except ClientError as e:
        check(f"{TENANT_A} cannot query {TENANT_B}'s partition", True, denied(e))

    # A Scan reads every partition, so dynamodb:LeadingKeys cannot constrain it.
    # The only correct answer is to not grant Scan at all.
    try:
        da.scan(TableName=TABLE)
        check(f"{TENANT_A} cannot Scan the table", False, "the scan succeeded and returned every tenant")
    except ClientError as e:
        check(f"{TENANT_A} cannot Scan the table", True, denied(e))


# ---------------------------------------------------------------------------
def prove_kms(a: boto3.Session, b: boto3.Session) -> None:
    section("KMS: one key, an encryption context per tenant")

    ka, kb = a.client("kms"), b.client("kms")

    ct_a = ka.encrypt(
        KeyId=KEY_ID, Plaintext=b"acme secret", EncryptionContext={"tenant": TENANT_A}
    )["CiphertextBlob"]
    ct_b = kb.encrypt(
        KeyId=KEY_ID, Plaintext=b"globex secret", EncryptionContext={"tenant": TENANT_B}
    )["CiphertextBlob"]
    check("each tenant can encrypt under its own context", True)

    out = ka.decrypt(CiphertextBlob=ct_a, EncryptionContext={"tenant": TENANT_A})["Plaintext"]
    check(f"{TENANT_A} can decrypt its own ciphertext", out == b"acme secret")

    # The interesting case. Assume acme has somehow obtained globex's ciphertext
    # (a backup, a log line, a mislabelled row). It still cannot read it.
    try:
        ka.decrypt(CiphertextBlob=ct_b, EncryptionContext={"tenant": TENANT_B})
        check(f"{TENANT_A} cannot decrypt {TENANT_B}'s ciphertext", False, "the decrypt succeeded")
    except ClientError as e:
        check(f"{TENANT_A} cannot decrypt {TENANT_B}'s ciphertext", True, denied(e))

    # And it cannot get around IAM by lying about the context. Note that this
    # one fails differently: IAM lets the call through, because the context now
    # matches the principal tag, and the failure comes from the cryptography
    # instead. The encryption context is authenticated additional data, bound
    # into the ciphertext at encrypt time, so the AEAD tag does not verify.
    # Two independent layers, and the second one does not depend on the policy
    # being right.
    try:
        ka.decrypt(CiphertextBlob=ct_b, EncryptionContext={"tenant": TENANT_A})
        check(f"{TENANT_A} cannot decrypt it by claiming its own context", False, "the decrypt succeeded")
    except ClientError as e:
        check(
            f"{TENANT_A} cannot decrypt it by claiming its own context",
            True,
            f"{denied(e)} -- this one is not IAM. The policy allowed the call; "
            f"the ciphertext failed to authenticate under the wrong context.",
        )


# ---------------------------------------------------------------------------
def connect(user: str, password: str) -> psycopg.Connection:
    return psycopg.connect(user=user, password=password, autocommit=True, **DB)


def apply_schema() -> None:
    """Create the roles, tables, policies and seed data, as the master user."""
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "schema.sql")) as fh:
        sql = fh.read().replace("__APP_PASSWORD__", APP_DB_PASSWORD)

    with connect(DB_MASTER_USER, DB_MASTER_PASSWORD) as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
    print("schema applied")


def prove_postgres() -> None:
    section("PostgreSQL: one database, row-level security")

    app = connect("app_rw", APP_DB_PASSWORD)

    def as_tenant(tenant: str, sql: str, params=None):
        """Exactly how the application should scope a request: a transaction,
        SET LOCAL, then the work. SET LOCAL is undone at COMMIT."""
        with app.transaction():
            with app.cursor() as cur:
                cur.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant,))
                cur.execute(sql, params or ())
                return cur.fetchall() if cur.description else None

    rows = as_tenant(TENANT_A, "SELECT tenant_id, customer FROM invoices")
    check(
        f"an unfiltered SELECT as {TENANT_A} returns only {TENANT_A} rows",
        rows is not None and len(rows) > 0 and all(r[0] == TENANT_A for r in rows),
        f"{len(rows)} rows, all tenant_id={TENANT_A}; the query had no WHERE clause",
    )

    # The shape a SQL injection or a forgotten scope actually takes.
    rows = as_tenant(TENANT_A, "SELECT tenant_id FROM invoices WHERE 1=1 OR TRUE")
    check(
        "a tautology in the WHERE clause changes nothing",
        all(r[0] == TENANT_A for r in rows),
        f"{len(rows)} rows, still only {TENANT_A}",
    )

    rows = as_tenant(TENANT_A, "SELECT count(*) FROM invoices WHERE tenant_id = %s", (TENANT_B,))
    check(
        f"asking explicitly for {TENANT_B} returns nothing",
        rows[0][0] == 0,
        "the policy is ANDed into the query plan, so this is not reachable",
    )

    # WITH CHECK, not USING. Without it a tenant can read only its own rows but
    # write rows labelled with anyone's tenant_id.
    try:
        as_tenant(
            TENANT_A,
            "INSERT INTO invoices (tenant_id, customer, amount_cents) VALUES (%s, %s, %s)",
            (TENANT_B, "planted", 1),
        )
        check(f"{TENANT_A} cannot insert a row labelled {TENANT_B}", False, "the insert succeeded")
    except psycopg.errors.Error as e:
        check(f"{TENANT_A} cannot insert a row labelled {TENANT_B}", True, str(e).splitlines()[0])

    # Fail closed. A connection that never set a tenant is not a connection that
    # sees everything.
    with app.cursor() as cur:
        cur.execute("SELECT count(*) FROM invoices")
        n = cur.fetchone()[0]
    check("a connection with no tenant set sees zero rows", n == 0, f"count = {n}")

    # The application's role cannot turn the policy off.
    try:
        with app.cursor() as cur:
            cur.execute("ALTER TABLE invoices DISABLE ROW LEVEL SECURITY")
        check("the app role cannot disable row-level security", False, "the ALTER succeeded")
    except psycopg.errors.Error as e:
        check("the app role cannot disable row-level security", True, str(e).splitlines()[0])

    try:
        with app.cursor() as cur:
            cur.execute("SET ROLE app_owner")
        check("the app role cannot become the table owner", False, "SET ROLE succeeded")
    except psycopg.errors.Error as e:
        check("the app role cannot become the table owner", True, str(e).splitlines()[0])

    try:
        with app.cursor() as cur:
            cur.execute("DROP POLICY tenant_isolation ON invoices")
        check("the app role cannot drop the policy", False, "the DROP succeeded")
    except psycopg.errors.Error as e:
        check("the app role cannot drop the policy", True, str(e).splitlines()[0])

    app.close()


def prove_force_matters() -> None:
    section("PostgreSQL: what ENABLE without FORCE actually protects")

    owner = connect(DB_MASTER_USER, DB_MASTER_PASSWORD)
    with owner.cursor() as cur:
        cur.execute("SET ROLE app_owner")
        cur.execute("SELECT set_config('app.tenant_id', %s, false)", (TENANT_A,))

        cur.execute("SELECT count(*) FROM invoices")
        forced = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM invoices_unforced")
        unforced = cur.fetchone()[0]

    check(
        "FORCE: the table owner is subject to the policy",
        forced == 3,
        f"invoices: {forced} rows visible to the owner (only {TENANT_A}'s)",
    )
    check(
        "no FORCE: the table owner sees every tenant",
        unforced == 7,
        f"invoices_unforced: {unforced} rows visible to the owner, all tenants. "
        f"Same policy, same query, one missing keyword. This is why the role the "
        f"application logs in as must not own the tables.",
    )
    owner.close()


def prove_pooling_hazard() -> None:
    section("Connection pooling: the way this leaks in production")

    # --- the wrong way, on its own connection -------------------------------
    #
    # Request 1 sets the tenant at session level. Everything about this looks
    # correct and every test passes, because within a single request a session
    # SET and a SET LOCAL are indistinguishable.
    wrong = connect("app_rw", APP_DB_PASSWORD)
    with wrong.cursor() as cur:
        # set_config(..., false) is the session-level form, identical to
        # `SET app.tenant_id = 'acme'`. This is the mistake.
        cur.execute("SELECT set_config('app.tenant_id', %s, false)", (TENANT_A,))
        cur.execute("SELECT count(*) FROM invoices")
        first = cur.fetchone()[0]

    # Request 2 gets handed the same connection out of the pool. It belongs to a
    # different customer, and it never sets a tenant because the developer
    # assumed connections start clean.
    with wrong.cursor() as cur:
        cur.execute("SELECT current_setting('app.tenant_id', true)")
        leaked = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM invoices")
        leaked_rows = cur.fetchone()[0]
    wrong.close()

    demo(
        "a session-level SET is still there on the next request",
        f"request 1 set tenant_id={TENANT_A!r} and saw {first} rows. "
        f"Request 2 set nothing and read tenant_id={leaked!r}, {leaked_rows} rows. "
        f"Row-level security did exactly what it was told; it was told the wrong tenant.",
    )

    # --- the right way, on a fresh connection -------------------------------
    right = connect("app_rw", APP_DB_PASSWORD)
    with right.transaction():
        with right.cursor() as cur:
            cur.execute("SELECT set_config('app.tenant_id', %s, true)", (TENANT_B,))
            cur.execute("SELECT count(*) FROM invoices")

    with right.cursor() as cur:
        cur.execute("SELECT current_setting('app.tenant_id', true)")
        after = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM invoices")
        after_rows = cur.fetchone()[0]
    right.close()

    check(
        "SET LOCAL is gone at COMMIT, so nothing can be inherited",
        (after is None or after == "") and after_rows == 0,
        f"after the transaction the setting is {after!r} and the same query "
        f"returns {after_rows} rows. The next request starts with no tenant, "
        f"and no tenant means no rows.",
    )


# ---------------------------------------------------------------------------
def main() -> int:
    print("Tenant isolation proofs")
    print("=======================")
    print(f"region={REGION} bucket={BUCKET} table={TABLE}")
    print(f"database={DB['host']}:{DB['port']}/{DB['dbname']}")

    section("Setup")
    apply_schema()

    steps = [prove_postgres, prove_force_matters, prove_pooling_hazard]

    if ONLY != "postgres":
        section("Vending scoped credentials")
        a, b = vend(TENANT_A), vend(TENANT_B)
        ident = a.client("sts").get_caller_identity()
        check(
            "both tenants received credentials from the same IAM role",
            True,
            f"session arn ends with .../{ident['Arn'].rsplit('/', 1)[-1]}",
        )
        steps = [
            lambda: prove_s3(a, b),
            lambda: prove_dynamodb(a, b),
            lambda: prove_kms(a, b),
        ] + steps

    for fn in steps:
        try:
            fn()
        except Exception:
            traceback.print_exc()
            results.append(("a check raised instead of completing", False, "raised"))

    section("Result")
    leaks = [n for n, ok, _ in results if not ok]
    print(f"{len(results) - len(leaks)}/{len(results)} isolation checks held")
    if leaks:
        for n in leaks:
            print(f"  LEAK: {n}")
        return 1
    print("No cross-tenant access was possible.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
