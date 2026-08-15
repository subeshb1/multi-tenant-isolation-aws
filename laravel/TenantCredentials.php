<?php

namespace App\Support;

use Aws\S3\S3Client;
use Aws\Sts\StsClient;
use Illuminate\Support\Facades\Cache;

/**
 * The token vending machine, in about thirty lines.
 *
 * The application's own IAM role can do exactly one interesting thing: assume
 * the tenant role with a tenant tag. It has no S3 permissions, no DynamoDB
 * permissions and no KMS permissions of its own, so a remote code execution in
 * this process does not hand the attacker the whole bucket. It hands them the
 * ability to become one tenant at a time, and only tenants they can name.
 */
class TenantCredentials
{
    public function __construct(private readonly StsClient $sts) {}

    /**
     * Credentials that can reach one tenant's data and nothing else.
     *
     * Cached for slightly less than their lifetime. AssumeRole is not free and
     * it is not fast; calling it on every request adds 50 to 100 ms and will
     * eventually run into an STS rate limit.
     */
    public function for(string $tenant): array
    {
        return Cache::remember("tenant-creds:{$tenant}", 3300, function () use ($tenant) {
            $result = $this->sts->assumeRole([
                'RoleArn' => config('services.aws.tenant_role_arn'),
                'RoleSessionName' => "tenant-{$tenant}",
                'DurationSeconds' => 3600,

                // This is the entire access control decision. Everything the
                // returned credentials can and cannot do follows from this tag
                // being matched against ${aws:PrincipalTag/tenant} in the
                // role's policy.
                'Tags' => [['Key' => 'tenant', 'Value' => $tenant]],
            ]);

            return [
                'key' => $result['Credentials']['AccessKeyId'],
                'secret' => $result['Credentials']['SecretAccessKey'],
                'token' => $result['Credentials']['SessionToken'],
            ];
        });
    }

    /** An S3 client that physically cannot read another tenant's prefix. */
    public function s3(string $tenant): S3Client
    {
        return new S3Client([
            'version' => 'latest',
            'region' => config('services.aws.region'),
            'credentials' => $this->for($tenant),
        ]);
    }
}
