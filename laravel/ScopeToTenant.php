<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;

/**
 * Tells PostgreSQL which tenant this request belongs to, once, and then gets
 * out of the way.
 *
 * Everything downstream of this middleware can write `Invoice::all()` and get
 * only the current tenant's invoices, because the policy on the table is doing
 * the filtering. There is no global scope to remember to apply, no trait to
 * add to a model, and no `where('tenant_id', ...)` for a code reviewer to
 * notice is missing. Forgetting to scope a query now returns nothing rather
 * than returning everything.
 *
 * Register it in bootstrap/app.php:
 *
 *     $middleware->web(append: [ScopeToTenant::class]);
 */
class ScopeToTenant
{
    public function handle(Request $request, Closure $next): Response
    {
        // The tenant comes from the authenticated session, never from anything
        // the caller can influence. A tenant id read out of a header, a query
        // parameter or a subdomain is an authorization decision made by the
        // attacker.
        $tenant = $request->user()?->tenant_id;

        abort_if($tenant === null, 403, 'No tenant on this request');

        // The whole request runs inside one transaction, and that is not
        // incidental: SET LOCAL exists only until the transaction ends.
        //
        // The alternative, a session-level SET, survives the request. Under
        // Octane, or behind PgBouncer in transaction mode, the same connection
        // is handed to the next request, which inherits this tenant. That is a
        // cross-tenant data leak produced by a working row-level security
        // policy being told the wrong tenant, and it does not show up in tests
        // because tests do not reuse connections across users.
        return DB::transaction(function () use ($tenant, $request, $next) {
            DB::statement("SELECT set_config('app.tenant_id', ?, true)", [$tenant]);

            return $next($request);
        });
    }
}
