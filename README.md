# AAA Knowledge Base

Internal static Vercel dashboard (Knowledge Base). Same auth shape as sibling
dashboards `aa-project-pipeline` and `aaa-jira-fulfillment`.

## Auth (Clerk) — AAA-769 Phase 1

Dashboard HTML is never served unauthenticated. Vercel Edge middleware verifies
a Clerk session, then admits **only** `brad@automationarchitecture.ai`.

This replaces shared Supabase Auth (`aaa-internal-auth`, ref
`qmdblnaqpylbnufvarcu`). There is no runtime Supabase Auth.

### Vercel environment variables

Set these on the Production (and Preview) target. Values never go in the repo.

| Variable | Required | Purpose |
|---|---|---|
| `CLERK_SECRET_KEY` | **yes** | Server-only. Verifies the Clerk session in `middleware.js`. |
| `CLERK_PUBLISHABLE_KEY` | **yes** | Used by `authenticateRequest` and the login/callback JS. Served to the browser via `/api/clerk-config` (this key is public by design). |
| `CLERK_JWT_KEY` | no | Optional PEM public key for networkless JWT verification. |

**Do not set / no longer required**

- `SUPABASE_ANON_KEY` — unused. Remove it from the Vercel project when convenient.
- `ALLOWED_EMAILS` — unused. Phase 1 allowlist is hard-coded to
  `brad@automationarchitecture.ai` and does not admit other emails.

### Clerk Dashboard

- Disable public sign-up (the edge allowlist is the real gate either way).
- Allow redirect URLs for this dashboard origin, `/login`, and `/auth/callback`.

After merge: set the Clerk env vars, smoke-test sign-in as
`brad@automationarchitecture.ai`, then (with Brad yes) pause/remove the
`aaa-internal-auth` Supabase Micro once every consumer has cut over.
