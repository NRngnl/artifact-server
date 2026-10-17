# Fork additions: Cloudflare Access and shared content zones

This file documents behavior added by this fork on top of upstream Artifact
Server. It is kept separate so upstream docs stay unchanged and easy to sync.
Read it together with [README.md](README.md).

## Opt-in OIDC auto-admission

With `autoAdmitOidcMembers: true` (Worker env
`ARTIFACT_SERVER_AUTO_ADMIT_OIDC_MEMBERS=true`), a verified OIDC or Access identity
with no member record is admitted as `member`. It is off by default. The
bootstrap administrator rule still wins on an empty installation, unverified
emails are refused, and a member deactivated by an administrator is never
re-admitted by login. Proved by `tests/conformance/oidc-auto-admit.test.ts`.

### Additional deployment fields

| Field | Required | Meaning |
|---|---|---|
| `autoAdmitOidcMembers` | no | `true` admits verified OIDC users without a member record as `member`; requires OIDC; default off |
| `accessSyncPolicyId` | with `accessSyncApiTokenSecretRef` | Cloudflare Access reusable policy whose email include list mirrors active members |
| `accessSyncApiTokenSecretRef` | with `accessSyncPolicyId` | Secret reference for an API token with Access policy edit; value comes from `ARTIFACT_SERVER_CF_ACCESS_SYNC_API_TOKEN` |
| `accessTeamDomain` | with `accessAudiences` | `https://<team>.cloudflareaccess.com`; enables `Cf-Access-Jwt-Assertion` enforcement |
| `accessAudiences` | with `accessTeamDomain` | Non-empty list of Access application AUD tags accepted by the Worker |

## Sharing a content zone between installations

Cloudflare inputs may set `"contentHostSuffix": "-team.content.example.org"` alongside
`"contentDomain": "content.example.org"`. Content URLs then use
`<token>-team.content.example.org`, including live, review, and private bootstrap URLs.
Omit the field to retain `<token>.content.example.org` unchanged. Suffixes are exactly
`-<label>.<contentDomain>`, where the label has 1–16 lowercase letters, digits,
or hyphens, with no leading/trailing hyphen or `--`.
Use a different suffix and `installationName` for each group;
keep the application on its existing separate registrable domain.

The plan emits DNS name `*-team.content.example.org`, Worker route
`*-team.content.example.org/*`, and `ARTIFACT_SERVER_CONTENT_HOST_SUFFIX`. DNS wildcard
semantics only recognize a whole `*` label: **the emitted flat DNS name is not a
wildcard**. The zone administrator must separately provision a shared proxied
`*.content.example.org` DNS record (or individual content names); do not let every
installation manage the shared wildcard. Standard `*.content.example.org` TLS coverage
covers these flat hosts. No DNS or TLS behavior is proved by the local plan test.

Flat review frames receive the exact issued content hostname in their frame URL
and allow only `https://<hostname>` for scripts, stylesheets, and fetches (also
HTTP for loopback development). Missing or foreign hosts fail closed. Dotted
installations retain their original CSP unchanged.

Flat review leases use `review<hex>` rather than the dotted `review-<56 hex>`.
The digest length is `56 - label.length`, retaining 40–55 hex digits (160–220
bits); the complete first label is always 63 characters including `-<label>`.
Dotted leases retain 224 bits. Immutable and live tokens remain unchanged.

Set `ALCHEMY_STACK_NAME=artifact-server-team` for each new group and reuse it for
all subsequent operations. The default remains `artifact-server-cloudflare` for
existing deployments; group configurations using that default are rejected
before resource planning. Stack names must match `/^[a-z0-9][a-z0-9-]{0,60}$/`.
Do not rename a live stack without a state migration.
Alchemy's Cloudflare backend uses the account's `alchemy-state-store` Worker:
a Durable Object is named by **stack name**, and its resource keys are
`r\\0<stage>\\0<resource FQN>` (stack outputs: `o\\0<stage>`). Thus the same
stack name and stage collide even with different `installationName` values.
Worker, D1, and R2 resource names separately include installation name,
environment, and stage. Distinct stack names plus distinct installation names
allow groups to share a `production` stage without sharing state or resources.

## Optional Cloudflare Access hardening

Member status in Artifact Server stays the authorization boundary. These
opt-in fields add Cloudflare Access as defense in depth:

```json
{
  "autoAdmitOidcMembers": true,
  "accessSyncPolicyId": "<reusable Access policy ID>",
  "accessSyncApiTokenSecretRef": "cloudflare-secrets-store://artifact-server-access-sync-token",
  "accessTeamDomain": "https://<team>.cloudflareaccess.com",
  "accessAudiences": ["<app AUD tag>", "<content AUD tag>"]
}
```

- `autoAdmitOidcMembers` (requires OIDC or Access login) admits a verified user with no
  member record as `member`. An administrator's deactivation is never undone
  by a later login.
- `accessSyncPolicyId` + `accessSyncApiTokenSecretRef` add each admitted
  member's email to the reusable policy's include list and remove it on
  deactivation. The token needs Access policy edit on the account and is read
  from `ARTIFACT_SERVER_CF_ACCESS_SYNC_API_TOKEN`. The bootstrap administrator
  is never removed and the list is never emptied. Sync failures only log a
  warning. The API has no atomic list edit (GET then PUT), so concurrent edits
  can drop one change; reconcile by hand if a warning appears.
- `accessTeamDomain` + `accessAudiences` make the Worker reject any request
  (except `GET /health`) without a valid `Cf-Access-Jwt-Assertion` for one of
  the listed AUD tags, so traffic that bypasses Access gets a bare 403.

## Single sign-on from the Access gate

To avoid signing into Access twice, replace all `oidc*`/`workos*` login settings
with this deployment configuration (the app AUD must be in `accessAudiences`):

```json
{
  "accessLogin": true,
  "accessTeamDomain": "https://<team>.cloudflareaccess.com",
  "accessAudiences": ["<application AUD tag>", "<content AUD tag>"],
  "accessAppAudience": "<application AUD tag>"
}
```

The stack maps these to `ARTIFACT_SERVER_CF_ACCESS_LOGIN=true`,
`ARTIFACT_SERVER_CF_ACCESS_TEAM_DOMAIN`, `ARTIFACT_SERVER_CF_ACCESS_AUDIENCES`
(comma-separated), and `ARTIFACT_SERVER_CF_ACCESS_APP_AUDIENCE`. Access login
cannot be combined with any OIDC or WorkOS login variables. Auto-admission is
still opt-in via `autoAdmitOidcMembers` / `ARTIFACT_SERVER_AUTO_ADMIT_OIDC_MEMBERS=true`.

The Worker verifies RS256 signatures, issuer, audience and expiry before using
`email` and `sub` as `cloudflare-access:<teamDomain>` identities. The application
AUD is checked again for login: a content-only token cannot establish or use an
app session. Service tokens (`common_name`, or no email) are never browser users;
`Cf-Access-Authenticated-User-Email` is never trusted. Access is responsible for
email verification; configure only IdPs that verify email ownership (for example,
Google or email OTP). An unseen provider/subject is bound to an existing member
by verified email, including administrators: reusing or reassigning an admin's
email grants that identity the existing administrator role. Treat IdP account
recovery and email reassignment as administrator-level trust decisions.
Local membership and deactivation remain authoritative.

Only `Sec-Fetch-Site: same-origin` or `none` navigations may issue or revoke
sessions (missing, `same-site`, and `cross-site` headers cannot). A cross-site
navigation with a matching session may read; otherwise it receives 401.
The first allowed HTML navigation creates normal session/CSRF cookies and redirects back
to the same local path; `/auth/login?returnTo=/review` also works explicitly.
Switching Access users revokes a different member's session and re-authenticates
reads; unsafe requests fail instead of executing as the old member. Bearer/API-key
requests keep their existing behavior (and still require a valid Access assertion
when JWT enforcement is enabled). Browser-session requests check local membership
on each request; this adds identity repository work rather than caching admission.

The management UI first POSTs the CSRF-protected `/api/v1/session/logout` to revoke
the app session, then navigates to `/auth/logout`, which also revokes any app
session server-side before redirecting to
`<teamDomain>/cdn-cgi/access/logout`. An upstream IdP session may still allow an
immediate subsequent Access sign-in; Access logout does not promise IdP logout.
The existing 15-minute scheduled handler reconciles missed policy updates, retaining
manual non-member email rules and non-email rules while removing deactivated
members and adding active members plus the bootstrap administrator.

