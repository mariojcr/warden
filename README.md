# warden

A credential custodian for AI agents. Agents run with **no credentials of their own**; when they need
something they ask warden, the owner approves it with a passkey, and the agent gets a **grant** with a
scope and a duration that ends on its own and can be revoked at any time. The credentials never leave
warden: it proxies the requests and puts the credential in itself. Everything goes to an append-only,
keyed audit chain.

Credentials come from OAuth connections the owner makes once, stored encrypted with a master key that is
not on the data volume.

What it covers today:

- **GitHub**: git over HTTP and the REST API, per repository, read or write, plus named *powers* for what
  can undo work or skip a review.
- **A claude.ai session** for Claude Code agents: warden keeps the refresh token and hands out
  short-lived access tokens.
- **Private package registries on Google Cloud** (Artifact Registry and a composer registry), read-only,
  for build sandboxes: fixed presets of images and packages chosen by the operator.

## How it works

```
agent (Nomad job)                   warden                                   owner
  workload identity ─POST /api/sessions─▶ session token
  POST /api/requests ─────────────▶ pending ──────────────────────────────▶ approval page / companion app
   {system, scope, mode,                                                  (what, why, scope, duration)
    duration, reason}                                                      passkey
                                     OIDC (prompt=login, max_age=0) or ◀──────
                                     warden's own WebAuthn passkey
                                     → grant (repos, mode, powers, until)
  GET /api/requests/{id}?wait ◀──── approved
  git / REST / registry ──────────▶ proxy: live grant for this? ──▶ upstream, with the credential added here
```

- **Sessions** are opened with the Nomad workload identity of the job (checked against Nomad's JWKS), so
  there is no bootstrap secret. Only the configured jobs and namespaces can open one.
- **Approving** needs a fresh passkey: an OIDC ID token with `auth_time` after the click, `amr=phr` and the
  owner's `sub`, or a signature from warden's own WebAuthn passkey over a single-use challenge bound to that
  request. Refusing and revoking do not need one: they only take away.
- **A companion app** can list, refuse and revoke with its own token. It can only approve by relaying a
  passkey signature made on the owner's screen; it cannot grant anything by itself.

## GitHub

The connection is a GitHub OAuth App authorised with the device flow (like `gh auth login`), scope
`repo` only. Because `repo` covers every repository of the account, the token never leaves warden: warden
proxies git ("smart" HTTP) and the REST API and only lets through the repositories, mode and time granted.
Tokens that expire are refreshed by warden; a connection whose refresh fails is marked as needing to be
connected again and the proxy says so.

| Path on warden | Mode | Upstream |
|---|---|---|
| `/git/github.com/{o}/{r}[.git]/info/refs?service=git-upload-pack`, `POST …/git-upload-pack` | read | `https://github.com/{o}/{r}.git/…` |
| `/git/github.com/{o}/{r}[.git]/info/refs?service=git-receive-pack`, `POST …/git-receive-pack` | write | same |
| `GET`/`HEAD /api/v3/repos/{o}/{r}/…`, only `READ_RULES` (`src/proxy.rs`) | read | `https://api.github.com/repos/{o}/{r}/…` |
| `POST`/`PUT`/`PATCH`/`DELETE /api/v3/repos/{o}/{r}/…`, only `WRITE_RULES` | write | same |

A write grant works on branches: create them, push commits that fast-forward them, pull requests, issues,
files outside the default branch. **That already runs GitHub Actions** for workflows triggered by `push`
or `pull_request`, with the secrets they use; the approval page says so. Anything that can undo work,
skip a review or publish is a power the request names and the owner approves one by one:

| Power | Without it the proxy refuses |
|---|---|
| `default_branch` | any push or write to the default branch |
| `force_push` | moving a branch to a commit that does not descend from it, deleting a branch, refs that are neither branches nor tags |
| `tags` | creating, moving or deleting tags (what usually triggers a release) |
| `merge` | `PUT pulls/{n}/merge` |
| `approve` | a review with `event: APPROVE` |
| `rerun` | re-running a workflow run or job (it runs the original commit and ref again with today's secrets) |

Fast-forward is checked against the pack itself while it streams; warden holds back the pack checksum
until it knows, so GitHub applies nothing that fails the check. A commit that is neither in the push nor
on GitHub (a thin pack) cannot be checked and is refused: use `git push --no-thin`.

Always refused, whatever the grant: GraphQL, LFS, the "dumb" protocol, repository administration
(settings, hooks, keys, collaborators, secrets, rulesets, branch protection, delete, transfer, forks),
reads that can carry secrets or say who has access (`SENSITIVE_READS`), and paths with `..`, empty
segments, backslashes or encoded separators. The upstream host comes from the configuration, never from
the request, redirects are not followed, and headers go both ways through an allowlist.

## claude.ai session

The owner connects a claude.ai account once (with a passkey). warden stores the refresh token encrypted
and is the only one that uses it. An agent with a `claude_session` grant asks for the current access token
(`POST /api/claude/token`) and gets it without the refresh token, so what it holds expires within hours.

## Google Cloud registries

For sandboxes that build a project with private images and packages:

- **The owner's Google account with `devstorage.read_only` only.** No service account keys and no `iam`
  scope: a stolen refresh token can at most read storage and Artifact Registry. After the OAuth flow,
  `tokeninfo` must show this client, the expected email and no other scope, or nothing is stored.
- **Requests name a preset** from the configuration (`gcp.presets`), never their own list; the grant
  keeps the list it was approved with.
- **The registry proxy** (`GET|HEAD /registry/{host}/{path}`) lets through only the manifests, blobs,
  npm tarballs and composer metadata/dists of the preset: no catalogs, tag lists, uploads or searches.
  Same-host redirects (signed download URLs) are followed inside warden; others are not.

## Audit

Every request, allowed or not, leaves a line: who asked what and why, scope, duration, who approved (with
`auth_time` and `amr`) or refused, expiries, revocations and every proxied request with its outcome. Each
row carries an HMAC-SHA256 over the previous one, keyed from the master key (HKDF), so someone who can
write the database but lacks the master key cannot edit a row or rebuild the chain. `warden audit-verify`
walks it without writing. Each session has an audit budget (per minute and in total); past it, warden
refuses with 429 and does not act.

## API

For a session (session token as `Authorization: Bearer`, or as the Basic password for git):

| | |
|---|---|
| `POST /api/sessions` | Nomad workload identity → `{token, expires_at, label}` |
| `POST /api/requests` | `{"system":"github","scope":{"repos":["o/r"]},"mode":"read\|write","powers":[…],"duration":"2h","reason":"…"}` |
| `GET /api/requests/{id}?wait=25` | status (`pending`, `approved`, `refused`, `expired`, `withdrawn`), waiting up to 30 s for a change |
| `DELETE /api/requests/{id}` | withdraw it |
| `GET /api/grants`, `DELETE /api/grants/{id}` | grants; release one early |
| `POST /api/claude/token` | current claude.ai access token (needs a `claude_session` grant) |

For the companion app (its own token): `GET /api/heimdall/state?since=V&wait=25`,
`POST /api/heimdall/requests/{id}/refuse`, `POST /api/heimdall/grants/{id}/revoke`,
`POST /api/heimdall/requests/{id}/challenge` and `POST /api/heimdall/requests/{id}/approve` (a WebAuthn
assertion from `navigator.credentials.get`).

In the browser: `/` (the owner's panel: connections, passkeys, pending requests, grants, audit),
`/r/{id}` (approve or refuse a request) and the OAuth callbacks. The only script is `/static/warden.js`
(`script-src 'self'`).

## Configuration

A JSON file (`warden --config warden.json`), see `src/config.rs` for every field and its default:

- `data_dir`, `master_key_file`, `public_url`, `browser_listen`, `api_listen`, `tls`;
- `oidc`: the owner's identity provider (`issuer`, `client_id`, `client_secret_file`, `owner_sub`);
- `github`: the OAuth App `client_id` and `expected_login`;
- `nomad`: `jwks_url`, `audience`, `namespace`, `jobs`, `other_namespaces`;
- optional `webauthn` (`rp_id`, allowed origins), `claude`, `gcp` (client, `expected_email`, `registries`,
  `upstreams`, `presets`) and `limits`.

## Build and run

```
cargo test
cargo build --release
podman build -t warden .
```

`deploy/` has a Nomad job and a volume as an example: TLS from the job's template, secrets from Nomad
variables, and the master key in a file outside the data volume.

## Known limits

- One owner (`owner_sub`). Rotating the master key means reconnecting and starting a new database, since
  the audit chain is keyed from it.
- Writing acts as the owner on GitHub: with a power granted, branch protections the owner can bypass are
  bypassed. The proxy is the only limit; warden never changes repository settings.
- A repository with a workflow that publishes on every push to any branch is one where writing is
  publishing.
- GitHub serves objects from the whole fork network, so reading a repository can reach commits of a
  private fork by SHA.
- A session lasts its TTL even if its Nomad allocation ends earlier.
- Redirects to other hosts (Actions logs, tarballs) are not followed, and `Link` pagination points to
  `/repositories/{id}`: paginate with `?page=N`.
- Most of `gh` uses GraphQL, which does not pass.
- A redirect to another host reaches the agent as it is. For a private repository, a tarball or a
  log answers with a signed URL that works for a few minutes without warden, outside the audit and
  after a revoke. It only reads what the grant could already read.
- The master key protects the credentials and the audit chain, not the grants. Someone who can write
  the database can add a session and a grant without it, and deleting the newest audit rows still
  verifies. Keep the data volume as private as the master key.

## License

Apache-2.0
