# api-security-probe

Lightweight API security probe that runs in seconds. No ZAP, no browser, no heavy setup. Point it at any REST API and it checks for common authentication and infrastructure weaknesses.

## What it checks

| Check | What it does |
|---|---|
| **Auth Rate Limit** | Fires 20 rapid bad login attempts, expects a 429 response |
| **API Rate Limit** | Fires 10 rapid requests per configured endpoint, expects a 429 response |
| **JWT: Tampered signature** | Corrupts the token signature, expects 401 |
| **JWT: Expired token** | Sends a known expired token, expects 401 |
| **JWT: Token after logout** | Logs out then reuses the old token, expects 401 |
| **JWT: Algorithm none attack** | Strips the signature and sets `alg: none`, expects 401 |
| **JWT: RS256 to HS256 confusion** | Signs a token using the server's public key as an HMAC secret, expects 401 |
| **BOLA (cross-role)** | Uses a regular user token against admin-only endpoints, expects 401/403 |
| **IDOR (cross-user)** | Uses user2's token against user's resource IDs, expects 401/403/404 |
| **Security Headers** | Checks for HSTS, X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy |
| **TLS Certificate** | Warns if the certificate expires within 30 days |
| **Open Ports** | Scans for unexpected open ports (databases, SSH, debug ports) |

## Install

```bash
npm install -g api-security-probe
```

Or as a project dev dependency:

```bash
npm install --save-dev api-security-probe
```

## Quick Start

**Step 1:** Create a config file (copy from `sample/probe.config.yml`):

```yaml
target: https://api.example.com

auth:
  type: oauth2-password
  url: https://auth.example.com/realms/myrealm/protocol/openid-connect/token
  client_id: myclient
  client_secret: ${AUTH_CLIENT_SECRET}

roles:
  admin:
    username: ${ADMIN_USERNAME}
    password: ${ADMIN_PASSWORD}
  user:
    username: ${USER_USERNAME}
    password: ${USER_PASSWORD}

session:
  probe_endpoint: /accounts

bola:
  admin_endpoints:
    - GET /admin/users
```

**Step 2:** Set your credentials as environment variables:

```bash
export AUTH_CLIENT_SECRET=...
export ADMIN_USERNAME=...
export ADMIN_PASSWORD=...
export USER_USERNAME=...
export USER_PASSWORD=...
```

**Step 3:** Run:

```bash
api-security-probe --config probe.config.yml
```

## CLI Options

```
api-security-probe --config <file> [options]

Options:
  --config, -c <file>   Path to probe config file (YAML or JSON)
  --tests  <list>       Comma-separated tests to run (default: all)
                        rate-limit, api-rate-limit, session, bola, idor,
                        headers, tls, ports
  --output <file>       Write results to a JSON file
  --help,  -h           Show this help
```

## Config Reference

### `target`
Base URL of the API under test.

### `auth`
| Field | Required | Description |
|---|---|---|
| `type` | Yes | Auth type. Currently supports `oauth2-password` |
| `url` | Yes | Token endpoint URL |
| `client_id` | Yes | OAuth2 client ID |
| `client_secret` | No | OAuth2 client secret (omit for public clients) |
| `logout_url` | No | Logout endpoint. Required for the token-after-logout check |
| `jwks_url` | No | JWKS endpoint. Required for the RS256-to-HS256 check |

### `roles`
| Role | Used by |
|---|---|
| `admin` | Session checks, BOLA, API rate limit, security headers |
| `user` | BOLA check (should be blocked from admin endpoints) |
| `user2` | IDOR check (should not access `user`'s resources) |

Each role takes `username` and `password`. Roles not needed for the selected tests are not authenticated.

### `tests`
List of tests to run. If omitted, all tests run. Can also be overridden via `--tests` on the CLI.

### `session`
| Field | Description |
|---|---|
| `probe_endpoint` | An authenticated endpoint used as the target for all JWT attack checks |

### `bola`
| Field | Description |
|---|---|
| `admin_endpoints` | List of admin-only endpoints. Format: `METHOD /path` or just `/path` (defaults to GET) |

### `idor`
| Field | Description |
|---|---|
| `endpoints` | List of endpoints with path parameters. Format: `METHOD /path/{paramName}` |
| `example_ids` | Map of parameter names to `user`'s resource IDs |

### `rate_limit`
| Field | Description |
|---|---|
| `api_endpoints` | Endpoints to probe for rate limiting. Format: `METHOD /path` or just `/path` |

### `headers`
| Field | Description |
|---|---|
| `probe_endpoint` | Endpoint to probe for security headers. Falls back to `session.probe_endpoint` if not set |

### `ports`
| Field | Description |
|---|---|
| `check` | List of ports to scan. Defaults to `[22, 23, 3306, 5432, 6379, 27017, 8080, 8443, 9200]` |

## Environment Variables

Config values support `${VARIABLE_NAME}` syntax and are resolved from environment variables at runtime. This keeps credentials out of config files.

```yaml
client_secret: ${AUTH_CLIENT_SECRET}
```

If a referenced variable is not set, the tool exits with an error before running any checks.

## CI Integration

```yaml
# GitHub Actions example
- name: Run API security probe
  env:
    AUTH_CLIENT_SECRET: ${{ secrets.AUTH_CLIENT_SECRET }}
    ADMIN_USERNAME: ${{ secrets.ADMIN_USERNAME }}
    ADMIN_PASSWORD: ${{ secrets.ADMIN_PASSWORD }}
    USER_USERNAME: ${{ secrets.USER_USERNAME }}
    USER_PASSWORD: ${{ secrets.USER_PASSWORD }}
  run: npx api-security-probe --config probe.config.yml --output results.json
```

The process exits with code `1` if any check fails, making it suitable as a CI gate.

## Output

Terminal output is color-coded and grouped:

- **FAILED** section first: each failing check with per-item detail and the reason it failed
- **PASSED** section: checks that passed, with sub-item counts
- **SKIPPED** section: checks that were skipped (e.g. TLS on an HTTP target)
- **Summary table**: per-check PASS / FAIL / SKIP counts with totals
- Start time, finish time, total duration, and final verdict on every run

Timestamps use UTC and are shown as `09 May 2026  07:27:52 +00:00`.

Pass `--output results.json` to also write a machine-readable JSON file:

```json
{
  "target": "https://api.example.com",
  "started_at": "2026-05-09T07:27:52.000Z",
  "finished_at": "2026-05-09T07:27:53.000Z",
  "duration_ms": 1045,
  "verdict": "FAILED",
  "summary": { "passed": 10, "failed": 5, "skipped": 1, "total": 8 },
  "checks": [...]
}
```

## License

MIT
