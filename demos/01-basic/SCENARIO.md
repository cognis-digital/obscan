# Demo 01 — Basic conformance lint

This demo runs OBSCAN against `noncompliant-openapi.json`, a small but
realistic Open Banking / PSD2 API definition that contains several common
conformance violations.

## What the sample document does wrong

The spec defines an `oauth2` security scheme but:

1. **Enables the implicit grant** (`flows.implicit`) — prohibited by FAPI.
2. **Serves its token endpoint over plain HTTP** (`http://...`) — violates
   the FAPI TLS requirement.
3. **Exposes a `POST /payments` operation that opts out of security**
   (`security: []`) — unauthenticated access to a payment endpoint.
4. **The payment POST has no idempotency header** — retries could
   double-initiate a payment.
5. **Has account + payment paths but no consent endpoint** — PSD2 requires an
   explicit consent resource.

It *does* declare `accounts` / `payments` consent scopes and offers the
`authorizationCode` flow, so those rules pass.

## Run it

```bash
python -m obscan lint demos/01-basic/noncompliant-openapi.json
# machine-readable for CI:
python -m obscan lint demos/01-basic/noncompliant-openapi.json --format json
```

## Expected result

OBSCAN reports the findings above:

- `FAPI-OAUTH-002` (error) — implicit flow present
- `FAPI-TLS-004`   (error) — token endpoint not over https
- `OB-SEC-007`     (error) — `POST /payments` disables security
- `OB-PSD2-008`    (warning) — missing consent endpoint
- `OB-IDEMPOTENCY-009` (warning) — payment POST lacks idempotency header

Because there are `error`-level findings, the process exits **non-zero (1)**,
so a CI step running this command will fail the build.
