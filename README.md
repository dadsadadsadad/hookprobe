# HookProbe

HookProbe tests whether a webhook **receiver** is secure. Point it at a receiver URL and give it the signing secret. It sends a series of hostile requests and reports which checks pass or fail.

```
hookprobe --scheme stripe --secret "$STRIPE_WEBHOOK_SECRET" https://staging.example.com/webhooks/stripe
```

Most webhook bugs are on the receiving end: signature checks that run on parsed JSON, timestamps that are signed but never compared, no dedupe on event IDs, handlers that read an unlimited body forever. They all look fine in a happy-path test. HookProbe makes them fail loudly, locally or in CI.

## What it checks

| # | Key | A secure receiver... |
|---|-----|----------------------|
| 0 | `baseline` | accepts a correctly signed request and processes it once (if this fails, nothing else is meaningful and the run stops) |
| 1 | `missing-signature` | rejects a request with no signature header |
| 2 | `wrong-signature` | rejects a request signed with a different secret |
| 3 | `replay` | does not process an exact copy of a valid request a second time |
| 4 | `stale-timestamp` | rejects a valid signature whose timestamp is outside the tolerance window, in the past or the future |
| 5 | `duplicate` | processes a legitimate redelivery (same event ID, fresh timestamp and signature) only once, and still answers 2xx so the sender stops retrying |
| 6 | `reserialized-body` | rejects the same JSON with different whitespace and key order when the signature covers the original bytes (catches receivers that verify parsed JSON instead of the raw body) |
| 7 | `oversized-body` | rejects a validly signed 10 MiB body with 413 or another 4xx, or cuts the connection |
| 8 | `slow-body` | times out a request whose body arrives one byte at a time (slowloris) |
| 9 | `header-variants` | accepts the signature header under another spelling (HTTP header names are case-insensitive) and rejects malformed values: wrong version tag, missing prefix, truncated signature, empty value |
| 10 | `multiple-signatures` | accepts a header carrying several signatures when any one matches (secret rotation), and rejects one where none matches |

"Rejects" means a 4xx status **and** the event was not processed. A receiver that answers 401 but runs the handler anyway fails. A 5xx counts as a failure, because senders retry on 5xx.

Some checks do not apply to every format, and those are reported as `SKIP` with the reason. Skips do not fail the run.

| Format | Skipped | Why |
|--------|---------|-----|
| `github` | 4, 10 | no signed timestamp, one signature per request |
| `paymongo`, `paymongo-live` | 10 | one signature per request |
| `xendit` | 4, 6, 10 | a static token: no timestamp, no body signature, no rotation |

## Signature schemes

```
$ hookprobe schemes
github             X-Hub-Signature-256: sha256=<hex HMAC-SHA256 of body>, X-GitHub-Delivery: <id>
hook               X-Hook-Signature: v1,<base64 HMAC-SHA256 of "event_id.timestamp.body">
paymongo           Paymongo-Signature: t=<unix>,te=<hex HMAC-SHA256 of "t.body">,li=
paymongo-live      Paymongo-Signature: t=<unix>,te=,li=<hex HMAC-SHA256 of "t.body">
standard-webhooks  webhook-signature: v1,<base64 HMAC-SHA256 of "id.timestamp.body">
stripe             Stripe-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "t.body">
xendit             x-callback-token: <verification token> (static token, body not signed)
```

- **stripe**: the full secret string (`whsec_...`) is the HMAC key, as in Stripe's libraries.
- **github**: `X-Hub-Signature-256`, with the event ID in `X-GitHub-Delivery`.
- **standard-webhooks**: [standardwebhooks.com](https://www.standardwebhooks.com). A `whsec_<base64>` secret is base64-decoded into the key.
- **paymongo** / **paymongo-live**: the signature goes in `te` for test-mode events and in `li` for live ones. Pass the webhook's secret key as `--secret`. The event ID is `data.id` in the body, so use `--body-file examples/paymongo-event.json`.
- **xendit**: Xendit does not sign the payload. Each callback carries the account's verification token, so pass that token as `--secret`. With no signature over the body and no timestamp, deduping the event ID is the only replay protection, and checks 3 and 5 matter most.
- **hook**: the format of my Reliable Webhook Delivery Service: `X-Hook-Event-Id`, `X-Hook-Timestamp`, `X-Hook-Attempt`, and `X-Hook-Signature` with space-separated `v1,` signatures during rotation. The key is the whole secret string, `whsec_` prefix included.

The Stripe, GitHub, Standard Webhooks and `hook` implementations are tested against the reference vectors those projects publish.

### Provider-shaped payloads

By default HookProbe sends a small generic event. Receivers built on a provider's library usually parse the event before trusting it (Stripe's library checks `api_version`, for example) and would reject the generic one in the baseline. Give them a real-looking event instead:

```
hookprobe --scheme stripe --body-file examples/stripe-event.json http://localhost:8080/webhooks/stripe
```

A template is any JSON file with placeholders. `{{id}}` is required (every check needs its own event ID), and the others are optional: `{{type}}`, `{{created}}` (unix seconds), `{{created_rfc3339}}` and `{{check}}`. Placeholders are replaced verbatim, so quote the string ones: `"id": "{{id}}"`. `examples/` has starting points for Stripe, PayMongo and Xendit. Set `api_version` and similar fields to whatever your receiver expects.

### Adding a scheme

A scheme is one file in `internal/scheme/` that implements `scheme.Scheme` and registers itself. For a made-up provider:

```go
package scheme

type acmepay struct{}

func init() { Register(acmepay{}) }

func (acmepay) Name() string            { return "acmepay" }
func (acmepay) Description() string     { return "Acme-Signature: <hex HMAC-SHA256 of body>" }
func (acmepay) SignatureHeader() string { return "Acme-Signature" }
func (acmepay) Timestamped() bool       { return false }
func (acmepay) MultiSignature() bool    { return false }
func (acmepay) BodySigned() bool        { return true }
func (acmepay) Sign(m Message, secrets ...string) (Headers, error)    { /* ... */ }
func (acmepay) Variants(m Message, secret string) ([]Variant, error) { /* ... */ }
```

`Sign` returns every header the format needs. `Variants` returns respelled and malformed copies of a valid signature header for check 9. Nothing else in the code base has to change. `--scheme acmepay` and `hookprobe schemes` pick it up automatically. `paymongo.go` and `xendit.go` are short, complete examples.

## How HookProbe knows an event was processed

A status code is not enough: a receiver can return 401 and still run the handler, or return 200 to a duplicate and process it again. So HookProbe asks the receiver how many times it processed each event ID. Every check uses its own event ID, so the counts never interfere with each other.

**Option 1 (recommended): a test-only endpoint.** Expose this in test and staging builds only:

```
GET /__hookprobe/events/{id}   ->   200 {"processed": 1}
```

A bare integer body also works, and 404 counts as 0. By default HookProbe calls `<receiver origin>/__hookprobe/events/{id}`. Point it elsewhere with `--processed-url 'http://localhost:9000/debug/events/{id}'`.

Increment the count where the business effect happens (the row is written, the email is queued), not where the request arrives. Otherwise the oracle will report work that never happened.

**Option 2: a command.** If the app has no HTTP surface for this, give a shell command that prints the count. `{id}` is substituted, and the ID is also in `$HOOKPROBE_EVENT_ID`:

```
--processed-cmd "psql -tAc \"select count(*) from processed_events where event_id = '{id}'\""
```

**Option 3: no oracle.** `--status-only` judges on status codes alone and skips the replay and duplicate checks. Use it only when neither option above is possible.

Receivers that answer 2xx and process asynchronously are fine. HookProbe waits `--settle` (300 ms by default) before asking. Raise it if your queue is slower.

## Demo: before and after

`demo/vulnerable` is a receiver for the `hook` format with four deliberate bugs:

1. It verifies the signature over `json.Marshal(parsed)` instead of the raw body.
2. It signs the timestamp but never checks its age.
3. It does not dedupe on the event ID.
4. It has no body size cap and no server timeouts (`http.ListenAndServe`).

`demo/fixed` is the same receiver with those four bugs fixed: `http.MaxBytesReader`, a 5-minute tolerance window, constant-time comparison against every `v1,` signature, dedupe that answers duplicates with 200, and `http.Server` read and write timeouts.

```
go run ./demo/vulnerable          # listens on :8081
go run ./demo/fixed               # listens on :8082
hookprobe --scheme hook --secret demo-secret http://localhost:8081/webhook
hookprobe --scheme hook --secret demo-secret http://localhost:8082/webhook
```

**Before** (`demo/vulnerable`, exit code 1):

```
hookprobe 0.2.0
  target  http://localhost:8081/webhook
  scheme  hook
  oracle  http://localhost:8081/__hookprobe/events/{id}

  PASS   0  baseline             Valid signed request is accepted
  PASS   1  missing-signature    Request with no signature header
  PASS   2  wrong-signature      Request signed with the wrong secret
  FAIL   3  replay               Exact replay of a valid request
                expected  replay is not processed again (count stays at 1)
                got       replay after 2s: HTTP 200, processed 2 times
                an attacker who captures one request can trigger it again inside the timestamp window; dedupe on the event ID
  FAIL   4  stale-timestamp      Valid signature, timestamp outside the window
                expected  rejected with 4xx when more than 5m0s off (set --tolerance to the receiver's window)
                got       2 of 2 cases failed
                FAIL   timestamp 6m0s in the past: HTTP 200, processed once
                FAIL   timestamp 6m0s in the future: HTTP 200, processed once
  FAIL   5  duplicate            Same event ID delivered twice
                expected  redelivery answered with 2xx, processed once in total
                got       redelivery: HTTP 200, processed 2 times
                senders deliver at least once, so the same event will arrive twice; dedupe on the event ID
  FAIL   6  reserialized-body    Body re-serialized after signing
                expected  HTTP 4xx, not processed
                got       HTTP 200, processed once
                signed 140 bytes, sent 172 bytes of the same JSON with other whitespace and key order
                the receiver verifies parsed-and-re-encoded JSON instead of the raw body bytes
  FAIL   7  oversized-body       Oversized body
                expected  HTTP 413 or another 4xx (or the connection is cut), not processed
                got       HTTP 200, processed once
                validly signed body of 10.0 MiB
  FAIL   8  slow-body            Very slow body (slowloris)
                expected  receiver times out the request before 20s
                got       connection still open after 20s, 39 body bytes in
                announced 477 bytes, sent 1 byte every 500ms
                a few hundred such connections can exhaust the receiver; set a read timeout
  PASS   9  header-variants      Signature header case and format variations
  PASS  10  multiple-signatures  Several signatures in one header (rotation)

  FAIL  5 passed, 6 failed, 0 skipped, 0 errors in 27.9s
```

**After** (`demo/fixed`, exit code 0):

```
hookprobe 0.2.0
  target  http://localhost:8082/webhook
  scheme  hook
  oracle  http://localhost:8082/__hookprobe/events/{id}

  PASS   0  baseline             Valid signed request is accepted
  PASS   1  missing-signature    Request with no signature header
  PASS   2  wrong-signature      Request signed with the wrong secret
  PASS   3  replay               Exact replay of a valid request
  PASS   4  stale-timestamp      Valid signature, timestamp outside the window
  PASS   5  duplicate            Same event ID delivered twice
  PASS   6  reserialized-body    Body re-serialized after signing
  PASS   7  oversized-body       Oversized body
  PASS   8  slow-body            Very slow body (slowloris)
  PASS   9  header-variants      Signature header case and format variations
  PASS  10  multiple-signatures  Several signatures in one header (rotation)

  PASS  11 passed, 0 failed, 0 skipped, 0 errors in 12.9s
```

Diff the two files in `demo/` to see exactly what each fix costs. Both reports are pinned by tests (`go test ./demo/...`), so the README cannot drift from the code.

## Install

Download a binary for Linux, macOS or Windows from the [releases page](https://github.com/dadsadadsadad/hookprobe/releases) (checksums in `checksums.txt`), or build from source:

```
go install github.com/dadsadadsadad/hookprobe/cmd/hookprobe@latest
```

Building needs Go 1.27 or later. There are no third-party dependencies.

How it works inside: [ARCHITECTURE.md](ARCHITECTURE.md). Why it works that way: [DESIGN-NOTES.md](DESIGN-NOTES.md).

## Usage

```
hookprobe [flags] <receiver-url>
hookprobe schemes | checks | version
```

| Flag | Default | |
|------|---------|--|
| `--scheme` | required | `stripe`, `github`, `standard-webhooks`, `hook`, `paymongo`, `paymongo-live`, `xendit` |
| `--secret` | `$HOOKPROBE_SECRET` | the secret the receiver holds. Prefer the environment variable to keep it out of shell history |
| `--processed-url` | `<origin>/__hookprobe/events/{id}` | oracle endpoint |
| `--processed-cmd` | | oracle command, instead of the endpoint |
| `--status-only` | `false` | run without an oracle |
| `--tolerance` | `5m` | the receiver's timestamp window; check 4 sends timestamps one minute beyond it |
| `--replay-delay` | `2s` | gap between the original request and its replay |
| `--settle` | `300ms` | wait before asking the oracle |
| `--oversize` | `10MiB` | body size for check 7 |
| `--slow-for` | `20s` | how long check 8 drips the body before failing |
| `--timeout` | `10s` | per-request timeout |
| `--only`, `--skip` | | comma-separated check numbers or keys, e.g. `--skip slow-body` |
| `--event-type` | `hookprobe.test` | type in the payload and type headers, if your receiver routes on it |
| `--body-file` | | JSON payload template (see [Provider-shaped payloads](#provider-shaped-payloads)) |
| `--json` | `false` | machine-readable report on stdout |
| `--json-file` | | also write the JSON report to a file, keeping the text report on stdout |
| `-v` | `false` | show details for passing checks too |
| `--no-color` | `false` | also honors `NO_COLOR` |
| `--insecure` | `false` | skip TLS verification, for self-signed test servers only |

Flags can come before or after the URL.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | every selected check passed or was skipped |
| 1 | at least one check failed or could not run |
| 2 | bad flags, or the baseline check failed (wrong secret, scheme, URL or oracle) |

### JSON output

`--json` prints one document with `passed`, `summary` and a `checks` array. Each check has `id`, `key`, `title`, `status` (`pass`, `fail`, `skip`, `error`), `expected`, `got`, `details` and `duration_ms`.

```json
{
  "tool": "hookprobe",
  "version": "0.2.0",
  "passed": false,
  "summary": { "pass": 2, "fail": 1, "skip": 0, "error": 0 },
  "target": "http://localhost:8081/webhook",
  "scheme": "hook",
  "checks": [
    {
      "id": 6,
      "key": "reserialized-body",
      "title": "Body re-serialized after signing",
      "status": "fail",
      "expected": "HTTP 4xx, not processed",
      "got": "HTTP 200, processed once",
      "details": ["the receiver verifies parsed-and-re-encoded JSON instead of the raw body bytes"],
      "duration_ms": 302
    }
  ]
}
```

## GitHub Actions

Start the receiver in test mode, then use the action. A failed check fails the job. The text report goes to the log, and the JSON report is written to a file you can upload as an artifact.

```yaml
- name: Probe webhook receiver
  id: hookprobe
  uses: dadsadadsadad/hookprobe@v0.2.0
  with:
    url: http://localhost:8080/webhooks/stripe
    scheme: stripe
    secret: ${{ secrets.WEBHOOK_TEST_SECRET }}
    args: --body-file examples/stripe-event.json

- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: hookprobe-report
    path: ${{ steps.hookprobe.outputs.report }}
```

| Input | Default | |
|-------|---------|--|
| `url` | required | receiver URL |
| `scheme` | required | signature format |
| `secret` | required | signing secret, from a repository secret |
| `args` | | any other flags |
| `version` | `latest` | HookProbe version to install |
| `report` | `hookprobe-report.json` | where to write the JSON report |

Outputs: `passed` (`"true"` or `"false"`) and `report` (the JSON report's path).

Without the action, it is one command:

```yaml
- run: |
    go install github.com/dadsadadsadad/hookprobe/cmd/hookprobe@latest
    hookprobe --scheme stripe --json-file hookprobe.json http://localhost:8080/webhooks/stripe
  env:
    HOOKPROBE_SECRET: ${{ secrets.WEBHOOK_TEST_SECRET }}
```

This repository's own workflow (`.github/workflows/ci.yml`) runs the unit tests, probes both demo receivers (asserting that the fixed one exits 0 and the vulnerable one exits 1), and runs the action itself against the fixed receiver.

## Limits

- Only point HookProbe at receivers you own or are allowed to test. Check 7 sends 10 MiB and check 8 holds a connection open.
- Check 8 uses HTTP/1.1 over a raw connection. Receivers behind a proxy that buffers whole requests (many load balancers do) will pass it because of the proxy, which is usually what you want to know anyway.
- HookProbe tests what an attacker can send. It does not read your code, so a receiver that passes may still have bugs in what it does with a verified event.

## License

MIT
