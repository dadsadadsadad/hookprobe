# Architecture

HookProbe is one Go binary with no third-party dependencies. It plays the part of a hostile webhook sender: it builds requests a real provider could send, breaks them on purpose, sends them to the receiver, and asks the receiver what it did with each one.

```
            ┌──────────────── hookprobe ────────────────┐
            │                                            │
 flags ───▶ │  cmd/hookprobe ──▶ probe.Run ──▶ checks    │
            │        │              │           │        │
            │        ▼              ▼           ▼        │
            │     report         scheme       runner ────┼──── POST (hostile request) ──▶  receiver
            │  (text, JSON)   (sign, vary)  (send, ask) ─┼──── GET /__hookprobe/events/{id} ─▶ oracle
            └────────────────────────────────────────────┘
```

## Packages

| Package | Job |
|---------|-----|
| `cmd/hookprobe` | Flags, validation, oracle selection, exit codes. Nothing here decides pass or fail. |
| `internal/scheme` | Signature formats. Each one is a file that registers itself in `init`. A scheme knows how to sign a message and how to break a valid signature header (check 9). It knows nothing about checks. |
| `internal/probe` | The checks, the runner that sends requests and reads the oracle, the payload builder and the oracles. |
| `internal/report` | Renders a `probe.Report` as streaming text or as one JSON document. |
| `demo/vulnerable`, `demo/fixed` | Two receivers for the `hook` format, used by the README, the tests and CI. They import nothing from `internal`: they are what an application would write. |

## How one check runs

Take check 6 (`reserialized-body`):

1. The runner makes a fresh event ID (`evt_` + 24 hex characters) and builds the payload: the built-in canonical body, or the `--body-file` template with its placeholders filled.
2. The scheme signs the original bytes.
3. The check re-serializes the body with the same value but other key order and whitespace, then sends those bytes with the headers signed over the originals.
4. The runner waits `--settle`, then asks the oracle how many times that event ID was processed.
5. The check combines the status code and the count into a `Result`: pass only if the answer was 4xx **and** the count is 0.

Every check follows that shape. The differences are in step 3. Checks with several cases (4, 9, 10) run each case with its own event ID and combine them, so one case's dedupe cannot hide another's result.

## The oracle

A status code says what the receiver *answered*, not what it *did*. The oracle closes that gap. It is an interface with two implementations:

- `HTTPOracle` calls a test-only endpoint, `GET /__hookprobe/events/{id}`, which returns `{"processed": n}` or a bare integer. 404 means 0.
- `CommandOracle` runs a shell command that prints the count, for apps without an HTTP surface for it (a SQL query, a log grep).

With `--status-only` there is no oracle. The checks that only an oracle can judge (3 and 5) report SKIP, and the rest judge on status codes alone.

## The baseline gate

Check 0 sends one correct request. If it is not accepted and counted exactly once, the run stops with exit code 2. A wrong secret, scheme, URL or oracle would otherwise turn every rejection check into a false PASS: "rejected" is easy when everything is rejected.

## Why some requests bypass net/http

`net/http` writes a request body as fast as the connection allows, so check 8 (`slow-body`) opens a raw TCP (or TLS) connection, writes the headers, and drips the body one byte per interval while a goroutine watches for the receiver to answer or hang up.

Everything else goes through `net/http` with redirects disabled, keep-alives off (every probe gets a clean connection) and header names assigned straight into the map, so `x-hook-signature` goes on the wire in lowercase instead of being canonicalized.

## Exit codes

| Code | When |
|------|------|
| 0 | every selected check passed or was skipped |
| 1 | a check failed or could not run |
| 2 | setup problem: bad flags, unreadable body template, or the baseline failed |

CI can tell "the receiver is insecure" (1) from "the test is misconfigured" (2).
