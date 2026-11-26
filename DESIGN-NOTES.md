# Design notes

Decisions that are not obvious from the code, with the reason for each.

## D1. Judge on processing, not on status codes

A receiver can answer 401 and still run the handler (it verified after doing the work), or answer 200 to a duplicate and process it twice. Status codes alone would pass both. So every check asks an oracle how many times the event was processed. The alternatives were parsing the receiver's logs (format differs per app) and timing (unreliable). A test-only count endpoint is the smallest contract an app can expose, and the command oracle covers apps that cannot.

## D2. One event ID per request

Each check, and each case inside a check, uses a fresh random event ID. Counts never bleed between checks, the run order does not matter, and a receiver's dedupe on one case cannot mask a bug in the next. The cost is that HookProbe never tests dedupe *across* checks, which no real attack needs.

## D3. A baseline that can stop the run

Without check 0, a misconfigured run (wrong secret) makes every rejection check pass, because the receiver rejects everything. That is the most dangerous failure a security tool can have: green when it should be red. So the baseline must pass, or the run exits 2 and reports nothing else as meaningful.

## D4. The built-in payload is canonical JSON

The default body is compact with sorted keys, the exact bytes `encoding/json` produces for it. This is deliberate. A receiver that verifies `json.Marshal(parsed)` instead of the raw body passes the baseline with these bytes (they survive the round trip), so check 6 can then show the real bug: re-ordered, re-spaced bytes also verify. With a non-canonical baseline body that receiver would fail check 0, and the report would blame the setup instead of the bug.

## D5. 5xx is a failure even when the request is bad

Rejecting a forged request with 500 keeps the attacker out, but senders retry on 5xx, so a probe that should be dropped once turns into a retry storm, and a crash is often what produced the 500. Bad requests get 4xx.

## D6. A duplicate must be answered with 2xx

Check 5 fails a receiver that dedupes correctly but answers the redelivery with 409. Senders (Stripe, GitHub, the Reliable Webhook Delivery Service) treat any non-2xx as "retry later", so that receiver gets the same event forever.

## D7. Checks that cannot apply are skipped, not passed

GitHub signs no timestamp, so "old timestamp is rejected" is untestable. Reporting PASS would claim a protection that does not exist. Reporting FAIL would punish the receiver for its provider's format. SKIP, with the reason, says exactly what is true. Skips do not affect the exit code.

## D8. Scheme variants live with the scheme

Check 9 needs malformed signature headers, and what counts as malformed is format-specific (`sha1=` means something only to GitHub). So each scheme returns its own variants, and the check only knows "accept these, reject those". A new scheme brings its own hostile cases without touching the checks.

## D9. Only unambiguous variants

Check 9 tests only cases with one correct answer: header names in another case (HTTP says they are equal: accept), and wrong prefixes, truncated or extended signatures, and empty values (reject). Uppercase hex, whitespace inside values and duplicate headers were left out. Provider libraries disagree on them, and a check that fails correct receivers teaches people to ignore the tool.

## D10. Static tokens are a scheme too

Xendit authenticates callbacks with a fixed token instead of an HMAC. It still fits the interface: `Sign` returns the token header, and `BodySigned` returns false, so the re-serialization check reports SKIP. The report then makes the real risk plain. With no body signature and no timestamp, replay protection rests entirely on deduping the event ID.

## D11. A JSON template rather than per-provider payload code

Receivers built on provider libraries parse the event before trusting it. Stripe's library checks `api_version`, and PayMongo receivers read `data.attributes.livemode`. Rather than hard-code one payload per provider (which would go stale), `--body-file` takes a template with placeholders, and `examples/` holds a starting point for each provider. Oversized bodies pad a template with trailing whitespace, which keeps the JSON valid without guessing where a padding field would be safe.

## D12. No dependencies

The tool sends hostile traffic with a secret in hand. Every dependency would be code with access to that secret. The standard library covers HTTP, TLS, HMAC and JSON, so there are none, and `go install` is the whole installation.
