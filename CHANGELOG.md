# Changelog

## 0.2.0

- New schemes: `paymongo` and `paymongo-live` (`Paymongo-Signature`, `te`/`li` fields) and `xendit` (static `x-callback-token`).
- `--body-file`: send a provider-shaped payload from a JSON template (`{{id}}`, `{{type}}`, `{{created}}`, `{{created_rfc3339}}`, `{{check}}`). Starting points for Stripe, PayMongo and Xendit are in `examples/`.
- `--json-file`: write the JSON report to a file and keep the text report on stdout.
- Check 9 now also sends signatures with extra characters appended, which catches receivers that only compare a prefix.
- Check 6 is skipped for formats that do not sign the body.
- The `hook` scheme is pinned to the reference vector published by the Reliable Webhook Delivery Service.
- A reusable GitHub Action (`uses: dadsadadsadad/hookprobe@v0.2.0`).
- Release binaries for Linux, macOS and Windows (amd64 and arm64), with checksums.
- `ARCHITECTURE.md` and `DESIGN-NOTES.md`.

## 0.1.0

- Ten checks and a baseline: missing and wrong signatures, replay, stale timestamps, duplicates, re-serialized bodies, oversized and slow bodies, header variations and secret rotation.
- Schemes: `stripe`, `github`, `standard-webhooks`, `hook`.
- HTTP and command oracles for processed-event counts, or `--status-only`.
- Text and JSON reports, CI exit codes.
- A deliberately vulnerable demo receiver and a fixed one.
