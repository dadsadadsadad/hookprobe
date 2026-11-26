package probe

import (
	"context"
	"fmt"
	"time"

	"github.com/dadsadadsadad/hookprobe/internal/scheme"
)

const (
	wantAccept = "HTTP 2xx, processed once"
	wantReject = "HTTP 4xx, not processed"
	needOracle = "needs a processed-event oracle (--processed-url or --processed-cmd)"
)

func (x *runner) baseline(ctx context.Context) Result {
	m := x.message(x.newID(), "baseline", time.Now(), 0)
	h, err := x.sign(m, x.cfg.Secret)
	if err != nil {
		return errResult(err)
	}
	r := single(wantAccept, x.expectAccept(ctx, m, h))
	if r.Status == Fail {
		r.Details = append(r.Details, "check the URL, --scheme, --secret and the oracle before reading anything else")
	}
	return r
}

func (x *runner) missingSignature(ctx context.Context) Result {
	m := x.message(x.newID(), "missing-signature", time.Now(), 0)
	h, err := x.sign(m, x.cfg.Secret)
	if err != nil {
		return errResult(err)
	}
	h = h.Without(x.cfg.Scheme.SignatureHeader())
	return single(wantReject, x.expectReject(ctx, m, h, m.Body, false))
}

func (x *runner) wrongSignature(ctx context.Context) Result {
	m := x.message(x.newID(), "wrong-signature", time.Now(), 0)
	h, err := x.sign(m, randomSecret())
	if err != nil {
		return errResult(err)
	}
	return single(wantReject, x.expectReject(ctx, m, h, m.Body, false))
}

func (x *runner) replay(ctx context.Context) Result {
	if x.cfg.Oracle == nil {
		return skip(needOracle)
	}
	m := x.message(x.newID(), "replay", time.Now(), 0)
	h, err := x.sign(m, x.cfg.Secret)
	if err != nil {
		return errResult(err)
	}
	const want = "replay is not processed again (count stays at 1)"
	first := x.send(ctx, m.Body, h)
	if !first.ok() {
		return Result{Status: Fail, Expected: want, Got: "the original request was not accepted: " + first.String()}
	}
	if err := sleep(ctx, x.cfg.ReplayDelay); err != nil {
		return errResult(err)
	}
	again := x.send(ctx, m.Body, h)
	if again.err != nil {
		return errResult(fmt.Errorf("replay request failed: %w", again.err))
	}
	n, err := x.processed(ctx, m.ID)
	if err != nil {
		return errResult(err)
	}
	r := Result{Status: Pass, Expected: want, Got: fmt.Sprintf("replay after %s: %s", x.cfg.ReplayDelay, describe(again, n))}
	if n != 1 || again.status/100 == 5 {
		r.Status = Fail
		r.Details = append(r.Details, "an attacker who captures one request can trigger it again inside the timestamp window; dedupe on the event ID")
	}
	return r
}

func (x *runner) staleTimestamp(ctx context.Context) Result {
	if !x.cfg.Scheme.Timestamped() {
		return skip(fmt.Sprintf("the %s format does not sign a timestamp", x.cfg.Scheme.Name()))
	}
	off := x.cfg.Tolerance + time.Minute
	cases := []struct {
		name string
		ts   time.Time
	}{
		{fmt.Sprintf("timestamp %s in the past", off), time.Now().Add(-off)},
		{fmt.Sprintf("timestamp %s in the future", off), time.Now().Add(off)},
	}
	var subs []subcase
	for _, c := range cases {
		m := x.message(x.newID(), "stale-timestamp", c.ts, 0)
		h, err := x.sign(m, x.cfg.Secret)
		if err != nil {
			return errResult(err)
		}
		subs = append(subs, subcase{c.name, x.expectReject(ctx, m, h, m.Body, false)})
	}
	return combine(fmt.Sprintf("rejected with 4xx when more than %s off (set --tolerance to the receiver's window)", x.cfg.Tolerance), subs)
}

func (x *runner) duplicate(ctx context.Context) Result {
	if x.cfg.Oracle == nil {
		return skip(needOracle)
	}
	const want = "redelivery answered with 2xx, processed once in total"
	first := x.message(x.newID(), "duplicate", time.Now(), 0)
	h1, err := x.sign(first, x.cfg.Secret)
	if err != nil {
		return errResult(err)
	}
	if r := x.send(ctx, first.Body, h1); !r.ok() {
		return Result{Status: Fail, Expected: want, Got: "the first delivery was not accepted: " + r.String()}
	}
	// A legitimate retry: same event ID and body, fresh timestamp and signature.
	retry := first
	retry.Timestamp = first.Timestamp.Add(time.Second)
	retry.Attempt = 2
	h2, err := x.sign(retry, x.cfg.Secret)
	if err != nil {
		return errResult(err)
	}
	resp := x.send(ctx, retry.Body, h2)
	if resp.err != nil {
		return errResult(fmt.Errorf("redelivery failed: %w", resp.err))
	}
	n, err := x.processed(ctx, first.ID)
	if err != nil {
		return errResult(err)
	}
	r := Result{Status: Pass, Expected: want, Got: "redelivery: " + describe(resp, n)}
	if n != 1 {
		r.Status = Fail
		r.Details = append(r.Details, "senders deliver at least once, so the same event will arrive twice; dedupe on the event ID")
	}
	if !resp.ok() {
		r.Status = Fail
		r.Details = append(r.Details, "answering a duplicate with a non-2xx status makes the sender keep retrying it")
	}
	return r
}

func (x *runner) reserializedBody(ctx context.Context) Result {
	if !x.cfg.Scheme.BodySigned() {
		return skip(fmt.Sprintf("the %s format does not sign the body, so a valid token covers any body", x.cfg.Scheme.Name()))
	}
	m := x.message(x.newID(), "reserialized-body", time.Now(), 0)
	h, err := x.sign(m, x.cfg.Secret)
	if err != nil {
		return errResult(err)
	}
	alt, err := reserialize(m.Body)
	if err != nil {
		return errResult(err)
	}
	r := single(wantReject, x.expectReject(ctx, m, h, alt, false))
	r.Details = append(r.Details, fmt.Sprintf("signed %d bytes, sent %d bytes of the same JSON with other whitespace and key order", len(m.Body), len(alt)))
	if r.Status == Fail {
		r.Details = append(r.Details, "the receiver verifies parsed-and-re-encoded JSON instead of the raw body bytes")
	}
	return r
}

func (x *runner) oversizedBody(ctx context.Context) Result {
	id := x.newID()
	now := time.Now()
	pad := x.cfg.OversizeBytes - len(x.message(id, "oversized-body", now, 0).Body)
	if pad < 0 {
		pad = 0
	}
	m := x.message(id, "oversized-body", now, pad)
	h, err := x.sign(m, x.cfg.Secret)
	if err != nil {
		return errResult(err)
	}
	r := single("HTTP 413 or another 4xx (or the connection is cut), not processed", x.expectReject(ctx, m, h, m.Body, true))
	r.Details = append(r.Details, fmt.Sprintf("validly signed body of %s", byteSize(len(m.Body))))
	return r
}

func (x *runner) slowBody(ctx context.Context) Result {
	pad := int(x.cfg.SlowFor/x.cfg.SlowInterval)*2 + 256
	m := x.message(x.newID(), "slow-body", time.Now(), pad)
	h, err := x.sign(m, x.cfg.Secret)
	if err != nil {
		return errResult(err)
	}
	res := x.slowSend(ctx, m.Body, h)
	if res.err != nil {
		return errResult(res.err)
	}
	want := fmt.Sprintf("receiver times out the request before %s", x.cfg.SlowFor)
	detail := fmt.Sprintf("announced %s, sent 1 byte every %s", byteSize(len(m.Body)), x.cfg.SlowInterval)
	if res.closed {
		return Result{Status: Pass, Expected: want, Details: []string{detail},
			Got: fmt.Sprintf("receiver gave up after %.1fs (%s)", res.after.Seconds(), res.how)}
	}
	return Result{Status: Fail, Expected: want,
		Got:     fmt.Sprintf("connection still open after %s, %d body bytes in", x.cfg.SlowFor, res.sent),
		Details: []string{detail, "a few hundred such connections can exhaust the receiver; set a read timeout"}}
}

func (x *runner) headerVariants(ctx context.Context) Result {
	probe := x.message(x.newID(), "header-variants", time.Now(), 0)
	list, err := x.cfg.Scheme.Variants(probe, x.cfg.Secret)
	if err != nil {
		return errResult(err)
	}
	var subs []subcase
	for i := range list {
		// Fresh event per variant so dedupe on one cannot mask another.
		m := x.message(x.newID(), "header-variants", time.Now(), 0)
		vs, err := x.cfg.Scheme.Variants(m, x.cfg.Secret)
		if err != nil {
			return errResult(err)
		}
		v := vs[i]
		name := "reject " + v.Name
		var o outcome
		if v.Accept {
			name = "accept " + v.Name
			o = x.expectAccept(ctx, m, v.Headers)
		} else {
			o = x.expectReject(ctx, m, v.Headers, m.Body, false)
		}
		subs = append(subs, subcase{name, o})
	}
	return combine("spellings HTTP treats as equal are accepted; malformed values are rejected", subs)
}

func (x *runner) multipleSignatures(ctx context.Context) Result {
	if !x.cfg.Scheme.MultiSignature() {
		return skip(fmt.Sprintf("the %s format carries one signature per request", x.cfg.Scheme.Name()))
	}
	retired := randomSecret()
	cases := []struct {
		name    string
		secrets []string
		accept  bool
	}{
		{"accept unknown signature first, valid second", []string{retired, x.cfg.Secret}, true},
		{"accept valid signature first, unknown second", []string{x.cfg.Secret, retired}, true},
		{"reject two unknown signatures", []string{retired, randomSecret()}, false},
	}
	var subs []subcase
	for _, c := range cases {
		m := x.message(x.newID(), "multiple-signatures", time.Now(), 0)
		h, err := x.sign(m, c.secrets...)
		if err != nil {
			return errResult(err)
		}
		var o outcome
		if c.accept {
			o = x.expectAccept(ctx, m, h)
		} else {
			o = x.expectReject(ctx, m, h, m.Body, false)
		}
		subs = append(subs, subcase{c.name, o})
	}
	return combine("accepted when any one signature matches, rejected when none does", subs)
}

// sign is a small wrapper so every check reports signing errors the same way.
func (x *runner) sign(m scheme.Message, secrets ...string) (scheme.Headers, error) {
	return x.cfg.Scheme.Sign(m, secrets...)
}
