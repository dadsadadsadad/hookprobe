package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dadsadadsadad/hookprobe/internal/scheme"
)

type runner struct {
	cfg    Config
	client *http.Client
}

func (x *runner) newID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "evt_" + hex.EncodeToString(b)
}

func randomSecret() string {
	b := make([]byte, 24)
	rand.Read(b)
	return "whsec_" + base64.StdEncoding.EncodeToString(b)
}

func (x *runner) message(id, check string, ts time.Time, pad int) scheme.Message {
	body := buildBody(id, x.cfg.EventType, check, ts, pad)
	if x.cfg.BodyTemplate != nil {
		// Validated up front by Run, so an error here cannot happen.
		body, _ = RenderTemplate(x.cfg.BodyTemplate, id, x.cfg.EventType, check, ts, pad)
	}
	return scheme.Message{
		ID:        id,
		Type:      x.cfg.EventType,
		Timestamp: ts,
		Attempt:   1,
		Body:      body,
	}
}

type response struct {
	status int
	err    error
}

func (r response) ok() bool          { return r.err == nil && r.status/100 == 2 }
func (r response) clientError() bool { return r.err == nil && r.status/100 == 4 }

func (r response) String() string {
	if r.err != nil {
		err := r.err
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return "no response (" + err.Error() + ")"
	}
	return fmt.Sprintf("HTTP %d", r.status)
}

func (x *runner) send(ctx context.Context, body []byte, h scheme.Headers) response {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, x.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return response{err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent())
	for _, kv := range h {
		// Assign directly so the name goes on the wire exactly as spelled.
		req.Header[kv.Name] = append(req.Header[kv.Name], kv.Value)
	}
	resp, err := x.client.Do(req)
	if err != nil {
		return response{err: err}
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	return response{status: resp.StatusCode}
}

// processed asks the oracle how often the receiver processed id. It returns
// -1 when there is no oracle.
func (x *runner) processed(ctx context.Context, id string) (int, error) {
	if x.cfg.Oracle == nil {
		return -1, nil
	}
	if err := sleep(ctx, x.cfg.Settle); err != nil {
		return 0, err
	}
	n, err := x.cfg.Oracle.Count(ctx, id)
	if err != nil {
		return 0, fmt.Errorf("oracle: %w", err)
	}
	return n, nil
}

func describe(r response, n int) string {
	s := r.String()
	switch {
	case n < 0:
		return s
	case n == 0:
		return s + ", not processed"
	case n == 1:
		return s + ", processed once"
	default:
		return fmt.Sprintf("%s, processed %d times", s, n)
	}
}

type outcome struct {
	ok  bool
	got string
	err error
}

func (x *runner) expectAccept(ctx context.Context, m scheme.Message, h scheme.Headers) outcome {
	resp := x.send(ctx, m.Body, h)
	if resp.err != nil {
		return outcome{err: fmt.Errorf("request failed: %s", resp)}
	}
	n, err := x.processed(ctx, m.ID)
	if err != nil {
		return outcome{err: err}
	}
	return outcome{ok: resp.ok() && (n < 0 || n == 1), got: describe(resp, n)}
}

// expectReject sends body with headers h. With dropOK a cut connection
// counts as a rejection.
func (x *runner) expectReject(ctx context.Context, m scheme.Message, h scheme.Headers, body []byte, dropOK bool) outcome {
	resp := x.send(ctx, body, h)
	if resp.err != nil && !dropOK {
		return outcome{err: fmt.Errorf("request failed: %s", resp)}
	}
	n, err := x.processed(ctx, m.ID)
	if err != nil {
		return outcome{err: err}
	}
	rejected := resp.clientError() || (dropOK && resp.err != nil)
	return outcome{ok: rejected && n <= 0, got: describe(resp, n)}
}

func single(expected string, o outcome) Result {
	if o.err != nil {
		return Result{Status: Error, Expected: expected, Got: o.err.Error()}
	}
	if o.ok {
		return Result{Status: Pass, Expected: expected, Got: o.got}
	}
	return Result{Status: Fail, Expected: expected, Got: o.got}
}

type subcase struct {
	name string
	o    outcome
}

func combine(expected string, subs []subcase) Result {
	r := Result{Status: Pass, Expected: expected}
	failed, errored := 0, 0
	for _, s := range subs {
		switch {
		case s.o.err != nil:
			errored++
			r.Details = append(r.Details, "error  "+s.name+": "+s.o.err.Error())
		case s.o.ok:
			r.Details = append(r.Details, "pass   "+s.name+": "+s.o.got)
		default:
			failed++
			r.Details = append(r.Details, "FAIL   "+s.name+": "+s.o.got)
		}
	}
	switch {
	case failed > 0:
		r.Status = Fail
		r.Got = fmt.Sprintf("%d of %d cases failed", failed, len(subs))
	case errored > 0:
		r.Status = Error
		r.Got = fmt.Sprintf("%d of %d cases could not run", errored, len(subs))
	default:
		r.Got = fmt.Sprintf("all %d cases passed", len(subs))
	}
	return r
}

func skip(reason string) Result { return Result{Status: Skip, Got: reason} }

func errResult(err error) Result { return Result{Status: Error, Got: err.Error()} }

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func byteSize(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}

type slowResult struct {
	closed bool
	after  time.Duration
	how    string
	sent   int
	err    error
}

// slowSend writes the headers at once, then drips the body one byte per
// SlowInterval until the receiver answers or closes, or SlowFor runs out. It
// uses a raw connection because net/http writes bodies as fast as it can.
func (x *runner) slowSend(ctx context.Context, body []byte, h scheme.Headers) slowResult {
	u, err := url.Parse(x.cfg.URL)
	if err != nil {
		return slowResult{err: err}
	}
	addr := u.Host
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		addr = net.JoinHostPort(u.Hostname(), port)
	}
	d := net.Dialer{Timeout: x.cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return slowResult{err: err}
	}
	if u.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: x.cfg.Insecure})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return slowResult{err: err}
		}
		conn = tc
	}
	defer conn.Close()

	var b strings.Builder
	fmt.Fprintf(&b, "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n",
		u.RequestURI(), u.Host, userAgent(), len(body))
	for _, kv := range h {
		fmt.Fprintf(&b, "%s: %s\r\n", kv.Name, kv.Value)
	}
	b.WriteString("\r\n")
	conn.SetWriteDeadline(time.Now().Add(x.cfg.Timeout))
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return slowResult{err: err}
	}

	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		line := "connection closed"
		if n > 0 {
			line = string(buf[:n])
			if i := strings.Index(line, "\r\n"); i >= 0 {
				line = line[:i]
			}
		}
		done <- line
	}()

	start := time.Now()
	tick := time.NewTicker(x.cfg.SlowInterval)
	defer tick.Stop()
	sent := 0
	for {
		select {
		case how := <-done:
			return slowResult{closed: true, after: time.Since(start), how: how, sent: sent}
		case <-ctx.Done():
			return slowResult{err: ctx.Err()}
		case <-tick.C:
			if time.Since(start) >= x.cfg.SlowFor {
				return slowResult{after: time.Since(start), sent: sent}
			}
			if sent < len(body) {
				conn.SetWriteDeadline(time.Now().Add(x.cfg.Timeout))
				if _, err := conn.Write(body[sent : sent+1]); err != nil {
					return slowResult{closed: true, after: time.Since(start), how: "connection closed", sent: sent}
				}
				sent++
			}
		}
	}
}
