// Package probe sends hostile requests to a webhook receiver and judges the
// answers.
package probe

import (
	"context"
	"crypto/tls"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dadsadadsadad/hookprobe/internal/scheme"
)

// Version is the HookProbe release. Release builds set it with
// -ldflags "-X github.com/dadsadadsadad/hookprobe/internal/probe.Version=...".
var Version = "0.2.0"

func userAgent() string { return "hookprobe/" + Version }

// Status is the outcome of one check.
type Status string

const (
	Pass  Status = "pass"
	Fail  Status = "fail"
	Skip  Status = "skip"
	Error Status = "error"
)

// Result is the outcome of one check.
type Result struct {
	ID         int      `json:"id"`
	Key        string   `json:"key"`
	Title      string   `json:"title"`
	Status     Status   `json:"status"`
	Expected   string   `json:"expected,omitempty"`
	Got        string   `json:"got,omitempty"`
	Details    []string `json:"details,omitempty"`
	DurationMS int64    `json:"duration_ms"`
}

// Check is one test HookProbe can run.
type Check struct {
	ID    int
	Key   string
	Title string
	run   func(*runner, context.Context) Result
}

var checks = []Check{
	{0, "baseline", "Valid signed request is accepted", (*runner).baseline},
	{1, "missing-signature", "Request with no signature header", (*runner).missingSignature},
	{2, "wrong-signature", "Request signed with the wrong secret", (*runner).wrongSignature},
	{3, "replay", "Exact replay of a valid request", (*runner).replay},
	{4, "stale-timestamp", "Valid signature, timestamp outside the window", (*runner).staleTimestamp},
	{5, "duplicate", "Same event ID delivered twice", (*runner).duplicate},
	{6, "reserialized-body", "Body re-serialized after signing", (*runner).reserializedBody},
	{7, "oversized-body", "Oversized body", (*runner).oversizedBody},
	{8, "slow-body", "Very slow body (slowloris)", (*runner).slowBody},
	{9, "header-variants", "Signature header case and format variations", (*runner).headerVariants},
	{10, "multiple-signatures", "Several signatures in one header (rotation)", (*runner).multipleSignatures},
}

// Checks returns every check in run order. Check 0 (baseline) always runs.
func Checks() []Check { return append([]Check(nil), checks...) }

// Lookup finds a check by number or key.
func Lookup(token string) (Check, bool) {
	token = strings.TrimSpace(strings.ToLower(token))
	n, numErr := strconv.Atoi(token)
	for _, c := range checks {
		if c.Key == token || (numErr == nil && c.ID == n) {
			return c, true
		}
	}
	return Check{}, false
}

// Config describes one probe run.
type Config struct {
	URL       string
	Scheme    scheme.Scheme
	Secret    string
	EventType string

	// BodyTemplate replaces the built-in payload with a JSON template using
	// {{id}}, {{type}}, {{created}}, {{created_rfc3339}} and {{check}}.
	// Check it with RenderTemplate before calling Run.
	BodyTemplate []byte

	// Oracle reports how many times the receiver processed an event. Nil
	// means status-only mode: checks that need a count are skipped.
	Oracle Oracle

	Tolerance     time.Duration // receiver's timestamp window
	ReplayDelay   time.Duration // wait before replaying a captured request
	Settle        time.Duration // wait before asking the oracle, for async receivers
	OversizeBytes int
	SlowFor       time.Duration // how long the slow body keeps dripping
	SlowInterval  time.Duration // gap between body bytes
	Timeout       time.Duration // per request
	Insecure      bool          // skip TLS verification

	// Selected filters checks; nil runs all of them.
	Selected func(Check) bool
	OnStart  func(Check)
	OnResult func(Result)
}

func (c *Config) defaults() {
	set := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	set(&c.Tolerance, 5*time.Minute)
	set(&c.ReplayDelay, 2*time.Second)
	set(&c.Settle, 300*time.Millisecond)
	set(&c.SlowFor, 20*time.Second)
	set(&c.SlowInterval, 500*time.Millisecond)
	set(&c.Timeout, 10*time.Second)
	if c.OversizeBytes == 0 {
		c.OversizeBytes = 10 << 20
	}
	if c.EventType == "" {
		c.EventType = "hookprobe.test"
	}
}

// Summary counts results by status.
type Summary struct {
	Pass  int `json:"pass"`
	Fail  int `json:"fail"`
	Skip  int `json:"skip"`
	Error int `json:"error"`
}

// Report is the outcome of a run.
type Report struct {
	Target     string    `json:"target"`
	Scheme     string    `json:"scheme"`
	Oracle     string    `json:"oracle"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	Aborted    string    `json:"aborted,omitempty"`
	Results    []Result  `json:"checks"`
}

// Summary counts the results by status.
func (r Report) Summary() Summary {
	var s Summary
	for _, x := range r.Results {
		switch x.Status {
		case Pass:
			s.Pass++
		case Fail:
			s.Fail++
		case Skip:
			s.Skip++
		case Error:
			s.Error++
		}
	}
	return s
}

// Passed reports whether nothing failed, errored or stopped the run.
func (r Report) Passed() bool {
	s := r.Summary()
	return r.Aborted == "" && s.Fail == 0 && s.Error == 0
}

// Run executes the selected checks in order.
func Run(ctx context.Context, cfg Config) Report {
	cfg.defaults()
	x := &runner{cfg: cfg, client: newClient(cfg)}
	rep := Report{Target: cfg.URL, Scheme: cfg.Scheme.Name(), Oracle: "none (status only)", StartedAt: time.Now().UTC()}
	if cfg.Oracle != nil {
		rep.Oracle = cfg.Oracle.Describe()
	}
	start := time.Now()
	for _, c := range checks {
		if c.ID != 0 && cfg.Selected != nil && !cfg.Selected(c) {
			continue
		}
		if ctx.Err() != nil {
			rep.Aborted = "interrupted"
			break
		}
		if cfg.OnStart != nil {
			cfg.OnStart(c)
		}
		t := time.Now()
		r := c.run(x, ctx)
		r.ID, r.Key, r.Title = c.ID, c.Key, c.Title
		r.DurationMS = time.Since(t).Milliseconds()
		rep.Results = append(rep.Results, r)
		if cfg.OnResult != nil {
			cfg.OnResult(r)
		}
		if c.ID == 0 && r.Status != Pass {
			rep.Aborted = "the baseline check did not pass, so the other checks would prove nothing"
			break
		}
	}
	rep.DurationMS = time.Since(start).Milliseconds()
	return rep
}

func newClient(cfg Config) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DisableKeepAlives = true // every probe gets a clean connection
	if cfg.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
