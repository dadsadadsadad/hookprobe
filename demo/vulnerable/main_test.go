package main

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dadsadadsadad/hookprobe/internal/probe"
	"github.com/dadsadadsadad/hookprobe/internal/scheme"
)

// Each bug in this receiver must show up as a failed check, and nothing else
// may fail, so the README's before/after report stays honest.
func TestVulnerableReceiverFailsExactlyTheBuggyChecks(t *testing.T) {
	srv := httptest.NewServer(newReceiver("demo-secret").routes())
	defer srv.Close()

	hook, _ := scheme.Get("hook")
	rep := probe.Run(context.Background(), probe.Config{
		URL:           srv.URL + "/webhook",
		Scheme:        hook,
		Secret:        "demo-secret",
		Oracle:        probe.HTTPOracle{Template: srv.URL + "/__hookprobe/events/{id}"},
		ReplayDelay:   50 * time.Millisecond,
		Settle:        10 * time.Millisecond,
		OversizeBytes: 2 << 20,
		SlowFor:       2 * time.Second,
		SlowInterval:  100 * time.Millisecond,
	})

	want := map[string]probe.Status{
		"baseline":            probe.Pass,
		"missing-signature":   probe.Pass,
		"wrong-signature":     probe.Pass,
		"replay":              probe.Fail, // BUG 3
		"stale-timestamp":     probe.Fail, // BUG 2
		"duplicate":           probe.Fail, // BUG 3
		"reserialized-body":   probe.Fail, // BUG 1
		"oversized-body":      probe.Fail, // BUG 4
		"slow-body":           probe.Fail, // BUG 4
		"header-variants":     probe.Pass,
		"multiple-signatures": probe.Pass,
	}
	if len(rep.Results) != len(want) {
		t.Fatalf("ran %d checks, want %d (aborted: %q)", len(rep.Results), len(want), rep.Aborted)
	}
	for _, r := range rep.Results {
		if r.Status != want[r.Key] {
			t.Errorf("%d %s: %s, want %s (got %s) %v", r.ID, r.Key, r.Status, want[r.Key], r.Got, r.Details)
		}
	}
}
