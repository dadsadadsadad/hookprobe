package main

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/dadsadadsadad/hookprobe/internal/probe"
	"github.com/dadsadadsadad/hookprobe/internal/scheme"
)

func TestFixedReceiverPassesEveryCheck(t *testing.T) {
	runFixed(t, nil)
}

// A provider-shaped body must not change the verdict: the receiver verifies
// bytes, whatever they spell.
func TestFixedReceiverPassesWithBodyTemplate(t *testing.T) {
	tmpl, err := os.ReadFile("../../examples/stripe-event.json")
	if err != nil {
		t.Fatal(err)
	}
	runFixed(t, tmpl)
}

func runFixed(t *testing.T, bodyTemplate []byte) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.Config = newServer("", newReceiver("demo-secret").routes())
	srv.Config.ReadTimeout = time.Second // keep the slow-body check short
	srv.Start()
	defer srv.Close()

	hook, _ := scheme.Get("hook")
	rep := probe.Run(context.Background(), probe.Config{
		URL:           srv.URL + "/webhook",
		Scheme:        hook,
		Secret:        "demo-secret",
		BodyTemplate:  bodyTemplate,
		Oracle:        probe.HTTPOracle{Template: srv.URL + "/__hookprobe/events/{id}"},
		ReplayDelay:   50 * time.Millisecond,
		Settle:        10 * time.Millisecond,
		OversizeBytes: 2 << 20,
		SlowFor:       3 * time.Second,
		SlowInterval:  100 * time.Millisecond,
	})
	if rep.Aborted != "" {
		t.Fatalf("aborted: %s", rep.Aborted)
	}
	if len(rep.Results) != len(probe.Checks()) {
		t.Fatalf("ran %d checks, want %d", len(rep.Results), len(probe.Checks()))
	}
	for _, r := range rep.Results {
		if r.Status != probe.Pass {
			t.Errorf("%d %s: %s (got %s) %v", r.ID, r.Key, r.Status, r.Got, r.Details)
		}
	}
}
