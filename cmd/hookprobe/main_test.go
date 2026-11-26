package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// acceptAll is a receiver that processes everything, signed or not.
func acceptAll() *httptest.Server {
	var mu sync.Mutex
	seen := map[string]int{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /webhook", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Header.Get("X-Hook-Event-Id")]++
		mu.Unlock()
	})
	mux.HandleFunc("GET /__hookprobe/events/{id}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(w, `{"processed": %d}`, seen[r.PathValue("id")])
	})
	return httptest.NewServer(mux)
}

func TestJSONReportAndExitCode(t *testing.T) {
	srv := acceptAll()
	defer srv.Close()
	var out, errOut bytes.Buffer
	code := run([]string{"--scheme", "hook", "--secret", "s", "--json", "--only", "1,2", "--settle", "1ms", srv.URL + "/webhook"}, &out, &errOut)
	if code != exitFail {
		t.Fatalf("exit %d, want %d; stderr: %s", code, exitFail, errOut.String())
	}
	var doc struct {
		Passed  bool
		Summary struct{ Pass, Fail int }
		Checks  []struct{ Key, Status string }
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out.String())
	}
	if doc.Passed || doc.Summary.Pass != 1 || doc.Summary.Fail != 2 || len(doc.Checks) != 3 {
		t.Fatalf("unexpected report: %+v", doc)
	}
}

func TestFlagsAfterURL(t *testing.T) {
	srv := acceptAll()
	defer srv.Close()
	var out, errOut bytes.Buffer
	code := run([]string{srv.URL + "/webhook", "--scheme", "hook", "--secret", "s", "--only", "baseline", "--settle", "1ms", "--no-color"}, &out, &errOut)
	if code != exitPass {
		t.Fatalf("exit %d, want %d; stderr: %s\n%s", code, exitPass, errOut.String(), out.String())
	}
	if !strings.Contains(out.String(), "PASS   0  baseline") {
		t.Fatalf("missing baseline line:\n%s", out.String())
	}
}

func TestJSONFileKeepsTextOnStdout(t *testing.T) {
	srv := acceptAll()
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "r.json")
	var out, errOut bytes.Buffer
	run([]string{"--scheme", "hook", "--secret", "s", "--only", "1", "--settle", "1ms", "--no-color", "--json-file", path, srv.URL + "/webhook"}, &out, &errOut)
	if !strings.Contains(out.String(), "missing-signature") {
		t.Fatalf("text report missing:\n%s", out.String())
	}
	b, err := os.ReadFile(path)
	if err != nil || !json.Valid(b) {
		t.Fatalf("json file: %v\n%s", err, b)
	}
}

func TestBodyFileValidated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(path, []byte(`{"id": {{id}}}`), 0o600)
	var out, errOut bytes.Buffer
	if code := run([]string{"--scheme", "hook", "--secret", "s", "--body-file", path, "http://localhost/x"}, &out, &errOut); code != exitSetup {
		t.Fatalf("exit %d, want %d", code, exitSetup)
	}
	if !strings.Contains(errOut.String(), "not valid JSON") {
		t.Fatalf("stderr: %s", errOut.String())
	}
}

func TestSetupErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no scheme":     {"--secret", "s", "http://localhost/x"},
		"bad scheme":    {"--scheme", "nope", "--secret", "s", "http://localhost/x"},
		"no secret":     {"--scheme", "hook", "http://localhost/x"},
		"bad url":       {"--scheme", "hook", "--secret", "s", "localhost/x"},
		"unknown check": {"--scheme", "hook", "--secret", "s", "--only", "99", "http://localhost/x"},
	} {
		t.Setenv("HOOKPROBE_SECRET", "")
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != exitSetup {
			t.Errorf("%s: exit %d, want %d", name, code, exitSetup)
		}
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int{"512": 512, "64KB": 64000, "10MiB": 10 << 20, "1.5kib": 1536} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
}
