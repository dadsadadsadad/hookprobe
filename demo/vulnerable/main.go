// Command vulnerable is a webhook receiver with four deliberate bugs. It is
// the "before" half of the README report. Do not copy it.
//
// It accepts the X-Hook-* format (hookprobe --scheme hook) on POST /webhook.
//
//	BUG 1  verifies the signature over re-encoded JSON, not the raw body
//	BUG 2  never checks the timestamp's age, so old requests replay forever
//	BUG 3  no dedupe on the event ID, so retries and replays run twice
//	BUG 4  no body size cap and no server timeouts
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

type receiver struct {
	secret []byte

	mu        sync.Mutex
	processed map[string]int
}

func newReceiver(secret string) *receiver {
	return &receiver{secret: []byte(secret), processed: map[string]int{}}
}

func (rc *receiver) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /webhook", rc.webhook)
	// Test-only: lets HookProbe see what was processed. Never ship this.
	mux.HandleFunc("GET /__hookprobe/events/{id}", rc.count)
	return mux
}

func (rc *receiver) webhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body) // BUG 4: reads as much as the client sends
	if err != nil {
		http.Error(w, "could not read body", http.StatusBadRequest)
		return
	}

	var event map[string]any
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	// BUG 1: the signature should cover the bytes that arrived. Re-encoding
	// throws away whitespace and key order, so a body nobody signed can still
	// verify.
	signed, _ := json.Marshal(event)

	id := r.Header.Get("X-Hook-Event-Id")
	ts := r.Header.Get("X-Hook-Timestamp")
	if id == "" || ts == "" {
		http.Error(w, "missing delivery headers", http.StatusBadRequest)
		return
	}
	// BUG 2: ts is part of the signed content but its age is never checked.
	if !rc.verify(id, ts, signed, r.Header.Get("X-Hook-Signature")) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}

	// BUG 3: every valid request is processed, even one seen before.
	rc.mu.Lock()
	rc.processed[id]++
	rc.mu.Unlock()
	fmt.Fprintln(w, "ok")
}

func (rc *receiver) verify(id, ts string, body []byte, header string) bool {
	m := hmac.New(sha256.New, rc.secret)
	m.Write([]byte(id + "." + ts + "."))
	m.Write(body)
	want := m.Sum(nil)
	for _, field := range strings.Fields(header) {
		sig, ok := strings.CutPrefix(field, "v1,")
		if !ok {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(sig)
		if err == nil && hmac.Equal(got, want) {
			return true
		}
	}
	return false
}

func (rc *receiver) count(w http.ResponseWriter, r *http.Request) {
	rc.mu.Lock()
	n := rc.processed[r.PathValue("id")]
	rc.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"processed": n})
}

func main() {
	addr := flag.String("addr", ":8081", "listen address")
	secret := flag.String("secret", envOr("WEBHOOK_SECRET", "demo-secret"), "signing secret")
	flag.Parse()
	log.Printf("vulnerable receiver on %s (POST /webhook)", *addr)
	// BUG 4 (cont.): http.ListenAndServe has no read timeout, so a client can
	// hold a connection open for as long as it likes.
	log.Fatal(http.ListenAndServe(*addr, newReceiver(*secret).routes()))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
