// Command fixed is the demo receiver with every HookProbe check addressed. It
// is the "after" half of the README report.
//
// It accepts the X-Hook-* format (hookprobe --scheme hook) on POST /webhook
// and verifies a delivery the way the sender's spec asks receivers to:
//
//  1. cap the body and read the raw bytes before parsing anything
//  2. check the timestamp is inside the tolerance window
//  3. verify every v1 signature in the header against every secret held,
//     over "event_id.timestamp.raw_body", in constant time
//  4. dedupe on the event ID, answering duplicates with 200
//
// The server itself has read and write timeouts.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxBody   = 1 << 20 // 1 MiB is far above any real event
	tolerance = 5 * time.Minute
)

type receiver struct {
	secrets [][]byte // current secret first; add the previous one during rotation

	mu        sync.Mutex
	processed map[string]int
}

func newReceiver(secrets ...string) *receiver {
	rc := &receiver{processed: map[string]int{}}
	for _, s := range secrets {
		if s != "" {
			rc.secrets = append(rc.secrets, []byte(s))
		}
	}
	return rc
}

func (rc *receiver) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /webhook", rc.webhook)
	// Test-only: lets HookProbe see what was processed. Never ship this.
	mux.HandleFunc("GET /__hookprobe/events/{id}", rc.count)
	return mux
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

func (rc *receiver) webhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "could not read body", http.StatusRequestTimeout)
		return
	}

	id := r.Header.Get("X-Hook-Event-Id")
	ts := r.Header.Get("X-Hook-Timestamp")
	if id == "" || ts == "" {
		http.Error(w, "missing delivery headers", http.StatusBadRequest)
		return
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		http.Error(w, "bad timestamp", http.StatusBadRequest)
		return
	}
	if age := time.Since(time.Unix(sec, 0)); age > tolerance || age < -tolerance {
		http.Error(w, "timestamp outside tolerance", http.StatusUnauthorized)
		return
	}
	if !rc.verify(id, ts, body, r.Header.Get("X-Hook-Signature")) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	if !json.Valid(body) {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if !rc.claim(id) {
		// Already handled. 2xx tells the sender to stop retrying.
		fmt.Fprintln(w, "duplicate, ignored")
		return
	}
	fmt.Fprintln(w, "ok")
}

// claim records id as processed and reports whether this call was the first.
// A real app does this with a unique constraint in the same transaction as
// the work, so a crash cannot leave the event half done.
func (rc *receiver) claim(id string) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.processed[id] > 0 {
		return false
	}
	rc.processed[id] = 1
	return true
}

func (rc *receiver) verify(id, ts string, body []byte, header string) bool {
	for _, field := range strings.Fields(header) {
		sig, ok := strings.CutPrefix(field, "v1,")
		if !ok {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			continue
		}
		for _, key := range rc.secrets {
			m := hmac.New(sha256.New, key)
			m.Write([]byte(id + "." + ts + "."))
			m.Write(body)
			if hmac.Equal(got, m.Sum(nil)) {
				return true
			}
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
	addr := flag.String("addr", ":8082", "listen address")
	secret := flag.String("secret", envOr("WEBHOOK_SECRET", "demo-secret"), "signing secret")
	previous := flag.String("previous-secret", os.Getenv("WEBHOOK_PREVIOUS_SECRET"), "previous secret, accepted during rotation")
	flag.Parse()
	log.Printf("fixed receiver on %s (POST /webhook)", *addr)
	log.Fatal(newServer(*addr, newReceiver(*secret, *previous).routes()).ListenAndServe())
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
