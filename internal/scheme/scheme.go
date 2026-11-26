// Package scheme holds the webhook signature formats HookProbe can produce.
//
// Each format lives in its own file and registers itself from init. Adding a
// format (PayMongo, Xendit, ...) means adding one file that implements Scheme
// and calls Register.
package scheme

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Header is one HTTP header. The name is sent exactly as spelled, which lets
// checks probe how a receiver handles different spellings of the same header.
type Header struct {
	Name  string
	Value string
}

// Headers is an ordered header list.
type Headers []Header

// Get returns the value of the first header called name, ignoring case.
func (h Headers) Get(name string) string {
	for _, x := range h {
		if strings.EqualFold(x.Name, name) {
			return x.Value
		}
	}
	return ""
}

// Without returns a copy with every header called name (in any case) removed.
func (h Headers) Without(name string) Headers {
	out := make(Headers, 0, len(h))
	for _, x := range h {
		if !strings.EqualFold(x.Name, name) {
			out = append(out, x)
		}
	}
	return out
}

// With returns a copy where the header called name (in any case) is replaced
// by one spelled exactly as given.
func (h Headers) With(name, value string) Headers {
	return append(h.Without(name), Header{Name: name, Value: value})
}

// Message is one webhook delivery before it is signed.
type Message struct {
	ID        string
	Type      string
	Timestamp time.Time
	Attempt   int
	Body      []byte
}

// Unix returns the timestamp as decimal unix seconds.
func (m Message) Unix() string {
	return strconv.FormatInt(m.Timestamp.Unix(), 10)
}

// Variant is a signed request whose signature header was altered. Accept says
// whether a correct receiver must accept it (a spelling HTTP treats as equal)
// or reject it (a malformed value).
type Variant struct {
	Name    string
	Headers Headers
	Accept  bool
}

// Scheme is one signature format.
type Scheme interface {
	// Name is the value users pass to --scheme.
	Name() string
	// Description is a one-line summary of the wire format.
	Description() string
	// SignatureHeader is the header that carries the signature.
	SignatureHeader() string
	// Sign returns every header the format needs (event ID, timestamp,
	// signature). With several secrets it emits one signature per secret, the
	// way a sender does while a secret is being rotated.
	Sign(m Message, secrets ...string) (Headers, error)
	// Timestamped reports whether the signature covers a timestamp.
	Timestamped() bool
	// MultiSignature reports whether one header can carry several signatures.
	MultiSignature() bool
	// Variants returns header spellings and malformed values to try, built
	// from a valid signature of m.
	Variants(m Message, secret string) ([]Variant, error)
}

var registry = map[string]Scheme{}

// Register adds a scheme. It panics on a duplicate name, so a clash shows up
// the first time the binary runs.
func Register(s Scheme) {
	name := strings.ToLower(s.Name())
	if _, dup := registry[name]; dup {
		panic("scheme: duplicate registration of " + name)
	}
	registry[name] = s
}

// Get looks a scheme up by name, ignoring case.
func Get(name string) (Scheme, bool) {
	s, ok := registry[strings.ToLower(name)]
	return s, ok
}

// All returns every registered scheme, sorted by name.
func All() []Scheme {
	out := make([]Scheme, 0, len(registry))
	for _, s := range registry {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Names returns every registered scheme name, sorted.
func Names() []string {
	var names []string
	for _, s := range All() {
		names = append(names, s.Name())
	}
	return names
}

func mac(key []byte, parts ...string) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write([]byte(p))
	}
	return m.Sum(nil)
}

func needSecret(secrets []string) error {
	if len(secrets) == 0 {
		return fmt.Errorf("no signing secret given")
	}
	return nil
}

func half(s string) string { return s[:len(s)/2] }
