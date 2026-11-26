package scheme

import (
	"strings"
	"testing"
	"time"
)

// Reference vector from the Standard Webhooks spec and its libraries.
func TestStandardWebhooksVector(t *testing.T) {
	s, _ := Get("standard-webhooks")
	m := Message{
		ID:        "msg_p5jXN8AQM9LWM0D4loKWxJek",
		Timestamp: time.Unix(1614265330, 0),
		Body:      []byte(`{"test": 2432232314}`),
	}
	h, err := s.Sign(m, "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
	if err != nil {
		t.Fatal(err)
	}
	want := "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
	if got := h.Get("webhook-signature"); got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}
}

// Reference vector from GitHub's "Validating webhook deliveries" docs.
func TestGitHubVector(t *testing.T) {
	s, _ := Get("github")
	h, err := s.Sign(Message{ID: "d1", Type: "push", Body: []byte("Hello, World!")}, "It's a Secret to Everybody")
	if err != nil {
		t.Fatal(err)
	}
	want := "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
	if got := h.Get("X-Hub-Signature-256"); got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}
}

func TestStripeFormat(t *testing.T) {
	s, _ := Get("stripe")
	m := Message{Timestamp: time.Unix(1700000000, 0), Body: []byte(`{}`)}
	h, err := s.Sign(m, "whsec_a", "whsec_b")
	if err != nil {
		t.Fatal(err)
	}
	v := h.Get("Stripe-Signature")
	parts := strings.Split(v, ",")
	if len(parts) != 3 || parts[0] != "t=1700000000" || !strings.HasPrefix(parts[1], "v1=") || !strings.HasPrefix(parts[2], "v1=") {
		t.Fatalf("unexpected header %q", v)
	}
	if parts[1] == parts[2] {
		t.Fatal("two secrets produced the same signature")
	}
}

func TestHookRotationSendsBothSignatures(t *testing.T) {
	s, _ := Get("hook")
	m := Message{ID: "evt_1", Type: "order.shipped", Timestamp: time.Unix(1760000000, 0), Body: []byte(`{"a":1}`)}
	h, err := s.Sign(m, "new", "old")
	if err != nil {
		t.Fatal(err)
	}
	sigs := strings.Fields(h.Get("X-Hook-Signature"))
	if len(sigs) != 2 {
		t.Fatalf("want 2 signatures, got %q", h.Get("X-Hook-Signature"))
	}
	if h.Get("X-Hook-Event-Id") != "evt_1" || h.Get("X-Hook-Timestamp") != "1760000000" || h.Get("X-Hook-Attempt") != "1" {
		t.Fatalf("missing delivery headers: %v", h)
	}
}

func TestEverySchemeHasUsableVariants(t *testing.T) {
	m := Message{ID: "evt_1", Type: "t", Timestamp: time.Now(), Body: []byte(`{"a":1}`)}
	for _, s := range All() {
		vs, err := s.Variants(m, "whsec_c2VjcmV0")
		if err != nil {
			t.Fatalf("%s: %v", s.Name(), err)
		}
		accepts, rejects := 0, 0
		for _, v := range vs {
			if v.Accept {
				accepts++
			} else {
				rejects++
			}
			if v.Headers.Get(s.SignatureHeader()) == "" && v.Accept {
				t.Errorf("%s/%s: accepted variant lost the signature", s.Name(), v.Name)
			}
		}
		if accepts == 0 || rejects == 0 {
			t.Errorf("%s: want both accepted and rejected variants, got %d/%d", s.Name(), accepts, rejects)
		}
	}
}

func TestHeadersWithReplacesAnyCase(t *testing.T) {
	h := Headers{{"X-Hook-Signature", "a"}, {"Other", "b"}}.With("x-hook-signature", "c")
	if len(h) != 2 || h.Get("X-HOOK-SIGNATURE") != "c" || h[1].Name != "x-hook-signature" {
		t.Fatalf("unexpected %v", h)
	}
}
