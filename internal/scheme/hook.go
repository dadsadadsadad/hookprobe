package scheme

import (
	"encoding/base64"
	"strconv"
	"strings"
)

// Hook is the format of the Reliable Webhook Delivery Service
// (github.com/dadsadadsadad/webhook-delivery-service, spec section 10). It
// signs "<event id>.<timestamp>.<body>" and sends
//
//	X-Hook-Event-Id:   <id>       stable across retries
//	X-Hook-Event-Type: <type>
//	X-Hook-Attempt:    <n>        1-based
//	X-Hook-Timestamp:  <unix>     fresh on every attempt
//	X-Hook-Signature:  v1,<base64>[ v1,<base64>]
//
// While a secret is being rotated the sender signs with both the current and
// the previous secret, space separated. The secret string's bytes are the key.
type hook struct{}

func init() { Register(hook{}) }

func (hook) Name() string { return "hook" }

func (hook) Description() string {
	return `X-Hook-Signature: v1,<base64 HMAC-SHA256 of "event_id.timestamp.body">`
}

func (hook) SignatureHeader() string { return "X-Hook-Signature" }
func (hook) Timestamped() bool       { return true }
func (hook) MultiSignature() bool    { return true }

func (hook) sig(m Message, secret string) string {
	return base64.StdEncoding.EncodeToString(
		mac([]byte(secret), m.ID, ".", m.Unix(), ".", string(m.Body)))
}

func (h hook) Sign(m Message, secrets ...string) (Headers, error) {
	if err := needSecret(secrets); err != nil {
		return nil, err
	}
	attempt := m.Attempt
	if attempt < 1 {
		attempt = 1
	}
	var sigs []string
	for _, sec := range secrets {
		sigs = append(sigs, "v1,"+h.sig(m, sec))
	}
	return Headers{
		{Name: "X-Hook-Event-Id", Value: m.ID},
		{Name: "X-Hook-Event-Type", Value: m.Type},
		{Name: "X-Hook-Attempt", Value: strconv.Itoa(attempt)},
		{Name: "X-Hook-Timestamp", Value: m.Unix()},
		{Name: "X-Hook-Signature", Value: strings.Join(sigs, " ")},
	}, nil
}

func (h hook) Variants(m Message, secret string) ([]Variant, error) {
	base, err := h.Sign(m, secret)
	if err != nil {
		return nil, err
	}
	return v1Variants(base, h.SignatureHeader(), "x-hook-signature", "lowercase header name", h.sig(m, secret)), nil
}
