package scheme

import (
	"encoding/hex"
	"strings"
)

// Stripe signs "<timestamp>.<body>" and sends
//
//	Stripe-Signature: t=<unix>,v1=<hex>[,v1=<hex>...]
//
// The whole secret string, "whsec_" prefix included, is the HMAC key.
type stripe struct{}

func init() { Register(stripe{}) }

func (stripe) Name() string { return "stripe" }

func (stripe) Description() string {
	return `Stripe-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "t.body">`
}

func (stripe) SignatureHeader() string { return "Stripe-Signature" }
func (stripe) Timestamped() bool       { return true }
func (stripe) MultiSignature() bool    { return true }
func (stripe) BodySigned() bool        { return true }

func (stripe) sig(m Message, secret string) string {
	return hex.EncodeToString(mac([]byte(secret), m.Unix(), ".", string(m.Body)))
}

func (s stripe) Sign(m Message, secrets ...string) (Headers, error) {
	if err := needSecret(secrets); err != nil {
		return nil, err
	}
	parts := []string{"t=" + m.Unix()}
	for _, sec := range secrets {
		parts = append(parts, "v1="+s.sig(m, sec))
	}
	return Headers{{Name: "Stripe-Signature", Value: strings.Join(parts, ",")}}, nil
}

func (s stripe) Variants(m Message, secret string) ([]Variant, error) {
	base, err := s.Sign(m, secret)
	if err != nil {
		return nil, err
	}
	valid := s.sig(m, secret)
	t := "t=" + m.Unix()
	h := "Stripe-Signature"
	return []Variant{
		{"lowercase header name", base.With("stripe-signature", base.Get(h)), true},
		{"signature under v0 instead of v1", base.With(h, t+",v0="+valid), false},
		{"no t= element", base.With(h, "v1="+valid), false},
		{"truncated signature", base.With(h, t+",v1="+half(valid)), false},
		{"signature with extra characters", base.With(h, t+",v1="+valid+"00"), false},
		{"empty header value", base.With(h, ""), false},
	}, nil
}
