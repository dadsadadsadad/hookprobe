package scheme

import (
	"encoding/base64"
	"strings"
)

// StandardWebhooks implements https://www.standardwebhooks.com. It signs
// "<id>.<timestamp>.<body>" and sends
//
//	webhook-id:        <id>
//	webhook-timestamp: <unix>
//	webhook-signature: v1,<base64>[ v1,<base64>...]
//
// A secret of the form "whsec_<base64>" is decoded and the bytes are the key.
// Any other secret string is used as-is.
type standardWebhooks struct{}

func init() { Register(standardWebhooks{}) }

func (standardWebhooks) Name() string { return "standard-webhooks" }

func (standardWebhooks) Description() string {
	return `webhook-signature: v1,<base64 HMAC-SHA256 of "id.timestamp.body">`
}

func (standardWebhooks) SignatureHeader() string { return "webhook-signature" }
func (standardWebhooks) Timestamped() bool       { return true }
func (standardWebhooks) MultiSignature() bool    { return true }
func (standardWebhooks) BodySigned() bool        { return true }

func standardKey(secret string) []byte {
	if rest, ok := strings.CutPrefix(secret, "whsec_"); ok {
		if key, err := base64.StdEncoding.DecodeString(rest); err == nil {
			return key
		}
	}
	return []byte(secret)
}

func (standardWebhooks) sig(m Message, secret string) string {
	return base64.StdEncoding.EncodeToString(
		mac(standardKey(secret), m.ID, ".", m.Unix(), ".", string(m.Body)))
}

func (s standardWebhooks) Sign(m Message, secrets ...string) (Headers, error) {
	if err := needSecret(secrets); err != nil {
		return nil, err
	}
	var sigs []string
	for _, sec := range secrets {
		sigs = append(sigs, "v1,"+s.sig(m, sec))
	}
	return Headers{
		{Name: "webhook-id", Value: m.ID},
		{Name: "webhook-timestamp", Value: m.Unix()},
		{Name: "webhook-signature", Value: strings.Join(sigs, " ")},
	}, nil
}

func (s standardWebhooks) Variants(m Message, secret string) ([]Variant, error) {
	base, err := s.Sign(m, secret)
	if err != nil {
		return nil, err
	}
	return v1Variants(base, s.SignatureHeader(), "Webhook-Signature", "title-case header name", s.sig(m, secret)), nil
}

// v1Variants covers formats that send "v1,<base64>" values: Standard Webhooks
// and the X-Hook format.
func v1Variants(base Headers, header, respelled, respelledName, valid string) []Variant {
	return []Variant{
		{respelledName, base.With(respelled, base.Get(header)), true},
		{"unknown version v2", base.With(header, "v2,"+valid), false},
		{"no v1, prefix", base.With(header, valid), false},
		{"v1, prefix with no signature", base.With(header, "v1,"), false},
		{"truncated signature", base.With(header, "v1,"+half(valid)), false},
		{"signature with extra characters", base.With(header, "v1,"+valid+"AAAA"), false},
		{"empty header value", base.With(header, ""), false},
	}
}
