package scheme

import "encoding/hex"

// GitHub signs the raw body only and sends
//
//	X-Hub-Signature-256: sha256=<hex>
//	X-GitHub-Delivery:   <delivery id>
//	X-GitHub-Event:      <event name>
//
// There is no timestamp and only one signature per request, so the stale
// timestamp and rotation checks do not apply.
type github struct{}

func init() { Register(github{}) }

func (github) Name() string { return "github" }

func (github) Description() string {
	return "X-Hub-Signature-256: sha256=<hex HMAC-SHA256 of body>, X-GitHub-Delivery: <id>"
}

func (github) SignatureHeader() string { return "X-Hub-Signature-256" }
func (github) Timestamped() bool       { return false }
func (github) MultiSignature() bool    { return false }

func (github) sig(m Message, secret string) string {
	return hex.EncodeToString(mac([]byte(secret), string(m.Body)))
}

func (g github) Sign(m Message, secrets ...string) (Headers, error) {
	if err := needSecret(secrets); err != nil {
		return nil, err
	}
	return Headers{
		{Name: "X-GitHub-Delivery", Value: m.ID},
		{Name: "X-GitHub-Event", Value: m.Type},
		{Name: "X-Hub-Signature-256", Value: "sha256=" + g.sig(m, secrets[0])},
	}, nil
}

func (g github) Variants(m Message, secret string) ([]Variant, error) {
	base, err := g.Sign(m, secret)
	if err != nil {
		return nil, err
	}
	valid := g.sig(m, secret)
	h := g.SignatureHeader()
	return []Variant{
		{"lowercase header name", base.With("x-hub-signature-256", base.Get(h)), true},
		{"sha1= prefix on a SHA-256 value", base.With(h, "sha1="+valid), false},
		{"no sha256= prefix", base.With(h, valid), false},
		{"truncated signature", base.With(h, "sha256="+half(valid)), false},
		{"empty header value", base.With(h, ""), false},
	}, nil
}
