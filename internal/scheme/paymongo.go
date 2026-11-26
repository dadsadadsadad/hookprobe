package scheme

import "encoding/hex"

// PayMongo signs "<timestamp>.<body>" with the webhook's secret key and sends
//
//	Paymongo-Signature: t=<unix>,te=<hex>,li=        (test mode)
//	Paymongo-Signature: t=<unix>,te=,li=<hex>        (live mode)
//
// Receivers compare against te for test-mode events and li for live ones.
// "paymongo" fills te and "paymongo-live" fills li. Each request carries one
// signature, and the event ID lives in the body (data.id), so use --body-file
// with examples/paymongo-event.json for receivers that parse the event.
type paymongo struct{ live bool }

func init() {
	Register(paymongo{})
	Register(paymongo{live: true})
}

func (p paymongo) Name() string {
	if p.live {
		return "paymongo-live"
	}
	return "paymongo"
}

func (p paymongo) Description() string {
	if p.live {
		return `Paymongo-Signature: t=<unix>,te=,li=<hex HMAC-SHA256 of "t.body">`
	}
	return `Paymongo-Signature: t=<unix>,te=<hex HMAC-SHA256 of "t.body">,li=`
}

func (paymongo) SignatureHeader() string { return "Paymongo-Signature" }
func (paymongo) Timestamped() bool       { return true }
func (paymongo) MultiSignature() bool    { return false }
func (paymongo) BodySigned() bool        { return true }

func (paymongo) sig(m Message, secret string) string {
	return hex.EncodeToString(mac([]byte(secret), m.Unix(), ".", string(m.Body)))
}

func (p paymongo) value(t, sig string) string {
	if p.live {
		return "t=" + t + ",te=,li=" + sig
	}
	return "t=" + t + ",te=" + sig + ",li="
}

func (p paymongo) Sign(m Message, secrets ...string) (Headers, error) {
	if err := needSecret(secrets); err != nil {
		return nil, err
	}
	return Headers{{Name: "Paymongo-Signature", Value: p.value(m.Unix(), p.sig(m, secrets[0]))}}, nil
}

func (p paymongo) Variants(m Message, secret string) ([]Variant, error) {
	base, err := p.Sign(m, secret)
	if err != nil {
		return nil, err
	}
	valid := p.sig(m, secret)
	h := p.SignatureHeader()
	field := "te="
	if p.live {
		field = "li="
	}
	return []Variant{
		{"lowercase header name", base.With("paymongo-signature", base.Get(h)), true},
		{"no t= element", base.With(h, field+valid), false},
		{"truncated signature", base.With(h, p.value(m.Unix(), half(valid))), false},
		{"signature with extra characters", base.With(h, p.value(m.Unix(), valid+"00")), false},
		{"empty header value", base.With(h, ""), false},
	}, nil
}
