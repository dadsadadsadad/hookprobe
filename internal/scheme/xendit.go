package scheme

// Xendit does not sign the payload. Each callback carries the account's
// static verification token, which receivers compare with the one in their
// dashboard settings:
//
//	x-callback-token: <verification token>
//
// Pass the token as --secret. With no signature over the body or a timestamp,
// the re-serialized body, stale timestamp and rotation checks do not apply,
// and replay protection rests entirely on deduping the event ID in the body.
type xendit struct{}

func init() { Register(xendit{}) }

func (xendit) Name() string { return "xendit" }

func (xendit) Description() string {
	return "x-callback-token: <verification token> (static token, body not signed)"
}

func (xendit) SignatureHeader() string { return "x-callback-token" }
func (xendit) Timestamped() bool       { return false }
func (xendit) MultiSignature() bool    { return false }
func (xendit) BodySigned() bool        { return false }

func (xendit) Sign(m Message, secrets ...string) (Headers, error) {
	if err := needSecret(secrets); err != nil {
		return nil, err
	}
	return Headers{{Name: "x-callback-token", Value: secrets[0]}}, nil
}

func (x xendit) Variants(m Message, secret string) ([]Variant, error) {
	base, err := x.Sign(m, secret)
	if err != nil {
		return nil, err
	}
	h := x.SignatureHeader()
	return []Variant{
		{"title-case header name", base.With("X-Callback-Token", secret), true},
		{"truncated token", base.With(h, half(secret)), false},
		// Catches prefix comparisons such as strings.HasPrefix(got, want).
		{"token with extra characters", base.With(h, secret+"x"), false},
		{"token behind a Bearer prefix", base.With(h, "Bearer "+secret), false},
		{"empty header value", base.With(h, ""), false},
	}, nil
}
