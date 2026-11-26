package probe

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

// buildBody returns compact JSON with sorted keys, the same bytes
// encoding/json and most other encoders produce for this shape. Using the
// canonical form keeps a receiver that wrongly re-encodes before verifying
// from failing the baseline, so the re-serialization check can catch it.
func buildBody(id, typ, check string, ts time.Time, pad int) []byte {
	data := map[string]any{"check": check, "source": "hookprobe"}
	if pad > 0 {
		data["pad"] = strings.Repeat("x", pad)
	}
	b, _ := json.Marshal(map[string]any{
		"created": ts.Unix(),
		"data":    data,
		"id":      id,
		"type":    typ,
	})
	return b
}

// Template placeholders for --body-file. Each is replaced verbatim, so put
// string placeholders inside quotes: "id": "{{id}}".
var placeholders = []string{"{{id}}", "{{type}}", "{{created}}", "{{created_rfc3339}}", "{{check}}"}

// RenderTemplate fills a --body-file template and pads it with trailing
// whitespace (valid JSON) to at least pad extra bytes.
func RenderTemplate(tmpl []byte, id, typ, check string, ts time.Time, pad int) ([]byte, error) {
	r := strings.NewReplacer(
		"{{id}}", id,
		"{{type}}", typ,
		"{{created}}", strconv.FormatInt(ts.Unix(), 10),
		"{{created_rfc3339}}", ts.UTC().Format(time.RFC3339),
		"{{check}}", check,
	)
	out := []byte(r.Replace(string(tmpl)))
	if !json.Valid(out) {
		return nil, errors.New("body template is not valid JSON once its placeholders are filled")
	}
	if !bytes.Contains(tmpl, []byte("{{id}}")) {
		return nil, errors.New(`body template has no {{id}} placeholder, so every check would reuse one event ID`)
	}
	if pad > 0 {
		out = append(out, bytes.Repeat([]byte{' '}, pad)...)
	}
	return out, nil
}

// reserialize returns the same JSON value with keys in reverse order and
// two-space indentation.
func reserialize(body []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	writeReversed(&buf, v, "")
	if bytes.Equal(buf.Bytes(), body) {
		return nil, errors.New("re-serialized body is identical to the original")
	}
	return buf.Bytes(), nil
}

func writeReversed(buf *bytes.Buffer, v any, indent string) {
	inner := indent + "  "
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
		buf.WriteString("{\n")
		for i, k := range keys {
			kb, _ := json.Marshal(k)
			buf.WriteString(inner)
			buf.Write(kb)
			buf.WriteString(": ")
			writeReversed(buf, t[k], inner)
			if i < len(keys)-1 {
				buf.WriteByte(',')
			}
			buf.WriteByte('\n')
		}
		buf.WriteString(indent + "}")
	case []any:
		buf.WriteString("[\n")
		for i, e := range t {
			buf.WriteString(inner)
			writeReversed(buf, e, inner)
			if i < len(t)-1 {
				buf.WriteByte(',')
			}
			buf.WriteByte('\n')
		}
		buf.WriteString(indent + "]")
	default:
		b, _ := json.Marshal(t)
		buf.Write(b)
	}
}
