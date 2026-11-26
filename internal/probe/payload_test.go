package probe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBuildBodyIsCanonical(t *testing.T) {
	b := buildBody("evt_1", "t", "c", time.Unix(1760000000, 0), 3)
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(v)
	if string(again) != string(b) {
		t.Fatalf("re-encoding changed the bytes:\n%s\n%s", b, again)
	}
}

func TestReserializeKeepsValueChangesBytes(t *testing.T) {
	b := buildBody("evt_1", "t", "c", time.Unix(1760000000, 0), 0)
	alt, err := reserialize(b)
	if err != nil {
		t.Fatal(err)
	}
	var x, y any
	json.Unmarshal(b, &x)
	json.Unmarshal(alt, &y)
	if !reflect.DeepEqual(x, y) {
		t.Fatalf("value changed:\n%s\n%s", b, alt)
	}
	if string(alt) == string(b) {
		t.Fatal("bytes did not change")
	}
}

func TestExampleTemplatesRender(t *testing.T) {
	files, _ := filepath.Glob("../../examples/*.json")
	if len(files) == 0 {
		t.Fatal("no example templates found")
	}
	for _, f := range files {
		tmpl, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out, err := RenderTemplate(tmpl, "evt_9", "payment.paid", "baseline", time.Unix(1760000000, 0), 10)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if !strings.Contains(string(out), `"evt_9"`) || !strings.HasSuffix(string(out), "          ") {
			t.Errorf("%s: id or padding missing", f)
		}
		if _, err := reserialize(out); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestRenderTemplateRejectsBadTemplates(t *testing.T) {
	for name, tmpl := range map[string]string{
		"unquoted string": `{"id": {{id}}}`,
		"no id":           `{"type": "{{type}}"}`,
	} {
		if _, err := RenderTemplate([]byte(tmpl), "evt_1", "t", "c", time.Now(), 0); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestParseCount(t *testing.T) {
	for in, want := range map[string]int{"3": 3, " 0\n": 0, `{"processed": 2}`: 2} {
		got, err := parseCount([]byte(in))
		if err != nil || got != want {
			t.Errorf("parseCount(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := parseCount([]byte(`{"count": 1}`)); err == nil {
		t.Error("want an error for a missing processed field")
	}
}

func TestLookup(t *testing.T) {
	if c, ok := Lookup("8"); !ok || c.Key != "slow-body" {
		t.Fatalf("Lookup(8) = %v, %v", c, ok)
	}
	if c, ok := Lookup("Replay"); !ok || c.ID != 3 {
		t.Fatalf("Lookup(Replay) = %v, %v", c, ok)
	}
	if _, ok := Lookup("nope"); ok {
		t.Fatal("Lookup(nope) found something")
	}
}
