package probe

import (
	"encoding/json"
	"reflect"
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
