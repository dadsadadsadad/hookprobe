package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// Oracle reports how many times the receiver processed an event.
type Oracle interface {
	Count(ctx context.Context, eventID string) (int, error)
	Describe() string
}

// HTTPOracle asks a test-only endpoint on the receiver. Template contains
// "{id}", which is replaced by the event ID. The endpoint answers
// {"processed": <n>} or a bare integer; 404 means 0.
type HTTPOracle struct {
	Template string
	Client   *http.Client
}

func (o HTTPOracle) Describe() string { return o.Template }

func (o HTTPOracle) Count(ctx context.Context, id string) (int, error) {
	u := strings.ReplaceAll(o.Template, "{id}", url.PathEscape(id))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	c := o.Client
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return 0, nil
	case resp.StatusCode/100 != 2:
		return 0, fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
	}
	return parseCount(body)
}

// CommandOracle runs a shell command that prints the processed count. The
// command sees the event ID as "{id}" in its text and as $HOOKPROBE_EVENT_ID.
type CommandOracle struct {
	Command string
}

func (o CommandOracle) Describe() string { return "command: " + o.Command }

func (o CommandOracle) Count(ctx context.Context, id string) (int, error) {
	line := strings.ReplaceAll(o.Command, "{id}", id)
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", line)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", line)
	}
	cmd.Env = append(os.Environ(), "HOOKPROBE_EVENT_ID="+id)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("%s: %v %s", line, err, strings.TrimSpace(stderr.String()))
	}
	return parseCount(out)
}

func parseCount(b []byte) (int, error) {
	s := strings.TrimSpace(string(b))
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	var v struct {
		Processed *int `json:"processed"`
	}
	if err := json.Unmarshal([]byte(s), &v); err != nil || v.Processed == nil {
		return 0, fmt.Errorf(`expected an integer or {"processed": <n>}, got %q`, s)
	}
	return *v.Processed, nil
}
