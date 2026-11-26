// Package report renders probe results for people (Text) and for CI (JSON).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/dadsadadsadad/hookprobe/internal/probe"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	purple = "\033[35m"
)

const indent = "                "

// Text writes a human-readable report as checks complete.
type Text struct {
	W       io.Writer
	Color   bool // ANSI colors
	Live    bool // show a "running" line while a check runs
	Verbose bool // show expected/got for passing checks too
}

func (t *Text) paint(code, s string) string {
	if !t.Color {
		return s
	}
	return code + s + reset
}

// Header prints what is being probed.
func (t *Text) Header(target, schemeName, oracle string) {
	fmt.Fprintf(t.W, "%s %s\n", t.paint(bold, "hookprobe"), probe.Version)
	fmt.Fprintf(t.W, "  target  %s\n  scheme  %s\n  oracle  %s\n\n", target, schemeName, oracle)
}

// Start shows a placeholder line for a check that is running.
func (t *Text) Start(c probe.Check) {
	if t.Live {
		fmt.Fprintf(t.W, "  %s  %2d  %-20s %s", t.paint(dim, "...."), c.ID, c.Key, t.paint(dim, c.Title))
	}
}

// Result prints one finished check.
func (t *Text) Result(r probe.Result) {
	if t.Live {
		fmt.Fprint(t.W, "\r\033[2K")
	}
	fmt.Fprintf(t.W, "  %s  %2d  %-20s %s\n", t.badge(r.Status), r.ID, r.Key, r.Title)
	switch {
	case r.Status == probe.Skip:
		fmt.Fprintf(t.W, "%s%s\n", indent, t.paint(dim, r.Got))
	case r.Status != probe.Pass || t.Verbose:
		if r.Expected != "" {
			fmt.Fprintf(t.W, "%s%s  %s\n", indent, t.paint(dim, "expected"), r.Expected)
		}
		fmt.Fprintf(t.W, "%s%s       %s\n", indent, t.paint(dim, "got"), r.Got)
		for _, d := range r.Details {
			fmt.Fprintf(t.W, "%s%s\n", indent, t.detail(d))
		}
	}
}

// Summary prints the totals and the verdict.
func (t *Text) Summary(rep probe.Report) {
	s := rep.Summary()
	fmt.Fprintln(t.W)
	if rep.Aborted != "" {
		fmt.Fprintf(t.W, "  %s %s\n", t.paint(red+bold, "stopped:"), rep.Aborted)
	}
	verdict := t.paint(green+bold, "PASS")
	if !rep.Passed() {
		verdict = t.paint(red+bold, "FAIL")
	}
	fmt.Fprintf(t.W, "  %s  %d passed, %d failed, %d skipped, %d errors in %.1fs\n",
		verdict, s.Pass, s.Fail, s.Skip, s.Error, float64(rep.DurationMS)/1000)
}

func (t *Text) badge(s probe.Status) string {
	switch s {
	case probe.Pass:
		return t.paint(green+bold, "PASS")
	case probe.Fail:
		return t.paint(red+bold, "FAIL")
	case probe.Skip:
		return t.paint(yellow, "SKIP")
	default:
		return t.paint(purple+bold, "ERR ")
	}
}

func (t *Text) detail(d string) string {
	switch {
	case strings.HasPrefix(d, "FAIL "):
		return t.paint(red, "FAIL") + d[4:]
	case strings.HasPrefix(d, "pass "):
		return t.paint(green, "pass") + d[4:]
	case strings.HasPrefix(d, "error "):
		return t.paint(purple, "error") + d[5:]
	default:
		return t.paint(dim, d)
	}
}

// Document is the --json output.
type Document struct {
	Tool    string        `json:"tool"`
	Version string        `json:"version"`
	Passed  bool          `json:"passed"`
	Summary probe.Summary `json:"summary"`
	probe.Report
}

// JSON writes rep as an indented JSON document.
func JSON(w io.Writer, rep probe.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Document{
		Tool:    "hookprobe",
		Version: probe.Version,
		Passed:  rep.Passed(),
		Summary: rep.Summary(),
		Report:  rep,
	})
}
