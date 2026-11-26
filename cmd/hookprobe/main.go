// Command hookprobe tests whether a webhook receiver is secure. It sends a
// series of hostile requests and reports which checks pass or fail.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/dadsadadsadad/hookprobe/internal/probe"
	"github.com/dadsadadsadad/hookprobe/internal/report"
	"github.com/dadsadadsadad/hookprobe/internal/scheme"
)

// Exit codes.
const (
	exitPass  = 0 // every selected check passed or was skipped
	exitFail  = 1 // at least one check failed or could not run
	exitSetup = 2 // bad flags, or the baseline check did not pass
)

const usage = `hookprobe tests whether a webhook receiver rejects hostile requests.

Usage:
  hookprobe [flags] <receiver-url>
  hookprobe schemes     list signature formats
  hookprobe checks      list checks
  hookprobe version

Example:
  HOOKPROBE_SECRET=whsec_... hookprobe --scheme stripe \
      --processed-url http://localhost:8080/__hookprobe/events/{id} \
      http://localhost:8080/webhooks/stripe

Flags:
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "schemes":
			for _, s := range scheme.All() {
				fmt.Fprintf(stdout, "%-18s %s\n", s.Name(), s.Description())
			}
			return exitPass
		case "checks":
			for _, c := range probe.Checks() {
				fmt.Fprintf(stdout, "%2d  %-20s %s\n", c.ID, c.Key, c.Title)
			}
			return exitPass
		case "version":
			fmt.Fprintln(stdout, "hookprobe", probe.Version)
			return exitPass
		case "help":
			args = []string{"-h"}
		}
	}

	fs := flag.NewFlagSet("hookprobe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	var (
		target       = fs.String("url", "", "receiver URL (or pass it as the argument)")
		schemeName   = fs.String("scheme", "", "signature format: "+strings.Join(scheme.Names(), ", "))
		secret       = fs.String("secret", "", "signing secret the receiver holds (default $HOOKPROBE_SECRET)")
		processedURL = fs.String("processed-url", "", "oracle endpoint with {id}, answering {\"processed\": n} (default <origin>/__hookprobe/events/{id})")
		processedCmd = fs.String("processed-cmd", "", "oracle command with {id} that prints the processed count")
		statusOnly   = fs.Bool("status-only", false, "no oracle: judge by status codes only and skip replay and duplicate checks")
		eventType    = fs.String("event-type", "hookprobe.test", "event type put in the payload and type headers")
		tolerance    = fs.Duration("tolerance", 5*time.Minute, "receiver's timestamp tolerance window")
		replayDelay  = fs.Duration("replay-delay", 2*time.Second, "wait before replaying a captured request")
		settle       = fs.Duration("settle", 300*time.Millisecond, "wait before asking the oracle, for receivers that process asynchronously")
		oversize     = fs.String("oversize", "10MiB", "body size for the oversized-body check")
		slowFor      = fs.Duration("slow-for", 20*time.Second, "how long the slow body keeps dripping before the check fails")
		timeout      = fs.Duration("timeout", 10*time.Second, "per-request timeout")
		only         = fs.String("only", "", "comma-separated checks to run, by number or key")
		skipList     = fs.String("skip", "", "comma-separated checks to skip, by number or key")
		asJSON       = fs.Bool("json", false, "print a JSON report instead of text")
		verbose      = fs.Bool("v", false, "show details for passing checks too")
		noColor      = fs.Bool("no-color", false, "disable colors (also honors $NO_COLOR)")
		insecure     = fs.Bool("insecure", false, "skip TLS certificate verification (self-signed test servers only)")
	)
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitPass
		}
		return exitSetup
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "hookprobe: "+format+"\n", a...)
		return exitSetup
	}

	if *target == "" && len(positional) > 0 {
		*target = positional[0]
		positional = positional[1:]
	}
	if len(positional) > 0 {
		return fail("unexpected arguments: %s", strings.Join(positional, " "))
	}
	if *target == "" {
		fs.Usage()
		return exitSetup
	}
	u, err := url.Parse(*target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fail("receiver URL must be an absolute http(s) URL, got %q", *target)
	}
	if *schemeName == "" {
		return fail("--scheme is required (one of %s)", strings.Join(scheme.Names(), ", "))
	}
	sch, ok := scheme.Get(*schemeName)
	if !ok {
		return fail("unknown scheme %q (one of %s)", *schemeName, strings.Join(scheme.Names(), ", "))
	}
	if *secret == "" {
		*secret = os.Getenv("HOOKPROBE_SECRET")
	}
	if *secret == "" {
		return fail("no signing secret: pass --secret or set HOOKPROBE_SECRET")
	}
	oversizeBytes, err := parseSize(*oversize)
	if err != nil {
		return fail("--oversize: %v", err)
	}

	var oracle probe.Oracle
	switch {
	case *statusOnly && (*processedURL != "" || *processedCmd != ""):
		return fail("--status-only cannot be combined with --processed-url or --processed-cmd")
	case *processedURL != "" && *processedCmd != "":
		return fail("use --processed-url or --processed-cmd, not both")
	case *statusOnly:
	case *processedCmd != "":
		oracle = probe.CommandOracle{Command: *processedCmd}
	default:
		tmpl := *processedURL
		if tmpl == "" {
			tmpl = u.Scheme + "://" + u.Host + "/__hookprobe/events/{id}"
		}
		if !strings.Contains(tmpl, "{id}") {
			return fail("--processed-url must contain {id}")
		}
		oracle = probe.HTTPOracle{Template: tmpl, Client: &http.Client{Timeout: *timeout}}
	}

	selected, err := selection(*only, *skipList)
	if err != nil {
		return fail("%v", err)
	}

	cfg := probe.Config{
		URL:           *target,
		Scheme:        sch,
		Secret:        *secret,
		EventType:     *eventType,
		Oracle:        oracle,
		Tolerance:     *tolerance,
		ReplayDelay:   *replayDelay,
		Settle:        *settle,
		OversizeBytes: oversizeBytes,
		SlowFor:       *slowFor,
		Timeout:       *timeout,
		Insecure:      *insecure,
		Selected:      selected,
	}

	var text *report.Text
	if !*asJSON {
		isTTY := isTerminal(stdout)
		color := isTTY && !*noColor && os.Getenv("NO_COLOR") == ""
		text = &report.Text{W: stdout, Color: color, Live: color, Verbose: *verbose}
		oracleName := "none (status only)"
		if oracle != nil {
			oracleName = oracle.Describe()
		}
		text.Header(*target, sch.Name(), oracleName)
		cfg.OnStart = text.Start
		cfg.OnResult = text.Result
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rep := probe.Run(ctx, cfg)

	if *asJSON {
		if err := report.JSON(stdout, rep); err != nil {
			return fail("writing report: %v", err)
		}
	} else {
		text.Summary(rep)
	}

	switch {
	case rep.Aborted != "":
		return exitSetup
	case rep.Passed():
		return exitPass
	default:
		return exitFail
	}
}

// parseInterspersed lets flags come before or after the receiver URL.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func selection(only, skip string) (func(probe.Check) bool, error) {
	parse := func(list string) (map[int]bool, error) {
		set := map[int]bool{}
		for _, tok := range strings.Split(list, ",") {
			if strings.TrimSpace(tok) == "" {
				continue
			}
			c, ok := probe.Lookup(tok)
			if !ok {
				return nil, fmt.Errorf("unknown check %q (see `hookprobe checks`)", strings.TrimSpace(tok))
			}
			set[c.ID] = true
		}
		return set, nil
	}
	in, err := parse(only)
	if err != nil {
		return nil, err
	}
	out, err := parse(skip)
	if err != nil {
		return nil, err
	}
	if len(in) == 0 && len(out) == 0 {
		return nil, nil
	}
	return func(c probe.Check) bool {
		return (len(in) == 0 || in[c.ID]) && !out[c.ID]
	}, nil
}

// parseSize reads sizes such as 512, 64KB, 10MiB.
func parseSize(s string) (int, error) {
	s = strings.TrimSpace(s)
	units := []struct {
		suffix string
		mult   int
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000}, {"B", 1}}
	mult := 1
	for _, u := range units {
		if strings.HasSuffix(strings.ToUpper(s), strings.ToUpper(u.suffix)) {
			s, mult = strings.TrimSpace(s[:len(s)-len(u.suffix)]), u.mult
			break
		}
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return int(n * float64(mult)), nil
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && enableTerminal(f)
}
