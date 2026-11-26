//go:build !windows

package main

import "os"

// enableTerminal reports whether f is a terminal.
func enableTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
