//go:build windows

package main

import (
	"os"
	"syscall"
)

// enableTerminal reports whether f is a console and turns on ANSI escape
// processing for it.
func enableTerminal(f *os.File) bool {
	h := syscall.Handle(f.Fd())
	var mode uint32
	if err := syscall.GetConsoleMode(h, &mode); err != nil {
		return false
	}
	const virtualTerminalProcessing = 0x0004
	if mode&virtualTerminalProcessing != 0 {
		return true
	}
	setConsoleMode := syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleMode")
	ok, _, _ := setConsoleMode.Call(uintptr(h), uintptr(mode|virtualTerminalProcessing))
	return ok != 0
}
