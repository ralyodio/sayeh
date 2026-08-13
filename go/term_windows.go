//go:build windows

package main

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// Console echo is toggled through kernel32 directly. golang.org/x/term would
// be the usual answer, but this project ships with zero external modules, and
// syscall.NewLazyDLL is part of the standard library on Windows.
var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

const enableEchoInput = 0x0004

var errNoConsole = errors.New("stdin is not an interactive console")

// withEchoDisabled runs fn while the console is not echoing typed characters.
func withEchoDisabled(fn func() (string, error)) (string, error) {
	handle := syscall.Handle(os.Stdin.Fd())

	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode))); r == 0 {
		return "", errNoConsole
	}
	if r, _, _ := procSetConsoleMode.Call(uintptr(handle), uintptr(mode&^enableEchoInput)); r == 0 {
		return "", errNoConsole
	}
	defer procSetConsoleMode.Call(uintptr(handle), uintptr(mode))

	return fn()
}
