//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
)

var errNoConsole = errors.New("stdin is not an interactive console")

// withEchoDisabled runs fn with terminal echo turned off. stty is used instead
// of raw termios ioctls to keep this file dependency-free and portable across
// the unix-like targets Go supports.
func withEchoDisabled(fn func() (string, error)) (string, error) {
	if !isTerminal() {
		return "", errNoConsole
	}
	if err := stty("-echo"); err != nil {
		return "", errNoConsole
	}
	defer stty("echo")

	return fn()
}

func stty(arg string) error {
	cmd := exec.Command("stty", arg)
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func isTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
