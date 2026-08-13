package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

const endMarker = "END"

type console struct {
	in *bufio.Reader
}

func newConsole() *console { return &console{in: bufio.NewReader(os.Stdin)} }

// line reads one line, stripping only the trailing CR/LF so passwords keep any
// spaces the user meant to type.
func (c *console) line() (string, error) {
	s, err := c.in.ReadString('\n')
	s = strings.TrimRight(s, "\r\n")
	if err != nil && s == "" {
		return "", err
	}
	return s, nil
}

// block reads lines until END (or EOF).
func (c *console) block() string {
	var lines []string
	for {
		s, err := c.line()
		if err != nil {
			break
		}
		if strings.TrimSpace(s) == endMarker {
			break
		}
		lines = append(lines, s)
	}
	return strings.Join(lines, "\n")
}

func (c *console) askBlock(prompt string) string {
	fmt.Printf("\n[+] %s\n", prompt)
	fmt.Printf("    Paste as many lines as you need, then type %s on a new line to finish:\n> ", endMarker)
	return c.block()
}

// password reads a password without echoing it. On a non-console stdin (a
// pipe, a redirected file) it falls back to a plain read and says so.
func (c *console) password(prompt string) (string, bool) {
	fmt.Printf("\n[+] %s\n> ", prompt)

	pw, err := withEchoDisabled(func() (string, error) { return c.line() })
	if err == nil {
		fmt.Println()
		return pw, pw != ""
	}

	// Not a console: read normally rather than failing outright.
	pw, rerr := c.line()
	if rerr != nil {
		return "", false
	}
	return pw, pw != ""
}

// newPassword asks twice and requires the two entries to match.
func (c *console) newPassword() (string, bool) {
	pw, ok := c.password("Enter the password (it will not be shown as you type):")
	if !ok {
		fmt.Println("\n[!] The password cannot be empty. Operation cancelled.")
		return "", false
	}
	again, ok := c.password("Confirm the password:")
	if !ok || again != pw {
		fmt.Println("\n[!] The passwords do not match. Operation cancelled.")
		return "", false
	}
	if warn := passwordWarning(pw); warn != "" {
		fmt.Printf("\n[warn] %s\n", warn)
	}
	return pw, true
}

// passwordWarning gives the user an honest read on their password without
// blocking them — the KDF is strong, but it cannot rescue "1234".
func passwordWarning(pw string) string {
	var classes int
	var hasLower, hasUpper, hasDigit, hasOther bool
	for _, r := range pw {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasOther = true
		}
	}
	for _, b := range []bool{hasLower, hasUpper, hasDigit, hasOther} {
		if b {
			classes++
		}
	}

	switch {
	case len([]rune(pw)) < 8:
		return "That password is very short. Offline guessing gets cheap fast — 12+ characters is a much better place to be."
	case len([]rune(pw)) < 12 && classes < 3:
		return "That password is short and uses few character types. Consider a longer passphrase."
	}
	return ""
}

const rule = "--------------------------------------------------------------------"

func printBlock(title, body string) {
	fmt.Println("\n" + title)
	fmt.Println(rule)
	fmt.Println(body)
	fmt.Println(rule)
}

func printReport(r Report) {
	fmt.Printf("[i] Protection : %s\n", r.Describe())
	if r.SecretSize > 0 {
		fmt.Printf("[i] Secret     : %d bytes\n", r.SecretSize)
	}
	if r.Container > 0 {
		fmt.Printf("[i] Payload    : %d bytes -> %d invisible characters\n", r.Container, r.Carriers)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", args...)
	os.Exit(1)
}

// readTextArg resolves a value that may come from a literal string, a file, or
// stdin ("-").
func readTextArg(literal, path string) (string, error) {
	if path == "" {
		return literal, nil
	}
	if literal != "" {
		return "", fmt.Errorf("give either the literal text or a file, not both")
	}
	if path == "-" {
		b, err := io.ReadAll(os.Stdin)
		return string(b), err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// writeOut sends result to a file, or to stdout when no path is given.
//
// Writing to a file is the reliable way to move a payload around: terminals,
// chat clients and web forms strip zero-width characters far more often than
// files do.
func writeOut(path, result string) error {
	if path == "" {
		fmt.Println(result)
		return nil
	}
	if err := os.WriteFile(path, []byte(result), 0o600); err != nil {
		return err
	}
	fmt.Printf("[i] Written to %s\n", path)
	return nil
}
