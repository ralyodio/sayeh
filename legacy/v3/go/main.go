package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

const appVersion = "3.0"

const banner = `====================================================================
  Sayeh v` + appVersion + `  -  zero-width steganography
  AES-256-GCM  |  PBKDF2-HMAC-SHA256  |  DEFLATE  |  no dependencies
====================================================================`

const usage = `Sayeh v` + appVersion + `

Usage:
  sayeh                 run the interactive menu
  sayeh hide    [flags] hide a secret inside a cover text
  sayeh reveal  [flags] extract a hidden secret
  sayeh scan    [flags] report what a text is carrying, without decrypting
  sayeh strip   [flags] remove every invisible character from a text
  sayeh selftest        verify the crypto and the wire format
  sayeh version

hide flags:
  -cover s        cover text (or -coverfile PATH, or "-" for stdin)
  -secret s       secret text (or -secretfile PATH)
  -nopass         do not encrypt (default is to ask for a password)
  -codec b4|b2    carrier density: b4 = 2 bits/char (default), b2 = 1 bit/char
  -iter N         PBKDF2 iterations (default %d)
  -nocompress     skip DEFLATE
  -o PATH         write the result to a file instead of stdout

reveal / scan / strip flags:
  -in s           the text (or -infile PATH, or "-" for stdin)
  -o PATH         write the result to a file instead of stdout

password sources, in order of preference:
  -passfile PATH  first line of a file
  SAYEH_PASS environment variable
  interactive prompt (no echo)
  -pass s         literal, discouraged: it leaks into shell history and ps

Zero-width characters are fragile in transit. Prefer -o / -infile over
copy-paste when a payload has to survive a trip through another program.`

func main() {
	if len(os.Args) < 2 {
		interactive()
		return
	}

	switch strings.ToLower(os.Args[1]) {
	case "hide":
		cmdHide(os.Args[2:])
	case "reveal", "extract":
		cmdReveal(os.Args[2:])
	case "scan":
		cmdScan(os.Args[2:])
	case "strip", "clean":
		cmdStrip(os.Args[2:])
	case "selftest", "test":
		cmdSelfTest()
	case "version", "-v", "--version":
		fmt.Printf("Sayeh %s\n", appVersion)
	case "help", "-h", "--help":
		fmt.Printf(usage+"\n", defaultIterations)
	default:
		fmt.Printf(usage+"\n", defaultIterations)
		os.Exit(2)
	}
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

type passFlags struct {
	literal string
	file    string
	none    bool
}

func (p *passFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&p.literal, "pass", "", "password (discouraged: leaks into shell history)")
	fs.StringVar(&p.file, "passfile", "", "read the password from the first line of a file")
	fs.BoolVar(&p.none, "nopass", false, "do not encrypt")
}

// resolve picks a password from the configured sources. confirm is only used
// when the password has to be typed for a *new* payload.
func (p *passFlags) resolve(confirm bool) (string, error) {
	if p.none {
		return "", nil
	}
	if p.file != "" {
		b, err := os.ReadFile(p.file)
		if err != nil {
			return "", err
		}
		s := string(b)
		if i := strings.IndexAny(s, "\r\n"); i >= 0 {
			s = s[:i]
		}
		if s == "" {
			return "", errors.New("the password file is empty")
		}
		return s, nil
	}
	if p.literal != "" {
		fmt.Fprintln(os.Stderr, "[warn] -pass puts the password in your shell history and in the process list; -passfile or the prompt is safer.")
		return p.literal, nil
	}
	if s := os.Getenv("SAYEH_PASS"); s != "" {
		return s, nil
	}

	c := newConsole()
	var pw string
	var ok bool
	if confirm {
		pw, ok = c.newPassword()
	} else {
		pw, ok = c.password("Enter the password (it will not be shown as you type):")
	}
	if !ok {
		return "", errAborted
	}
	return pw, nil
}

func cmdHide(args []string) {
	fs := flag.NewFlagSet("hide", flag.ExitOnError)
	cover := fs.String("cover", "", "cover text")
	coverFile := fs.String("coverfile", "", "read the cover text from a file")
	secret := fs.String("secret", "", "secret text")
	secretFile := fs.String("secretfile", "", "read the secret from a file")
	out := fs.String("o", "", "write the result to a file")
	codecName := fs.String("codec", "b4", "carrier density: b4 or b2")
	iter := fs.Int("iter", defaultIterations, "PBKDF2 iterations")
	noCompress := fs.Bool("nocompress", false, "skip DEFLATE")
	var pass passFlags
	pass.register(fs)
	_ = fs.Parse(args)

	coverText, err := readTextArg(*cover, *coverFile)
	if err != nil {
		fail("cover: %v", err)
	}
	secretText, err := readTextArg(*secret, *secretFile)
	if err != nil {
		fail("secret: %v", err)
	}
	if secretText == "" {
		fail("no secret given (use -secret or -secretfile)")
	}
	codec, err := ParseCodec(*codecName)
	if err != nil {
		fail("%v", err)
	}

	password, err := pass.resolve(true)
	if err != nil {
		if errors.Is(err, errAborted) {
			os.Exit(1)
		}
		fail("%v", err)
	}

	result, rep, err := Hide(coverText, secretText, HideOptions{
		Password:   password,
		Codec:      codec,
		Iterations: *iter,
		NoCompress: *noCompress,
	})
	if err != nil {
		fail("%v", err)
	}

	printReport(rep)
	if err := writeOut(*out, result); err != nil {
		fail("%v", err)
	}
}

func cmdReveal(args []string) {
	fs := flag.NewFlagSet("reveal", flag.ExitOnError)
	in := fs.String("in", "", "text containing the hidden message")
	inFile := fs.String("infile", "", "read that text from a file")
	out := fs.String("o", "", "write the secret to a file")
	var pass passFlags
	pass.register(fs)
	_ = fs.Parse(args)

	text, err := readTextArg(*in, *inFile)
	if err != nil {
		fail("input: %v", err)
	}

	secret, rep, err := Reveal(text, func() (string, bool) {
		pw, perr := pass.resolve(false)
		return pw, perr == nil && pw != ""
	})
	if err != nil {
		reportRevealError(text, err)
	}

	printReport(rep)
	if err := writeOut(*out, secret); err != nil {
		fail("%v", err)
	}
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	in := fs.String("in", "", "text to inspect")
	inFile := fs.String("infile", "", "read that text from a file")
	_ = fs.Parse(args)

	text, err := readTextArg(*in, *inFile)
	if err != nil {
		fail("input: %v", err)
	}

	_, _, _, rep, err := Scan(text)
	if err != nil {
		var legacy errLegacyPlain
		if errors.As(err, &legacy) {
			fmt.Println("[i] Found a legacy (v1/v2) unencrypted payload.")
			printReport(rep)
			return
		}
		reportRevealError(text, err)
	}

	fmt.Println("[i] Hidden payload detected.")
	printReport(rep)
}

func cmdStrip(args []string) {
	fs := flag.NewFlagSet("strip", flag.ExitOnError)
	in := fs.String("in", "", "text to clean")
	inFile := fs.String("infile", "", "read that text from a file")
	out := fs.String("o", "", "write the cleaned text to a file")
	_ = fs.Parse(args)

	text, err := readTextArg(*in, *inFile)
	if err != nil {
		fail("input: %v", err)
	}

	n := CountCarriers(text)
	fmt.Fprintf(os.Stderr, "[i] Removed %d invisible characters.\n", n)
	if err := writeOut(*out, Strip(text)); err != nil {
		fail("%v", err)
	}
}

func cmdSelfTest() {
	if err := SelfTest(os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] SELF-TEST FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("\n[OK] All self-tests passed.")
}

// reportRevealError turns an extraction failure into a message that actually
// tells the user what to do next, then exits.
func reportRevealError(text string, err error) {
	if errors.Is(err, errAborted) {
		os.Exit(1)
	}
	if errors.Is(err, errBadMagic) && LegacyEncrypted(text) {
		fail("this is a v2 STEGO_ENC: payload. v2 derived its key with a bare SHA-256, so v3 does not accept it. Decrypt it with the old build, then re-hide it with this one.")
	}
	if errors.Is(err, errTruncated) {
		fail("%v\n    Zero-width characters are often stripped by terminals, chat apps and web forms.\n    Try moving the text as a file: sayeh reveal -infile payload.txt", err)
	}
	fail("%v", err)
}

// ---------------------------------------------------------------------------
// Interactive menu
// ---------------------------------------------------------------------------

func interactive() {
	c := newConsole()
	fmt.Println(banner)

	for {
		fmt.Println("\n  1. Hide message (Without Password)")
		fmt.Println("  2. Hide message (With Password)")
		fmt.Println("  3. Extract message")
		fmt.Println("  4. Scan a text for hidden data")
		fmt.Println("  5. Clean a text (remove all invisible characters)")
		fmt.Println("  0. Exit")
		fmt.Println(rule)
		fmt.Print("Select an option: ")

		choice, err := c.line()
		if err != nil {
			fmt.Println("\n[i] Input stream closed. Goodbye.")
			return
		}

		switch strings.ToLower(strings.TrimSpace(choice)) {
		case "1":
			menuHide(c, false)
		case "2":
			menuHide(c, true)
		case "3":
			menuReveal(c)
		case "4":
			menuScan(c)
		case "5":
			menuStrip(c)
		case "0", "q", "quit", "exit":
			fmt.Println("\n[i] Goodbye.")
			return
		default:
			fmt.Println("\n[!] Invalid choice. Enter 0-5.")
		}
	}
}

func menuHide(c *console, withPassword bool) {
	cover := c.askBlock("Enter the COVER text (any language, e.g. English/Persian).")
	secret := c.askBlock("Enter the SECRET message.")
	if secret == "" {
		fmt.Println("\n[!] The secret is empty. Nothing to hide.")
		return
	}

	password := ""
	if withPassword {
		pw, ok := c.newPassword()
		if !ok {
			return
		}
		password = pw
		fmt.Printf("\n[i] Deriving the key (PBKDF2 x%d)...\n", defaultIterations)
	}

	result, rep, err := Hide(cover, secret, HideOptions{Password: password})
	if err != nil {
		fmt.Printf("\n[!] %v\n", err)
		return
	}

	fmt.Println("\n[OK] Message hidden successfully.")
	printReport(rep)

	fmt.Print("\n[?] Save to a file? Enter a path, or press Enter to print it here: ")
	path, _ := c.line()
	if path = strings.TrimSpace(path); path != "" {
		if err := os.WriteFile(path, []byte(result), 0o600); err != nil {
			fmt.Printf("\n[!] Could not write the file: %v\n", err)
			return
		}
		fmt.Printf("\n[OK] Written to %s\n", path)
		fmt.Println("[i] A file is the safest way to move this: copy-paste often strips invisible characters.")
		return
	}

	printBlock("[!] Copy everything between the lines below, invisible characters included:", result)
}

func menuReveal(c *console) {
	text := c.askBlock("Paste the text that contains the hidden message.")

	secret, rep, err := Reveal(text, func() (string, bool) {
		fmt.Println("\n[i] This payload is encrypted.")
		return c.password("Enter the password:")
	})
	if err != nil {
		if errors.Is(err, errAborted) {
			return
		}
		fmt.Printf("\n[!] %v\n", err)
		if errors.Is(err, errBadMagic) && LegacyEncrypted(text) {
			fmt.Println("    (This looks like a v2 STEGO_ENC: payload. v2 used a bare SHA-256 key, so v3 refuses it by design.)")
		}
		return
	}

	printReport(rep)
	printBlock("[OK] Hidden message extracted successfully:", secret)
}

func menuScan(c *console) {
	text := c.askBlock("Paste the text you want to inspect.")

	_, _, _, rep, err := Scan(text)
	if err != nil {
		var legacy errLegacyPlain
		if errors.As(err, &legacy) {
			fmt.Println("\n[i] Found a legacy (v1/v2) unencrypted payload.")
			printReport(rep)
			return
		}
		fmt.Printf("\n[!] %v\n", err)
		return
	}

	fmt.Println("\n[i] Hidden payload detected.")
	printReport(rep)
	if rep.Encrypted {
		fmt.Println("[i] The content stays sealed until the password is supplied (option 3).")
	}
}

func menuStrip(c *console) {
	text := c.askBlock("Paste the text you want to clean.")
	n := CountCarriers(text)
	if n == 0 {
		fmt.Println("\n[i] This text contains no invisible characters.")
		return
	}
	printBlock(fmt.Sprintf("[OK] Removed %d invisible characters:", n), Strip(text))
}
