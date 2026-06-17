package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AlexanderYastrebov/vanity25519"
)

const usage = `Usage:
    onion-vanity-address [--client] [--from PUBLIC_KEY] [--timeout TIMEOUT] [--count COUNT] PATTERN [PATTERN]...
    onion-vanity-address [--client] [--from PUBLIC_KEY] [--timeout TIMEOUT] [--count COUNT] --suffix SUFFIX [SUFFIX]...
    onion-vanity-address [--client] [--from PUBLIC_KEY] [--timeout TIMEOUT] [--count COUNT] --both PREFIX SUFFIX
    onion-vanity-address [--start9] [--timeout TIMEOUT] [--count COUNT] PATTERN [PATTERN]...
    onion-vanity-address [--start9] [--timeout TIMEOUT] [--count COUNT] --suffix SUFFIX [SUFFIX]...
    onion-vanity-address [--start9] [--timeout TIMEOUT] [--count COUNT] --both PREFIX SUFFIX
    onion-vanity-address [--client] --offset OFFSET
    onion-vanity-address [--start9] --offset OFFSET

Options:
    --both                  Search for addresses/keys matching the supplied PREFIX and SUFFIX.
    --client                Search for a Client Authorization keypair instead of an Onion Service keypair.
    --count COUNT           Stop after finding COUNT matching keys. Defaults to 3.
    --from PUBLIC_KEY       Start search from the given public key.
    --offset OFFSET         Add an offset to the secret keys read from standard input.
    --start9                Write Onion Service secret keys as Start9 StartOS-compatible 88-character base64 files.
    --suffix                Search for suffixes instead of prefixes.
    --timeout TIMEOUT       Stop after the specified timeout (e.g., 10s, 5m, 1h).

onion-vanity-address generates Onion Service ed25519 keypairs with onion addresses matching one of the specified PATTERNs.
By default it writes each matching Onion Service keypair to a directory named after the hostname. Each directory contains:

    hostname
    hs_ed25519_public_key
    hs_ed25519_secret_key

With --start9, it writes one file per hostname. The file is named after the hostname and contains the 88-character
base64-encoded expanded secret key expected by Start9 StartOS's Tor plugin UI.

In --client mode, onion-vanity-address generates Client Authorization keypairs with public keys matching one of the specified PATTERNs.
Client keypairs are still printed to standard output.

By default, PATTERNs are matched as prefixes. With --suffix, they are matched as suffixes.
With --both, exactly two positional arguments are required: PREFIX and SUFFIX.
Suffix matching for Onion Service addresses checks the address body before the .onion suffix.

PATTERN must use base32 character set "` + onionBase32EncodingCharset + `" for Onion Service keypairs
and "` + clientBase32EncodingCharset + `" for Client Authorization keypairs.

In --from mode, onion-vanity-address starts the search from a specified public key and outputs matching offsets.
The offset can be added to the corresponding secret key to derive the new keypair.

In --offset mode, onion-vanity-address reads the secret key from standard input, adds the specified offset,
and writes the resulting Onion Service keypair in the selected output format.

Service examples:

    # Generate three new service keypairs with addresses having any of the specified prefixes
    $ onion-vanity-address test t3st testaddr
    Searching test,t3st,testaddr | elapsed 10s | tried 564.0M | 56.4M attempts/s | found 1/3 | remaining 2
    Found test... testabc...onion (1/3) after 12s and 676.8M attempts (56.4M attempts/s)
    Wrote Tor service files to testabc...onion/

    # Generate one Start9-compatible key
    $ onion-vanity-address --start9 --count 1 test
    Found test... testxyz...onion (1/1) after 5s and 282.0M attempts (56.4M attempts/s)
    Wrote Start9 key to testxyz...onion

    # Search for a suffix instead of a prefix
    $ onion-vanity-address --suffix --count 1 test
    Warning: suffix matching is slower because each candidate must be fully encoded before it can be checked.
    Found ...test abcxyz...test.onion (1/1) after 2m and 5.6B attempts (46.7M attempts/s)
    Wrote Tor service files to abcxyz...test.onion/

    # Search for both a prefix and suffix. This is much slower than searching only one side.
    $ onion-vanity-address --both --count 1 test pleb
    Warning: --both requires each result to match the supplied prefix and suffix. This can take much longer than searching only one side.

    # Find prefix offset from the specified public key
    $ onion-vanity-address --from PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAAAC1ooweCbRP6ncFQs3NRyK40fRwaodrmH572D8py+tCQ== cebula
    Found cebula... cebulasfa3b4ahol44ydvc2an6b4vgpjcguarwsj35dr6jbanveea4id.onion (1/3) after 2s and 78.5M attempts (44.9M attempts/s)
    ---
    hostname: cebulasfa3b4ahol44ydvc2an6b4vgpjcguarwsj35dr6jbanveea4id.onion
    offset: cIZ5Birj/cY=

    # Apply offset to the secret key and write Tor service files
    $ echo PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAAAQEW4Rhot7oroPaETlAEG3GPAntvJ1agF2c7A2AXmBW3WqAH0oUZ1hySvvZl3hc9dSAIc49h1UuCPZacOWp4vQ \
    | onion-vanity-address --offset cIZ5Birj/cY=
    Wrote Tor service files to cebulasfa3b4ahol44ydvc2an6b4vgpjcguarwsj35dr6jbanxenrcqd.onion/

Client examples:

    # Generate client authorization keypairs with the specified prefix
    $ onion-vanity-address --client --count 1 LEMON
    Found LEMON... in 0s after 15.0M attempts (63.6M attempts/s)
    ---
    public_key: LEMON7P5L7FEZZEJJGQTC3PDFRHEOOBP3H2XXHRFQSD72OKKEE5Q
    private_key: AAADDFICRR46KLA52KV2QRIN6GUWIPEIVZZZUVZLC5UVE53QNMTA
`

type searchOptions struct {
	count  int
	start9 bool
	mode   matchMode
}

type foundKey struct {
	publicKey []byte
	offset    *big.Int
}

func must[T any](v T, err error) T {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return v
}

func check(cond bool, msg string) {
	if !cond {
		fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
		flag.Usage()
		os.Exit(1)
	}
}

func main() {
	var clientFlag bool
	var fromFlag string
	var offsetFlag string
	var timeoutFlag time.Duration
	var countFlag int
	var start9Flag bool
	var suffixFlag bool
	var bothFlag bool

	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.BoolVar(&bothFlag, "both", false, "search for keys matching the supplied prefix and suffix")
	flag.BoolVar(&clientFlag, "client", false, "search for a Client Authorization keypair instead of an Onion Service keypair")
	flag.IntVar(&countFlag, "count", 3, "stop after finding this many matching keys")
	flag.StringVar(&fromFlag, "from", "", "public key to start search from")
	flag.StringVar(&offsetFlag, "offset", "", "offset to add to the secret key read from stdin")
	flag.BoolVar(&start9Flag, "start9", false, "write Start9 StartOS-compatible 88-character base64 secret key files")
	flag.BoolVar(&suffixFlag, "suffix", false, "search for suffixes instead of prefixes")
	flag.DurationVar(&timeoutFlag, "timeout", 0, "stop after specified timeout")
	flag.Parse()

	check(countFlag > 0, "--count must be greater than zero")
	check(!(clientFlag && start9Flag), "--start9 can only be used with Onion Service keypairs")
	check(!(fromFlag != "" && start9Flag), "--start9 can not be used with --from because --from only outputs offsets")
	check(!(suffixFlag && bothFlag), "--suffix and --both can not be used together")

	mode := matchPrefix
	if suffixFlag {
		mode = matchSuffix
	}
	if bothFlag {
		mode = matchBoth
	}

	opts := searchOptions{count: countFlag, start9: start9Flag, mode: mode}

	if offsetFlag != "" {
		check(fromFlag == "", "--from can not be used with --offset")
		check(timeoutFlag == 0, "--timeout can not be used with --offset")
		check(mode == matchPrefix, "--suffix and --both can not be used with --offset")
		check(flag.NArg() == 0, "PATTERN can not be used with --offset")

		offset := new(big.Int).SetBytes(must(base64.StdEncoding.DecodeString(offsetFlag)))

		if clientFlag {
			offsetClientKey(offset)
		} else {
			offsetServiceKey(offset, opts)
		}
		return
	}

	if opts.mode == matchBoth {
		check(flag.NArg() == 2, "--both requires exactly two patterns: PREFIX SUFFIX")
	} else {
		check(flag.NArg() > 0, "PATTERN required")
	}

	if opts.mode == matchSuffix {
		fmt.Fprintln(os.Stderr, "Warning: suffix matching is slower because each candidate must be fully encoded before it can be checked.")
	}
	if opts.mode == matchBoth {
		fmt.Fprintln(os.Stderr, "Warning: --both requires each result to match the supplied prefix and suffix. This can take much longer than searching only one side.")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if timeoutFlag > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeoutFlag)
		defer cancel()
	}

	if clientFlag {
		searchClientKey(ctx, flag.Args(), fromFlag, opts)
	} else {
		searchServiceKey(ctx, flag.Args(), fromFlag, opts)
	}
}

func offsetClientKey(offset *big.Int) {
	startSecretKey := must(readClientSecretKey(os.Stdin))
	vanitySecretKey := must(vanity25519.Add(startSecretKey, offset))
	vanityPublicKey := must(clientPublicKeyFor(vanitySecretKey))

	fmt.Println("---")
	fmt.Printf("public_key: %s\n", clientBase32Encoding.EncodeToString(vanityPublicKey))
	fmt.Printf("private_key: %s\n", clientBase32Encoding.EncodeToString(vanitySecretKey))
}

func offsetServiceKey(offset *big.Int, opts searchOptions) {
	startSecretKey := must(readServiceSecretKey(os.Stdin))
	vanitySecretKey := must(add(startSecretKey, offset))
	vanityPublicKey := must(publicKeyFor(vanitySecretKey))
	address := encodeOnionAddress(vanityPublicKey)

	path := must(writeServiceKey(address, vanityPublicKey, vanitySecretKey, opts.start9))
	printOutputPath(path, opts.start9)
}

func searchClientKey(ctx context.Context, prefixes []string, from string, opts searchOptions) {
	for i := 1; i <= opts.count; i++ {
		var startSecretKey, startPublicKey []byte
		if from != "" {
			startPublicKey = must(decodeClientPublicKey(from))
		} else {
			startSecretKey = make([]byte, 32)
			must(rand.Read(startSecretKey))
			startPublicKey = must(clientPublicKeyFor(startSecretKey))
		}

		start := time.Now()
		found, vanityPublicKey, attempts := parallel(vanity25519.Search, ctx, startPublicKey, must(clientMatcher(prefixes, opts.mode)))
		elapsed := time.Since(start)

		if found == nil {
			fmt.Fprintf(os.Stderr, "Stopped searching %s after %s and %s attempts (%s attempts/s)\n",
				formatSearchPatterns(prefixes, opts.mode), elapsed.Round(time.Second), formatCompactUint(attempts), formatCompactRate(attempts, elapsed))
			os.Exit(2)
		}

		var vanitySecretKey []byte
		if len(startSecretKey) > 0 {
			vanitySecretKey = must(vanity25519.Add(startSecretKey, found))
			vanityPublicKey = must(clientPublicKeyFor(vanitySecretKey))
		}

		vanityPublicKeyEncoded := clientBase32Encoding.EncodeToString(vanityPublicKey)
		match := matchDescription(prefixes, vanityPublicKeyEncoded, opts.mode)

		fmt.Fprintf(os.Stderr, "Found %s (%d/%d) in %s after %s attempts (%s attempts/s)\n",
			match, i, opts.count, elapsed.Round(time.Second), formatCompactUint(attempts), formatCompactRate(attempts, elapsed))

		fmt.Println("---")
		fmt.Printf("public_key: %s\n", vanityPublicKeyEncoded)
		if len(vanitySecretKey) > 0 {
			fmt.Printf("private_key: %s\n", clientBase32Encoding.EncodeToString(vanitySecretKey))
		} else {
			fmt.Printf("offset: %s\n", base64.StdEncoding.EncodeToString(found.Bytes()))
		}
	}
}

func searchServiceKey(ctx context.Context, prefixes []string, from string, opts searchOptions) {
	var startSecretKey, startPublicKey []byte
	if from != "" {
		startPublicKey = must(decodeServicePublicKey(from))
	} else {
		startSecretKey = make([]byte, 32)
		must(rand.Read(startSecretKey))
		startPublicKey = must(publicKeyFor(startSecretKey))
	}

	start := time.Now()
	var attemptsTotal atomic.Uint64
	var foundTotal atomic.Int64

	progressCtx, stopProgress := context.WithCancel(context.Background())
	defer stopProgress()
	go reportProgress(progressCtx, start, &attemptsTotal, &foundTotal, opts.count, prefixes, opts.mode)

	var verifyFound func(publicKey []byte, offset *big.Int) ([]byte, bool)
	if opts.mode != matchPrefix {
		exactMatch := must(exactAddressMatcher(prefixes, opts.mode))
		verifyFound = func(_ []byte, offset *big.Int) ([]byte, bool) {
			exactPublicKey := must(publicKeyForOffset(startPublicKey, offset))
			return exactPublicKey, exactMatch(exactPublicKey)
		}
	}

	results, attempts := parallelService(ctx, startPublicKey, must(addressMatcher(prefixes, opts.mode)), verifyFound, opts.count, &attemptsTotal, func(index int, publicKey []byte, offset *big.Int) {
		foundTotal.Store(int64(index))
		address := encodeOnionAddress(publicKey)
		match := matchDescription(prefixes, onionAddressBody(address), opts.mode)
		elapsed := time.Since(start)

		clearProgressLine()
		fmt.Fprintf(os.Stderr, "Found %s %s (%d/%d) after %s and %s attempts (%s attempts/s)\n",
			match, address, index, opts.count, elapsed.Round(time.Second), formatCompactUint(attemptsTotal.Load()), formatCompactRate(attemptsTotal.Load(), elapsed))
	})

	stopProgress()
	clearProgressLine()

	if len(results) == 0 {
		elapsed := time.Since(start)
		fmt.Fprintf(os.Stderr, "Stopped searching %s after %s and %s attempts (%s attempts/s)\n",
			formatSearchPatterns(prefixes, opts.mode), elapsed.Round(time.Second), formatCompactUint(attempts), formatCompactRate(attempts, elapsed))
		os.Exit(2)
	}

	for _, result := range results {
		if len(startSecretKey) == 0 {
			address := encodeOnionAddress(result.publicKey)
			fmt.Println("---")
			fmt.Printf("%s: %s\n", hostnameFileName, address)
			fmt.Printf("offset: %s\n", base64.StdEncoding.EncodeToString(result.offset.Bytes()))
			continue
		}

		vanitySecretKey := must(add(startSecretKey, result.offset))
		vanityPublicKey := must(publicKeyFor(vanitySecretKey))
		address := encodeOnionAddress(vanityPublicKey)
		path := must(writeServiceKey(address, vanityPublicKey, vanitySecretKey, opts.start9))
		printOutputPath(path, opts.start9)
	}

	if len(results) < opts.count {
		elapsed := time.Since(start)
		fmt.Fprintf(os.Stderr, "Stopped after finding %d/%d keys in %s and %s attempts (%s attempts/s)\n",
			len(results), opts.count, elapsed.Round(time.Second), formatCompactUint(attempts), formatCompactRate(attempts, elapsed))
	}
}

func writeServiceKey(address string, publicKey, secretKey []byte, start9 bool) (string, error) {
	if start9 {
		path := filepath.Clean(address)
		if err := os.WriteFile(path, []byte(encodeStart9ServiceSecretKey(secretKey)), 0o600); err != nil {
			return "", err
		}
		return path, nil
	}

	dir := filepath.Clean(address)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, hostnameFileName), []byte(address+"\n"), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, publicKeyFileName), serializeServicePublicKey(publicKey), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, secretKeyFileName), serializeServiceSecretKey(secretKey), 0o600); err != nil {
		return "", err
	}
	return dir + string(os.PathSeparator), nil
}

func printOutputPath(path string, start9 bool) {
	if start9 {
		fmt.Fprintf(os.Stderr, "Wrote Start9 key to %s\n", path)
		return
	}
	fmt.Fprintf(os.Stderr, "Wrote Tor service files to %s\n", path)
}

func reportProgress(ctx context.Context, start time.Time, attempts *atomic.Uint64, found *atomic.Int64, target int, patterns []string, mode matchMode) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	render := func() {
		elapsed := time.Since(start).Round(time.Second)
		foundCount := int(found.Load())
		remaining := target - foundCount
		if remaining < 0 {
			remaining = 0
		}

		fmt.Fprintf(os.Stderr, "\r\033[KSearching %s | elapsed %s | tried %s | %s attempts/s | found %d/%d | remaining %d",
			formatSearchPatterns(patterns, mode), elapsed, formatCompactUint(attempts.Load()), formatCompactRate(attempts.Load(), time.Since(start)), foundCount, target, remaining)
	}

	render()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			render()
		}
	}
}

func clearProgressLine() {
	fmt.Fprint(os.Stderr, "\r\033[K")
}

func formatCompactRate(attempts uint64, elapsed time.Duration) string {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		return "0"
	}
	return formatCompactFloat(float64(attempts) / seconds)
}

func formatCompactUint(n uint64) string {
	return formatCompactFloat(float64(n))
}

func formatCompactFloat(n float64) string {
	units := []string{"", "K", "M", "B", "T", "P", "E"}
	unit := 0
	for n >= 1000 && unit < len(units)-1 {
		n /= 1000
		unit++
	}

	if unit == 0 {
		return fmt.Sprintf("%.0f", n)
	}
	return fmt.Sprintf("%.1f%s", n, units[unit])
}

func clientMatcher(patterns []string, mode matchMode) (func([]byte) bool, error) {
	if mode == matchPrefix {
		return matchAnyOf(patterns, clientPrefixMatch)
	}

	return encodedMatcher(patterns, mode, validateClientPattern, func(publicKey []byte) string {
		return clientBase32Encoding.EncodeToString(publicKey)
	})
}

func addressMatcher(patterns []string, mode matchMode) (func([]byte) bool, error) {
	if mode == matchPrefix {
		return matchAnyOf(patterns, addressPrefixMatch)
	}

	match, err := stringMatcher(patterns, mode, validateAddressPattern)
	if err != nil {
		return nil, err
	}

	return func(publicKey []byte) bool {
		candidate := append([]byte(nil), publicKey...)
		candidate[31] &^= 0x80
		if match(onionAddressBody(encodeOnionAddress(candidate))) {
			return true
		}

		candidate[31] |= 0x80
		return match(onionAddressBody(encodeOnionAddress(candidate)))
	}, nil
}

func exactAddressMatcher(patterns []string, mode matchMode) (func([]byte) bool, error) {
	match, err := stringMatcher(patterns, mode, validateAddressPattern)
	if err != nil {
		return nil, err
	}

	return func(publicKey []byte) bool {
		return match(onionAddressBody(encodeOnionAddress(publicKey)))
	}, nil
}

func clientPrefixMatch(prefix string) (func([]byte) bool, error) {
	if err := validateClientPattern(prefix); err != nil {
		return nil, err
	}
	return hasPrefix(prefix, clientBase32Encoding)
}

func addressPrefixMatch(prefix string) (func([]byte) bool, error) {
	if err := validateAddressPattern(prefix); err != nil {
		return nil, err
	}
	return hasPrefix(prefix, onionBase32Encoding)
}

func validateClientPattern(pattern string) error {
	if len(pattern) == 0 {
		return fmt.Errorf("empty pattern")
	}

	if strings.TrimLeft(pattern, clientBase32EncodingCharset) != "" {
		return fmt.Errorf("client public key pattern must use characters %q", clientBase32EncodingCharset)
	}

	return nil
}

func validateAddressPattern(pattern string) error {
	if len(pattern) == 0 {
		return fmt.Errorf("empty pattern")
	}

	if strings.TrimLeft(pattern, onionBase32EncodingCharset) != "" {
		return fmt.Errorf("address pattern must use characters %q", onionBase32EncodingCharset)
	}

	return nil
}

type searchFunc func(ctx context.Context, startPublicKey []byte, startOffset *big.Int, batchSize int, accept func(candidatePublicKey []byte) bool, yield func(publicKey []byte, offset *big.Int)) uint64

func parallel(search searchFunc, ctx context.Context, startPublicKey []byte, test func([]byte) bool) (*big.Int, []byte, uint64) {
	var result atomic.Pointer[big.Int]
	var vanityPublicKey []byte

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var attemptsTotal atomic.Uint64
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			startOffset, _ := rand.Int(rand.Reader, new(big.Int).SetUint64(1<<64-1))
			attempts := search(ctx, startPublicKey, startOffset, 4096, test, func(pk []byte, offset *big.Int) {
				if result.CompareAndSwap(nil, offset) {
					vanityPublicKey = pk
					cancel()
				}
			})
			attemptsTotal.Add(attempts)
		}()
	}
	wg.Wait()

	return result.Load(), vanityPublicKey, attemptsTotal.Load()
}

func parallelService(ctx context.Context, startPublicKey []byte, test func([]byte) bool, verify func(publicKey []byte, offset *big.Int) ([]byte, bool), target int, attemptsTotal *atomic.Uint64, onFound func(index int, publicKey []byte, offset *big.Int)) ([]foundKey, uint64) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var mu sync.Mutex
	var results []foundKey
	var wg sync.WaitGroup

	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()

			startOffset, _ := rand.Int(rand.Reader, new(big.Int).SetUint64(1<<64-1))
			searchWithProgress(ctx, startPublicKey, startOffset, 4096, test, func(delta uint64) {
				attemptsTotal.Add(delta)
			}, func(pk []byte, offset *big.Int) {
				pkCopy := append([]byte(nil), pk...)
				offsetCopy := new(big.Int).Set(offset)

				mu.Lock()
				if len(results) >= target {
					mu.Unlock()
					return
				}
				mu.Unlock()

				if verify != nil {
					var ok bool
					pkCopy, ok = verify(pkCopy, offsetCopy)
					if !ok {
						return
					}
				}

				mu.Lock()
				if len(results) >= target {
					mu.Unlock()
					return
				}

				results = append(results, foundKey{publicKey: pkCopy, offset: offsetCopy})
				index := len(results)
				if index >= target {
					cancel()
				}
				mu.Unlock()

				if onFound != nil {
					onFound(index, pkCopy, offsetCopy)
				}
			})
		}()
	}

	wg.Wait()
	return results, attemptsTotal.Load()
}
