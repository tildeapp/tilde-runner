// Command attest verifies a Tinfoil enclave for the hosted runner's uptime check
// (runner/ops/uptime.yml) the way the app's runner client does (internal/transport): the same
// Tinfoil SDK at the version this module pins, an enclave handle that proves which release of the
// repository the enclave runs, and requests bound to the TLS key that attestation names. The check
// therefore fails when the app's verification would, and moves with every SDK update the app takes.
//
//	attest verify -enclave HOST -repo OWNER/NAME
//	attest get -enclave HOST -repo OWNER/NAME@TAG@sha256:DIGEST -path /health
//
// verify prints {"enclave","repo","digest","tag","status","freshness_expires_at"} with status
// "ok", or with status "failed" and exit status 1; the verifier's error goes to stderr. get accepts
// only a release pinned by tag and digest, sends one GET over the key-bound transport and prints
// the body whatever the HTTP status, as uptime_check.sh expects; it exits 1 only when no verified
// response arrived. The body is never echoed to stderr: /v2/host carries identifiers that the
// public Actions log must not show.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

const (
	maxBodyBytes = 1 << 20
	// overall bounds one invocation, verification retries included, so a stalled enclave or
	// endorsement fetch fails the step instead of holding the job until its timeout.
	overall = 3 * time.Minute
)

var (
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hostPattern   = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
	// connect is replaced in tests; the SDK needs a live enclave.
	connect = verifiedTransport
)

// record is the attestation summary uptime_check.sh reads (attested_digest).
type record struct {
	Enclave            string `json:"enclave"`
	Repo               string `json:"repo"`
	Digest             string `json:"digest,omitempty"`
	Tag                string `json:"tag,omitempty"`
	Status             string `json:"status"`
	FreshnessExpiresAt string `json:"freshness_expires_at,omitempty"`
}

func main() {
	timer := time.AfterFunc(overall, func() {
		fmt.Fprintln(os.Stderr, "attest: timed out")
		os.Exit(1)
	})
	code := run(os.Args[1:], os.Stdout, os.Stderr)
	timer.Stop()
	os.Exit(code)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usage(stderr)
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	host := flags.String("enclave", "", "enclave hostname")
	ref := flags.String("repo", "", "OWNER/NAME, pinned as OWNER/NAME@TAG@sha256:DIGEST for get")
	path := flags.String("path", "", "absolute request path (get)")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || !hostPattern.MatchString(*host) || *ref == "" {
		return usage(stderr)
	}
	repo, _, digest, err := verify.ParseReference(*ref)
	if err != nil {
		fmt.Fprintf(stderr, "attest: %v\n", err)
		return 2
	}
	switch args[0] {
	case "verify":
		if *path != "" {
			return usage(stderr)
		}
		return verifyCommand(*host, *ref, repo, digest, stdout, stderr)
	case "get":
		if !digestPattern.MatchString(digest) || !strings.HasPrefix(*path, "/") || strings.HasPrefix(*path, "//") {
			return usage(stderr)
		}
		return getCommand(*host, *ref, repo, digest, *path, stdout, stderr)
	default:
		return usage(stderr)
	}
}

func usage(stderr io.Writer) int {
	fmt.Fprintln(stderr, "usage: attest verify -enclave HOST -repo OWNER/NAME[@TAG][@sha256:DIGEST]")
	fmt.Fprintln(stderr, "       attest get -enclave HOST -repo OWNER/NAME@TAG@sha256:DIGEST -path /PATH")
	return 2
}

func verifyCommand(host, ref, repo, digest string, stdout, stderr io.Writer) int {
	verified, _, err := connect(host, ref, repo, digest)
	if err != nil {
		fmt.Fprintf(stderr, "attest: verifying %s: %v\n", host, err)
		writeRecord(stdout, record{Enclave: host, Repo: repo, Status: "failed"})
		return 1
	}
	out := record{Enclave: host, Repo: verified.ConfigRepo, Digest: verified.CodeDigest, Tag: verified.CodeTag, Status: "ok"}
	if !verified.FreshnessExpiresAt.IsZero() {
		out.FreshnessExpiresAt = verified.FreshnessExpiresAt.UTC().Format(time.RFC3339)
	}
	writeRecord(stdout, out)
	return 0
}

func getCommand(host, ref, repo, digest, path string, stdout, stderr io.Writer) int {
	_, transport, err := connect(host, ref, repo, digest)
	if err != nil {
		fmt.Fprintf(stderr, "attest: verifying %s: %v\n", host, err)
		return 1
	}
	client := &http.Client{Transport: transport, Timeout: time.Minute}
	response, err := client.Get("https://" + host + path)
	if err != nil {
		fmt.Fprintf(stderr, "attest: GET %s: %v\n", path, err)
		return 1
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	if err != nil || len(body) > maxBodyBytes {
		fmt.Fprintf(stderr, "attest: GET %s: unreadable or oversized body\n", path)
		return 1
	}
	fmt.Fprintf(stderr, "attest: GET %s: HTTP %d\n", path, response.StatusCode)
	if _, err := stdout.Write(body); err != nil {
		return 1
	}
	return 0
}

func writeRecord(stdout io.Writer, out record) {
	encoded, _ := json.Marshal(out)
	fmt.Fprintln(stdout, string(encoded))
}

// admit is the app's approvedTransport check without the list: the SDK proved this release of
// some repository, and it must be the requested repository and, when pinned, the pinned digest.
func admit(verified *verify.Verification, repo, digest string) error {
	if verified.ConfigRepo != repo {
		return fmt.Errorf("attested repository %q is not %q", verified.ConfigRepo, repo)
	}
	if !digestPattern.MatchString(verified.CodeDigest) {
		return errors.New("attestation has no release digest")
	}
	if digest != "" && verified.CodeDigest != digest {
		return fmt.Errorf("attested release %s is not the pinned %s", verified.CodeDigest, digest)
	}
	return nil
}

// verifiedTransport verifies the enclave through the SDK handle, as transport.newGateway does,
// and returns the verification with a transport bound to its attested TLS key.
func verifiedTransport(host, ref, repo, digest string) (*verify.Verification, http.RoundTripper, error) {
	handle, err := enclave.NewHandle(host, ref, nil)
	if err != nil {
		return nil, nil, err
	}
	var first atomic.Pointer[verify.Verification]
	transport, err := handle.NewTransport(func(verified *verify.Verification) (http.RoundTripper, error) {
		if err := admit(verified, repo, digest); err != nil {
			return nil, err
		}
		key, err := verified.TLSPublicKeyFP()
		if err != nil {
			return nil, err
		}
		first.CompareAndSwap(nil, verified)
		return &enclave.TLSBoundRoundTripper{ExpectedPublicKey: key}, nil
	}, isKeyRejection)
	if err != nil {
		return nil, nil, err
	}
	verified := first.Load()
	if verified == nil {
		return nil, nil, errors.New("the SDK returned a transport without a verification")
	}
	return verified, transport, nil
}

// isKeyRejection is internal/transport's classification: the SDK's TLS-bound transport reports a
// handshake whose key no longer matches the attestation as an AttestationError.
func isKeyRejection(err error) bool {
	var attestation *verify.AttestationError
	return errors.As(err, &attestation)
}
