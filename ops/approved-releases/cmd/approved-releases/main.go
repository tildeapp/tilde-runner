// Command approved-releases creates and verifies Tilde's signed approved-releases list.
//
//	approved-releases keygen -out KEY                 # writes the private key, prints the public key
//	approved-releases sign -key KEY -in DOC.json -out LIST.json -out-v2 LIST.v2.json \
//	    [-previous CURRENT.json -previous-v2 CURRENT.v2.json] \
//	    [-introduction INTRO.json -introduction-v2 INTRO.v2.json] [-allow-lower-minimum]
//	approved-releases verify -pub BASE64 -in LIST.json  # either format; prints the verified document
//
// DOC.json is a v2 document: every approved release carries minimum_app, the oldest app build it
// serves ({"ios": [major, minor, build], "android": versionCode}). sign writes the same document as
// both lists from one key: v2 as given, and v1 without the minimums for app builds that read only
// v1 (and for the runner's mirror). Both lists share the version, which must exceed each -previous.
//
// The private key file holds the base64 Ed25519 seed. Keep it offline and out of Git.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"com.tilde/runner-client/internal/approval"
)

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: approved-releases keygen|sign|verify [flags]"))
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verifyList(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func keygen(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := flags.String("out", "", "private key file to create (must not exist)")
	_ = flags.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(file, base64.StdEncoding.EncodeToString(private.Seed())); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(public))
	return nil
}

func readKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("key file must hold a base64 32-byte Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// published reads a currently published list of scheme, unverified: the signer only needs its
// document to keep the version moving forward and to compare minimums.
func published(path string, scheme approval.Scheme) (approval.Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return approval.Document{}, err
	}
	var envelope approval.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return approval.Document{}, err
	}
	if envelope.Format != scheme.Format() {
		return approval.Document{}, fmt.Errorf("format %q, expected %q", envelope.Format, scheme.Format())
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return approval.Document{}, err
	}
	document, _, err := scheme.ParseDocument(payload)
	return document, err
}

// lowered names an approved release whose minimum the new document lowers on some platform.
func lowered(previous, next approval.Document) (string, bool) {
	before := map[string]approval.AppMinimum{}
	for _, release := range previous.Approved {
		if release.MinimumApp != nil {
			before[release.Digest] = *release.MinimumApp
		}
	}
	for _, release := range next.Approved {
		earlier, ok := before[release.Digest]
		if !ok {
			continue
		}
		now := *release.MinimumApp
		if now.Android < earlier.Android || compareIOS(now.IOS, earlier.IOS) < 0 {
			return release.Tag, true
		}
	}
	return "", false
}

func compareIOS(a, b [3]uint32) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

func sign(args []string) error {
	flags := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := flags.String("key", "", "private key file")
	in := flags.String("in", "", "unsigned v2 document JSON: every approved release carries minimum_app")
	out := flags.String("out", "", "v1 list to write (without minimums)")
	outV2 := flags.String("out-v2", "", "v2 list to write")
	previous := flags.String("previous", "", "the currently published v1 list; the new version must exceed it")
	previousV2 := flags.String("previous-v2", "", "the currently published v2 list; the new version must exceed it")
	introduction := flags.String("introduction", "", "the v1 list that named this key as successor_key (successor keys only)")
	introductionV2 := flags.String("introduction-v2", "", "the v2 list that named this key as successor_key (successor keys only)")
	allowLower := flags.Bool("allow-lower-minimum", false, "allow lowering an approved release's minimum below -previous-v2")
	_ = flags.Parse(args)
	if *keyPath == "" || *in == "" || *out == "" || *outV2 == "" {
		return errors.New("-key, -in, -out and -out-v2 are required")
	}
	if (*introduction == "") != (*introductionV2 == "") {
		return errors.New("-introduction and -introduction-v2 go together: a successor key signs both lists")
	}
	key, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	document, _, err := approval.V2.ParseDocument(raw)
	if err != nil {
		return fmt.Errorf("document (a v2 document: every approved release needs minimum_app): %w", err)
	}
	for path, scheme := range map[string]approval.Scheme{*previous: approval.V1, *previousV2: approval.V2} {
		if path == "" {
			continue
		}
		current, err := published(path, scheme)
		if err != nil {
			return fmt.Errorf("previous %s: %w", scheme.Format(), err)
		}
		if document.Version <= current.Version {
			return fmt.Errorf("version %d must exceed the published %s version %d", document.Version, scheme.Format(), current.Version)
		}
		if scheme == approval.V2 && !*allowLower {
			if tag, ok := lowered(current, document); ok {
				return fmt.Errorf("the minimum app build of %s is lower than in the published list; pass -allow-lower-minimum only to undo a mistaken raise", tag)
			}
		}
	}
	var intro, introV2 []byte
	if *introduction != "" {
		if intro, err = os.ReadFile(*introduction); err != nil {
			return err
		}
		if introV2, err = os.ReadFile(*introductionV2); err != nil {
			return err
		}
	}
	signedV1, err := approval.V1.Sign(document.WithoutMinimums(), key, intro)
	if err != nil {
		return fmt.Errorf("v1: %w", err)
	}
	signedV2, err := approval.V2.Sign(document, key, introV2)
	if err != nil {
		return fmt.Errorf("v2: %w", err)
	}
	if err := os.WriteFile(*out, append(signedV1, '\n'), 0o644); err != nil {
		return err
	}
	return os.WriteFile(*outV2, append(signedV2, '\n'), 0o644)
}

func verifyList(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ExitOnError)
	pub := flags.String("pub", "", "trusted approval public key (base64), normally the app's compiled key")
	in := flags.String("in", "", "signed list, v1 or v2")
	_ = flags.Parse(args)
	anchor, err := approval.DecodeKey(*pub)
	if err != nil {
		return errors.New("-pub must be a base64 Ed25519 public key")
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	raw = []byte(strings.TrimSpace(string(raw)))
	var envelope struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return approval.ErrMalformed
	}
	scheme, ok := approval.SchemeOf(envelope.Format)
	if !ok {
		return approval.ErrMalformed
	}
	verified, err := scheme.Verify(raw, anchor)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(verified.Document, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	fmt.Fprintf(os.Stderr, "verified: %s version %d, signer %s, chain length %d\n",
		scheme.Format(), verified.Document.Version, base64.StdEncoding.EncodeToString(verified.Signer), len(verified.Chain))
	return nil
}
