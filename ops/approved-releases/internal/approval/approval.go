// Package approval verifies Tilde's signed approved-releases list (TDE-344): the runner releases
// the app may connect to. The router section is parsed and validated here but applied only by the
// runner, which accepts the inference router release Tinfoil's SDK proves unless router.revoked
// lists it; router.approved no longer gates a current runner (runner/rust/README.md, Inference
// router trust).
//
// The list is a JSON document wrapped in a signed envelope:
//
//	{"format": "tilde.approved-releases.v1",
//	 "payload": base64(document bytes),
//	 "signature": base64(Ed25519(SigningContext || document bytes)),
//	 "introduction": <envelope>}            // optional, see below
//
// The document is exactly the design's format (the M4 design on Linear TDE-310 §8.1):
//
//	{"version": n, "issued_at": RFC 3339,
//	 "approved": [{"tag": …, "digest": 64 hex}], "revoked": [64 hex],
//	 "router": {"repo": owner/name, "approved": [64 hex], "revoked": [64 hex]},
//	 "successor_key": base64 Ed25519 public key}   // optional
//
// A list is signed by the compiled approval key or by a successor that key endorsed. A document
// signed by key K may name successor_key S. A later list signed by S carries that document's
// envelope as its introduction, so a client that never saw it can still follow the chain from the
// compiled key. Every field is required except successor_key and introduction; unknown fields,
// trailing data and malformed values are refused.
//
// Format v2 (TDE-426) is the same list with the oldest app build each approved release serves:
//
//	"approved": [{"tag": …, "digest": 64 hex, "minimum_app": {"ios": [major, minor, build], "android": versionCode}}]
//
// It has its own format string and signing context ("tilde.approved-releases.v2\n"), so a v1
// signature never verifies as v2 or the other way round, and an introduction must be in the same
// format as the list that carries it. Apps that verify v1 refuse any field they do not know, so the
// minimum can only be published in a separate v2 list; the signer emits both from one document. A
// v2 list also refuses duplicate object keys and an approved digest listed twice with different
// minimums. Every minimum is required and must be well formed, or the whole list is malformed.
package approval

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"
)

const (
	Format = "tilde.approved-releases.v1"
	// SigningContext separates these signatures from every other use of an Ed25519 key.
	SigningContext   = "tilde.approved-releases.v1\n"
	FormatV2         = "tilde.approved-releases.v2"
	SigningContextV2 = "tilde.approved-releases.v2\n"
	MaxListBytes     = 64 * 1024
	maxEntries       = 256
	// maxChain bounds key rotations a single envelope may carry (compiled key plus successors).
	maxChain = 4
	// MaxIOSVersionPart bounds each part of an iOS minimum. The release manifest that numbers
	// builds (service_api.release_manifest_reserve) stores the parts as 32-bit signed integers.
	MaxIOSVersionPart = 1<<31 - 1
	// MaxVersionCode is Google Play's ceiling for an Android versionCode.
	MaxVersionCode = 2_100_000_000
)

var (
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	tagPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	repoPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)
	// integerPattern is a JSON integer literal without sign, fraction, exponent or leading zero.
	integerPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,9})$`)

	ErrMalformed    = errors.New("approval list malformed")
	ErrBadSignature = errors.New("approval list signature invalid")
)

// Scheme is one wire format of the list.
type Scheme int

const (
	V1 Scheme = 1
	// V2 adds minimum_app to every approved release.
	V2 Scheme = 2
)

func (s Scheme) Format() string {
	switch s {
	case V1:
		return Format
	case V2:
		return FormatV2
	}
	return ""
}

func (s Scheme) SigningContext() string {
	switch s {
	case V1:
		return SigningContext
	case V2:
		return SigningContextV2
	}
	return ""
}

func (s Scheme) cacheName() string {
	switch s {
	case V1:
		return "approved-releases.v1"
	case V2:
		return "approved-releases.v2"
	}
	return ""
}

// SchemeOf names the scheme whose format string is format.
func SchemeOf(format string) (Scheme, bool) {
	for _, s := range []Scheme{V1, V2} {
		if s.Format() == format {
			return s, true
		}
	}
	return 0, false
}

// AppMinimum is the oldest app build an approved release serves. iOS is [major, minor, build]:
// CFBundleShortVersionString "major.minor" and CFBundleVersion, compared part by part, because the
// release manifest restarts the build number at 0 on every major or minor bump. Android is the
// versionCode, which only ever increases. An app is too old only when strictly below its platform's
// minimum.
type AppMinimum struct {
	IOS     [3]uint32 `json:"ios"`
	Android uint32    `json:"android"`
}

type Release struct {
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
	// MinimumApp is required in v2 and refused in v1.
	MinimumApp *AppMinimum `json:"minimum_app,omitempty"`
}

type Router struct {
	Repo     string   `json:"repo"`
	Approved []string `json:"approved"`
	Revoked  []string `json:"revoked"`
}

type Document struct {
	Version      uint64    `json:"version"`
	IssuedAt     string    `json:"issued_at"`
	Approved     []Release `json:"approved"`
	Revoked      []string  `json:"revoked"`
	Router       Router    `json:"router"`
	SuccessorKey string    `json:"successor_key,omitempty"`
}

// WithoutMinimums is the v1 document carrying the same releases.
func (d Document) WithoutMinimums() Document {
	releases := make([]Release, len(d.Approved))
	for i, release := range d.Approved {
		releases[i] = Release{Tag: release.Tag, Digest: release.Digest}
	}
	d.Approved = releases
	return d
}

type Envelope struct {
	Format       string    `json:"format"`
	Payload      string    `json:"payload"`
	Signature    string    `json:"signature"`
	Introduction *Envelope `json:"introduction,omitempty"`
}

// Verified is a list whose signature chains to the trusted key.
type Verified struct {
	Document Document
	IssuedAt time.Time
	// Signer signed this document; Chain runs from the trusted key to Signer.
	Signer ed25519.PublicKey
	Chain  []ed25519.PublicKey
}

// Approves reports whether digest is approved and not revoked. Revocation wins.
func (v *Verified) Approves(digest string) bool {
	if v.Revokes(digest) {
		return false
	}
	for _, release := range v.Document.Approved {
		if release.Digest == digest {
			return true
		}
	}
	return false
}

func (v *Verified) Revokes(digest string) bool {
	for _, revoked := range v.Document.Revoked {
		if revoked == digest {
			return true
		}
	}
	return false
}

// Minimum is the oldest app build digest's release serves, when a v2 list approves that release.
// A v2 list gives every listing of a digest the same minimum, so the first one decides.
func (v *Verified) Minimum(digest string) (AppMinimum, bool) {
	if v.Revokes(digest) {
		return AppMinimum{}, false
	}
	for _, release := range v.Document.Approved {
		if release.Digest == digest && release.MinimumApp != nil {
			return *release.MinimumApp, true
		}
	}
	return AppMinimum{}, false
}

func (v *Verified) trusts(key ed25519.PublicKey) bool {
	for _, link := range v.Chain {
		if link.Equal(key) {
			return true
		}
	}
	return false
}

// Verify parses a v1 envelope and checks that it chains to anchor.
func Verify(raw []byte, anchor ed25519.PublicKey) (*Verified, error) { return V1.Verify(raw, anchor) }

// Verify parses an envelope in this scheme and checks that it chains to anchor.
func (s Scheme) Verify(raw []byte, anchor ed25519.PublicKey) (*Verified, error) {
	if len(raw) > MaxListBytes || s.Format() == "" {
		return nil, ErrMalformed
	}
	if len(anchor) != ed25519.PublicKeySize {
		return nil, ErrBadSignature
	}
	if s == V2 && !uniqueKeys(raw) {
		return nil, ErrMalformed
	}
	var envelope Envelope
	if err := strictDecode(raw, &envelope); err != nil {
		return nil, ErrMalformed
	}
	return s.verifyEnvelope(&envelope, anchor, 1)
}

func (s Scheme) verifyEnvelope(envelope *Envelope, anchor ed25519.PublicKey, depth int) (*Verified, error) {
	if envelope.Format != s.Format() {
		return nil, ErrMalformed
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil {
		return nil, ErrMalformed
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, ErrMalformed
	}
	message := append([]byte(s.SigningContext()), payload...)
	signer, chain := anchor, []ed25519.PublicKey{anchor}
	var introduced *Verified
	if !ed25519.Verify(anchor, message, signature) {
		if envelope.Introduction == nil || depth >= maxChain {
			return nil, ErrBadSignature
		}
		introduced, err = s.verifyEnvelope(envelope.Introduction, anchor, depth+1)
		if err != nil {
			return nil, err
		}
		successor, err := decodeKey(introduced.Document.SuccessorKey)
		if err != nil || !ed25519.Verify(successor, message, signature) {
			return nil, ErrBadSignature
		}
		signer, chain = successor, append(append([]ed25519.PublicKey(nil), introduced.Chain...), successor)
	}
	document, issuedAt, err := s.ParseDocument(payload)
	if err != nil {
		return nil, err
	}
	if introduced != nil && document.Version <= introduced.Document.Version {
		return nil, ErrMalformed
	}
	if document.SuccessorKey != "" {
		successor, err := decodeKey(document.SuccessorKey)
		if err != nil || successor.Equal(signer) {
			return nil, ErrMalformed
		}
	}
	return &Verified{Document: document, IssuedAt: issuedAt, Signer: signer, Chain: chain}, nil
}

// ParseDocument strictly parses and validates an unsigned v1 document.
func ParseDocument(payload []byte) (Document, time.Time, error) { return V1.ParseDocument(payload) }

// ParseDocument strictly parses and validates an unsigned document in this scheme.
func (s Scheme) ParseDocument(payload []byte) (Document, time.Time, error) {
	if s.Format() == "" || (s == V2 && !uniqueKeys(payload)) {
		return Document{}, time.Time{}, ErrMalformed
	}
	var required struct {
		Version  *uint64            `json:"version"`
		IssuedAt *string            `json:"issued_at"`
		Approved *[]json.RawMessage `json:"approved"`
		Revoked  *[]string          `json:"revoked"`
		Router   *json.RawMessage   `json:"router"`
		Key      *string            `json:"successor_key"`
	}
	if strictDecode(payload, &required) != nil || required.Version == nil || required.IssuedAt == nil ||
		required.Approved == nil || required.Revoked == nil || required.Router == nil {
		return Document{}, time.Time{}, ErrMalformed
	}
	approved := make([]Release, 0, len(*required.Approved))
	for _, raw := range *required.Approved {
		release, ok := s.parseRelease(raw)
		if !ok {
			return Document{}, time.Time{}, ErrMalformed
		}
		approved = append(approved, release)
	}
	var router struct {
		Repo     *string   `json:"repo"`
		Approved *[]string `json:"approved"`
		Revoked  *[]string `json:"revoked"`
	}
	if strictDecode(*required.Router, &router) != nil || router.Repo == nil || router.Approved == nil || router.Revoked == nil {
		return Document{}, time.Time{}, ErrMalformed
	}
	document := Document{
		Version:  *required.Version,
		IssuedAt: *required.IssuedAt,
		Approved: approved,
		Revoked:  *required.Revoked,
		Router:   Router{Repo: *router.Repo, Approved: *router.Approved, Revoked: *router.Revoked},
	}
	if required.Key != nil {
		if *required.Key == "" {
			return Document{}, time.Time{}, ErrMalformed
		}
		document.SuccessorKey = *required.Key
	}
	issuedAt, err := validate(document)
	if err != nil {
		return Document{}, time.Time{}, err
	}
	if s == V2 && !consistentMinimums(document.Approved) {
		return Document{}, time.Time{}, ErrMalformed
	}
	return document, issuedAt, nil
}

// parseRelease decodes one approved entry. A v1 entry is exactly {tag, digest}; a v2 entry also
// requires minimum_app.
func (s Scheme) parseRelease(raw json.RawMessage) (Release, bool) {
	if s == V1 {
		// The v1 entry keeps its original shape, so minimum_app is an unknown field there.
		var release struct {
			Tag    string `json:"tag"`
			Digest string `json:"digest"`
		}
		if strictDecode(raw, &release) != nil {
			return Release{}, false
		}
		return Release{Tag: release.Tag, Digest: release.Digest}, true
	}
	var release struct {
		Tag        *string          `json:"tag"`
		Digest     *string          `json:"digest"`
		MinimumApp *json.RawMessage `json:"minimum_app"`
	}
	if strictDecode(raw, &release) != nil || release.Tag == nil || release.Digest == nil || release.MinimumApp == nil {
		return Release{}, false
	}
	minimum, ok := parseMinimum(*release.MinimumApp)
	if !ok {
		return Release{}, false
	}
	return Release{Tag: *release.Tag, Digest: *release.Digest, MinimumApp: &minimum}, true
}

// parseMinimum reads {"ios": [major, minor, build], "android": versionCode}. Each value must be a
// plain integer literal in range: iOS major from 1, minor and build from 0, each at most
// MaxIOSVersionPart; Android from 1 to MaxVersionCode. A missing platform, an extra key, null, a
// string, a fraction, an exponent, a sign or the wrong number of iOS parts is malformed; nothing
// falls back to zero.
func parseMinimum(raw json.RawMessage) (AppMinimum, bool) {
	var platforms struct {
		IOS     *json.RawMessage `json:"ios"`
		Android *json.RawMessage `json:"android"`
	}
	if strictDecode(raw, &platforms) != nil || platforms.IOS == nil || platforms.Android == nil {
		return AppMinimum{}, false
	}
	var parts []json.RawMessage
	if strictDecode(*platforms.IOS, &parts) != nil || len(parts) != 3 {
		return AppMinimum{}, false
	}
	major, majorOK := integer(parts[0], 1, MaxIOSVersionPart)
	minor, minorOK := integer(parts[1], 0, MaxIOSVersionPart)
	build, buildOK := integer(parts[2], 0, MaxIOSVersionPart)
	android, androidOK := integer(*platforms.Android, 1, MaxVersionCode)
	if !majorOK || !minorOK || !buildOK || !androidOK {
		return AppMinimum{}, false
	}
	return AppMinimum{IOS: [3]uint32{major, minor, build}, Android: android}, true
}

func integer(raw json.RawMessage, least, most uint64) (uint32, bool) {
	if !integerPattern.Match(raw) {
		return 0, false
	}
	value, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil || value < least || value > most {
		return 0, false
	}
	return uint32(value), true
}

func consistentMinimums(releases []Release) bool {
	seen := make(map[string]AppMinimum, len(releases))
	for _, release := range releases {
		if release.MinimumApp == nil {
			return false
		}
		if earlier, ok := seen[release.Digest]; ok && earlier != *release.MinimumApp {
			return false
		}
		seen[release.Digest] = *release.MinimumApp
	}
	return true
}

func validate(document Document) (time.Time, error) {
	issuedAt, err := time.Parse(time.RFC3339, document.IssuedAt)
	if err != nil || document.Version == 0 || !repoPattern.MatchString(document.Router.Repo) {
		return time.Time{}, ErrMalformed
	}
	if len(document.Approved) > maxEntries || len(document.Revoked) > maxEntries ||
		len(document.Router.Approved) > maxEntries || len(document.Router.Revoked) > maxEntries {
		return time.Time{}, ErrMalformed
	}
	for _, release := range document.Approved {
		if !tagPattern.MatchString(release.Tag) || !digestPattern.MatchString(release.Digest) {
			return time.Time{}, ErrMalformed
		}
	}
	for _, list := range [][]string{document.Revoked, document.Router.Approved, document.Router.Revoked} {
		for _, digest := range list {
			if !digestPattern.MatchString(digest) {
				return time.Time{}, ErrMalformed
			}
		}
	}
	return issuedAt.UTC(), nil
}

// Sign validates a v1 document and returns its envelope signed by key.
func Sign(document Document, key ed25519.PrivateKey, introduction []byte) ([]byte, error) {
	return V1.Sign(document, key, introduction)
}

// Sign validates document and returns its envelope in this scheme signed by key. A successor's list
// passes the envelope that named it as introduction, in the same scheme; Sign checks that the
// introduction names key.
func (s Scheme) Sign(document Document, key ed25519.PrivateKey, introduction []byte) ([]byte, error) {
	payload, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	if _, _, err := s.ParseDocument(payload); err != nil {
		return nil, err
	}
	envelope := Envelope{
		Format:    s.Format(),
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(s.SigningContext()), payload...))),
	}
	if introduction != nil {
		var intro Envelope
		if err := strictDecode(introduction, &intro); err != nil {
			return nil, fmt.Errorf("introduction: %w", err)
		}
		if intro.Format != s.Format() {
			return nil, fmt.Errorf("introduction: %w", ErrMalformed)
		}
		introPayload, err := base64.StdEncoding.Strict().DecodeString(intro.Payload)
		if err != nil {
			return nil, fmt.Errorf("introduction: %w", ErrMalformed)
		}
		introDocument, _, err := s.ParseDocument(introPayload)
		if err != nil {
			return nil, fmt.Errorf("introduction: %w", err)
		}
		public := key.Public().(ed25519.PublicKey)
		if introDocument.SuccessorKey != base64.StdEncoding.EncodeToString(public) {
			return nil, errors.New("introduction does not name this key as successor")
		}
		if document.Version <= introDocument.Version {
			return nil, errors.New("version must exceed the introduction's version")
		}
		envelope.Introduction = &intro
	}
	return json.Marshal(envelope)
}

// DecodeKey decodes a base64 Ed25519 public key.
func DecodeKey(encoded string) (ed25519.PublicKey, error) { return decodeKey(encoded) }

func decodeKey(encoded string) (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, ErrMalformed
	}
	return ed25519.PublicKey(key), nil
}

func strictDecode(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrMalformed
	}
	return nil
}

// uniqueKeys reports whether data is one JSON value in which no object repeats a key. encoding/json
// keeps the last of repeated keys, and another parser may keep the first; refusing them keeps every
// reader of a signed v2 list on the same values.
func uniqueKeys(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value func() bool
	value = func() bool {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, isString := key.(string)
				if err != nil || !isString || seen[name] {
					return false
				}
				seen[name] = true
				if !value() {
					return false
				}
			}
		case '[':
			for decoder.More() {
				if !value() {
					return false
				}
			}
		default:
			return false
		}
		_, err = decoder.Token()
		return err == nil
	}
	if !value() {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}
