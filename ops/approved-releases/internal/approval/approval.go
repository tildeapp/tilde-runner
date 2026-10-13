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
	"time"
)

const (
	Format = "tilde.approved-releases.v1"
	// SigningContext separates these signatures from every other use of an Ed25519 key.
	SigningContext = "tilde.approved-releases.v1\n"
	MaxListBytes   = 64 * 1024
	maxEntries     = 256
	// maxChain bounds key rotations a single envelope may carry (compiled key plus successors).
	maxChain = 4
)

var (
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	tagPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	repoPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)

	ErrMalformed    = errors.New("approval list malformed")
	ErrBadSignature = errors.New("approval list signature invalid")
)

type Release struct {
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
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

func (v *Verified) trusts(key ed25519.PublicKey) bool {
	for _, link := range v.Chain {
		if link.Equal(key) {
			return true
		}
	}
	return false
}

// Verify parses an envelope and checks that it chains to anchor.
func Verify(raw []byte, anchor ed25519.PublicKey) (*Verified, error) {
	if len(raw) > MaxListBytes {
		return nil, ErrMalformed
	}
	if len(anchor) != ed25519.PublicKeySize {
		return nil, ErrBadSignature
	}
	var envelope Envelope
	if err := strictDecode(raw, &envelope); err != nil {
		return nil, ErrMalformed
	}
	return verifyEnvelope(&envelope, anchor, 1)
}

func verifyEnvelope(envelope *Envelope, anchor ed25519.PublicKey, depth int) (*Verified, error) {
	if envelope.Format != Format {
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
	message := append([]byte(SigningContext), payload...)
	signer, chain := anchor, []ed25519.PublicKey{anchor}
	var introduced *Verified
	if !ed25519.Verify(anchor, message, signature) {
		if envelope.Introduction == nil || depth >= maxChain {
			return nil, ErrBadSignature
		}
		introduced, err = verifyEnvelope(envelope.Introduction, anchor, depth+1)
		if err != nil {
			return nil, err
		}
		successor, err := decodeKey(introduced.Document.SuccessorKey)
		if err != nil || !ed25519.Verify(successor, message, signature) {
			return nil, ErrBadSignature
		}
		signer, chain = successor, append(append([]ed25519.PublicKey(nil), introduced.Chain...), successor)
	}
	document, issuedAt, err := ParseDocument(payload)
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

// ParseDocument strictly parses and validates an unsigned document.
func ParseDocument(payload []byte) (Document, time.Time, error) {
	var required struct {
		Version  *uint64          `json:"version"`
		IssuedAt *string          `json:"issued_at"`
		Approved *[]Release       `json:"approved"`
		Revoked  *[]string        `json:"revoked"`
		Router   *json.RawMessage `json:"router"`
		Key      *string          `json:"successor_key"`
	}
	if strictDecode(payload, &required) != nil || required.Version == nil || required.IssuedAt == nil ||
		required.Approved == nil || required.Revoked == nil || required.Router == nil {
		return Document{}, time.Time{}, ErrMalformed
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
		Approved: *required.Approved,
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
	return document, issuedAt, nil
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

// Sign validates document and returns its envelope signed by key. A successor's list passes the
// envelope that named it as introduction; Sign checks that the introduction names key.
func Sign(document Document, key ed25519.PrivateKey, introduction []byte) ([]byte, error) {
	payload, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	if _, _, err := ParseDocument(payload); err != nil {
		return nil, err
	}
	envelope := Envelope{
		Format:    Format,
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(SigningContext), payload...))),
	}
	if introduction != nil {
		var intro Envelope
		if err := strictDecode(introduction, &intro); err != nil {
			return nil, fmt.Errorf("introduction: %w", err)
		}
		introPayload, err := base64.StdEncoding.Strict().DecodeString(intro.Payload)
		if err != nil {
			return nil, fmt.Errorf("introduction: %w", ErrMalformed)
		}
		introDocument, _, err := ParseDocument(introPayload)
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
