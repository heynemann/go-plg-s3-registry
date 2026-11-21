// Package target implements v1 rollout predicates and deterministic bucketing.
package target

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/bits"
	"strings"
	"unicode/utf8"
)

const (
	bucketDomain   = "go-plg-s3-registry/bucket/v1"
	maxBasisPoints = 10_000
	maxIDBytes     = 63
	maxSubject     = 4096
	maxAttributes  = 32
	maxPath        = 128
	maxString      = 1024
	maxExpression  = 4096
	maxDepth       = 16
	maxNodes       = 128
)

var (
	errVersion     = errors.New("target: unsupported spec version")
	errSeed        = errors.New("target: seed must be 64 lowercase hexadecimal characters")
	errSchema      = errors.New("target: invalid attribute schema")
	errPredicate   = errors.New("target: invalid predicate")
	errComplexity  = errors.New("target: predicate exceeds complexity limit")
	errProgram     = errors.New("target: program was not compiled")
	errRoutingKey  = errors.New("target: invalid routing key")
	errSubject     = errors.New("target: subject key must be 1 to 4096 bytes")
	errBasisPoints = errors.New("target: basis points must be at most 10000")
	errContext     = errors.New("target: too many attributes")
	errMissing     = errors.New("target: required attribute is missing")
	errAttribute   = errors.New("target: required attribute has an invalid type or value")
)

// Spec is the signed predicate and bucketing configuration. Attributes maps
// case-sensitive paths to "bool", "string", or "int". Seed is lowercase hex.
type Spec struct {
	Version    int               `json:"version"`
	Expression string            `json:"expression"`
	Attributes map[string]string `json:"attributes"`
	Seed       string            `json:"seed"`
}

// Result describes assignment, not authorization to invoke a plugin.
type Result struct {
	Match     bool   `json:"match"`
	Bucket    uint16 `json:"bucket"`
	Candidate bool   `json:"candidate"`
}

type kind uint8

const (
	boolean kind = iota + 1
	text
	integer
)

type field struct {
	path string
	kind kind
}

type value struct {
	num  int64
	text string
}

// Program is immutable after Compile and safe for concurrent evaluation.
type Program struct {
	seed   [sha256.Size]byte
	fields []field
	nodes  []node // the last node is the root
}

// Compile accepts only v1. An empty or whitespace-only expression matches all.
// Paths contain dot-separated ASCII identifiers, [A-Za-z_][A-Za-z0-9_]*,
// with true and false reserved as whole paths. Predicates use &&, ||, !,
// parentheses, boolean literals, and boolean fields. A comparison has a field
// on the left and a literal of its declared type on the right. All types allow
// == and !=; only int allows <, <=, >, >=. Literals are true or false, a Go
// double-quoted string, or a signed decimal int64 with no leading zeroes.
func Compile(spec Spec) (*Program, error) {
	if spec.Version != 1 {
		return nil, errVersion
	}
	if len(spec.Seed) != hex.EncodedLen(sha256.Size) {
		return nil, errSeed
	}
	for i := range len(spec.Seed) {
		c := spec.Seed[i]
		if !digit(c) && (c < 'a' || c > 'f') {
			return nil, errSeed
		}
	}
	if len(spec.Expression) > maxExpression {
		return nil, errComplexity
	}
	if !utf8.ValidString(spec.Expression) {
		return nil, errPredicate
	}
	if len(spec.Attributes) > maxAttributes {
		return nil, errSchema
	}
	for path, decl := range spec.Attributes {
		if !validPath(path) || attributeKind(decl) == 0 {
			return nil, errSchema
		}
	}
	var seed [sha256.Size]byte
	if _, err := hex.Decode(seed[:], []byte(spec.Seed)); err != nil {
		return nil, errSeed
	}

	p := parser{src: strings.Clone(spec.Expression), schema: spec.Attributes}
	p.skipSpace()
	if p.pos == len(p.src) {
		p.add(node{op: opTrue})
	} else {
		p.parseOr(0)
		p.skipSpace()
		if p.err != nil {
			return nil, p.err
		}
		if p.pos != len(p.src) {
			return nil, errPredicate
		}
	}
	return &Program{seed: seed, fields: p.fields, nodes: p.nodes}, nil
}

// Evaluate validates every referenced field even if the predicate can
// short-circuit. Attribute lookups use exact, flat keys (e.g. "user.region").
// Unreferenced entries are ignored. Strings are bounded valid UTF-8; integers
// accept Go signed integer types and integer json.Number values, never floats.
// On invalid input it returns a zero Result and an error with no input data.
// A valid non-match still returns its bucket for preview and diagnostics.
func (p *Program) Evaluate(environment, plugin string, subject []byte, attrs map[string]any, basisPoints uint16) (Result, error) {
	if p == nil || len(p.nodes) == 0 {
		return Result{}, errProgram
	}
	if !validID(environment) || !validID(plugin) {
		return Result{}, errRoutingKey
	}
	if len(subject) == 0 || len(subject) > maxSubject {
		return Result{}, errSubject
	}
	if basisPoints > maxBasisPoints {
		return Result{}, errBasisPoints
	}
	if len(attrs) > maxAttributes {
		return Result{}, errContext
	}

	var values [maxAttributes]value
	for i, f := range p.fields {
		raw, ok := attrs[f.path]
		if !ok {
			return Result{}, errMissing
		}
		values[i], ok = f.kind.read(raw)
		if !ok {
			return Result{}, errAttribute
		}
	}
	match := p.matches(uint8(len(p.nodes)-1), &values)
	bucket, _ := bits.Mul64(bucketWord(environment, plugin, &p.seed, subject), maxBasisPoints)
	return Result{Match: match, Bucket: uint16(bucket), Candidate: match && bucket < uint64(basisPoints)}, nil
}

func (k kind) read(raw any) (value, bool) {
	switch k {
	case boolean:
		b, ok := raw.(bool)
		if b {
			return value{num: 1}, ok
		}
		return value{}, ok
	case text:
		s, ok := raw.(string)
		return value{text: s}, ok && validString(s)
	case integer:
		switch n := raw.(type) {
		case int:
			return value{num: int64(n)}, true
		case int8:
			return value{num: int64(n)}, true
		case int16:
			return value{num: int64(n)}, true
		case int32:
			return value{num: int64(n)}, true
		case int64:
			return value{num: n}, true
		case json.Number:
			i, ok := parseInt(string(n))
			return value{num: i}, ok
		}
	}
	return value{}, false
}

func validString(s string) bool { return len(s) <= maxString && utf8.ValidString(s) }

func validID(id string) bool {
	if len(id) == 0 || len(id) > maxIDBytes || id[0] == '-' {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if !digit(c) && (c < 'a' || c > 'z') && c != '-' {
			return false
		}
	}
	return true
}

func bucketWord(environment, plugin string, seed *[sha256.Size]byte, subject []byte) uint64 {
	// Only the bounded header is assembled; hash the raw subject directly.
	var header [5*4 + len(bucketDomain) + 2*maxIDBytes + sha256.Size]byte
	prefix := binary.BigEndian.AppendUint32(header[:0], uint32(len(bucketDomain)))
	prefix = append(prefix, bucketDomain...)
	prefix = binary.BigEndian.AppendUint32(prefix, uint32(len(environment)))
	prefix = append(prefix, environment...)
	prefix = binary.BigEndian.AppendUint32(prefix, uint32(len(plugin)))
	prefix = append(prefix, plugin...)
	prefix = binary.BigEndian.AppendUint32(prefix, uint32(len(seed)))
	prefix = append(prefix, seed[:]...)
	prefix = binary.BigEndian.AppendUint32(prefix, uint32(len(subject)))

	h := sha256.New()
	_, _ = h.Write(prefix)
	_, _ = h.Write(subject)
	var digest [sha256.Size]byte
	return binary.BigEndian.Uint64(h.Sum(digest[:0]))
}
