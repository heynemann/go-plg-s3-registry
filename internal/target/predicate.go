package target

import (
	"strconv"
	"strings"
)

type opcode uint8

const (
	opFalse opcode = iota
	opTrue
	opNot
	opAnd
	opOr
	opEq
	opNe
	opLT
	opLE
	opGT
	opGE
)

type node struct {
	op          opcode
	left, right uint8
	field       uint8
	literal     value
}

func (p *Program) matches(index uint8, values *[maxAttributes]value) bool {
	n := &p.nodes[index]
	switch n.op {
	case opTrue:
		return true
	case opNot:
		return !p.matches(n.left, values)
	case opAnd:
		return p.matches(n.left, values) && p.matches(n.right, values)
	case opOr:
		return p.matches(n.left, values) || p.matches(n.right, values)
	case opEq:
		return values[n.field] == n.literal
	case opNe:
		return values[n.field] != n.literal
	case opLT:
		return values[n.field].num < n.literal.num
	case opLE:
		return values[n.field].num <= n.literal.num
	case opGT:
		return values[n.field].num > n.literal.num
	case opGE:
		return values[n.field].num >= n.literal.num
	default: // opFalse
		return false
	}
}

type parser struct {
	src    string
	pos    int
	schema map[string]string
	fields []field
	nodes  []node
	err    error
}

// or := and { "||" and }; and := unary { "&&" unary }.
func (p *parser) parseOr(depth int) uint8 {
	left := p.parseAnd(depth)
	for p.err == nil && p.take("||") {
		right := p.parseAnd(depth)
		left = p.add(node{op: opOr, left: left, right: right})
	}
	return left
}

func (p *parser) parseAnd(depth int) uint8 {
	left := p.parseUnary(depth)
	for p.err == nil && p.take("&&") {
		right := p.parseUnary(depth)
		left = p.add(node{op: opAnd, left: left, right: right})
	}
	return left
}

// unary := "!" unary | "(" or ")" | bool | field [ comparison literal ].
func (p *parser) parseUnary(depth int) uint8 {
	if depth > maxDepth {
		p.err = errComplexity
		return 0
	}
	if p.take("!") {
		return p.add(node{op: opNot, left: p.parseUnary(depth + 1)})
	}
	if p.take("(") {
		i := p.parseOr(depth + 1)
		if p.err == nil && !p.take(")") {
			p.err = errPredicate
		}
		return i
	}
	path := p.word()
	switch path {
	case "true":
		return p.add(node{op: opTrue})
	case "false":
		return p.add(node{op: opFalse})
	}
	k := attributeKind(p.schema[path])
	if k == 0 {
		p.err = errPredicate
		return 0
	}
	op := p.comparison()
	if op != opFalse {
		if op >= opLT && k != integer {
			p.err = errPredicate
			return 0
		}
		literal := p.readLiteral(k)
		return p.add(node{op: op, field: p.useField(path, k), literal: literal})
	}
	if k != boolean {
		p.err = errPredicate
		return 0
	}
	return p.add(node{op: opEq, field: p.useField(path, k), literal: value{num: 1}})
}

func (p *parser) comparison() opcode {
	switch {
	case p.take("=="):
		return opEq
	case p.take("!="):
		return opNe
	case p.take("<="):
		return opLE
	case p.take(">="):
		return opGE
	case p.take("<"):
		return opLT
	case p.take(">"):
		return opGT
	default:
		return opFalse
	}
}

func (p *parser) readLiteral(k kind) value {
	p.skipSpace()
	switch k {
	case boolean:
		switch p.word() {
		case "true":
			return value{num: 1}
		case "false":
			return value{}
		}
	case integer:
		start := p.pos
		if p.pos < len(p.src) && p.src[p.pos] == '-' {
			p.pos++
		}
		for p.pos < len(p.src) && digit(p.src[p.pos]) {
			p.pos++
		}
		if n, ok := parseInt(p.src[start:p.pos]); ok {
			return value{num: n}
		}
	case text:
		if s, ok := p.quoted(); ok {
			return value{text: s}
		}
	}
	p.err = errPredicate
	return value{}
}

func (p *parser) quoted() (string, bool) {
	if p.pos == len(p.src) || p.src[p.pos] != '"' {
		return "", false
	}
	start := p.pos
	p.pos++
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		p.pos++
		switch c {
		case '\\':
			if p.pos < len(p.src) {
				p.pos++
			}
		case '"':
			s, err := strconv.Unquote(p.src[start:p.pos])
			return s, err == nil && validString(s)
		}
	}
	return "", false
}

func (p *parser) add(n node) uint8 {
	if p.err != nil {
		return 0
	}
	if len(p.nodes) >= maxNodes {
		p.err = errComplexity
		return 0
	}
	p.nodes = append(p.nodes, n)
	return uint8(len(p.nodes) - 1)
}

func (p *parser) useField(path string, k kind) uint8 {
	for i, f := range p.fields {
		if f.path == path {
			return uint8(i)
		}
	}
	p.fields = append(p.fields, field{path: path, kind: k})
	return uint8(len(p.fields) - 1)
}

func (p *parser) take(token string) bool {
	p.skipSpace()
	if !strings.HasPrefix(p.src[p.pos:], token) {
		return false
	}
	p.pos += len(token)
	return true
}

func (p *parser) word() string {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if !identStart(c) && !digit(c) && c != '.' {
			break
		}
		p.pos++
	}
	return p.src[start:p.pos]
}

func (p *parser) skipSpace() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}

func attributeKind(s string) kind {
	switch s {
	case "bool":
		return boolean
	case "string":
		return text
	case "int":
		return integer
	default:
		return 0
	}
}

func validPath(s string) bool {
	if len(s) == 0 || len(s) > maxPath || s == "true" || s == "false" {
		return false
	}
	start := true
	for i := range len(s) {
		c := s[i]
		switch {
		case start:
			if !identStart(c) {
				return false
			}
			start = false
		case c == '.':
			start = true
		case !identStart(c) && !digit(c):
			return false
		}
	}
	return !start
}

func identStart(c byte) bool {
	return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func digit(c byte) bool { return c >= '0' && c <= '9' }

func parseInt(s string) (int64, bool) {
	if len(s) == 0 || len(s) > 20 {
		return 0, false
	}
	limit := uint64(1<<63 - 1)
	negative := s[0] == '-'
	digits := s
	if negative {
		digits = s[1:]
		limit++
	}
	if len(digits) == 0 || len(digits) > 1 && digits[0] == '0' {
		return 0, false
	}
	var n uint64
	for i := range len(digits) {
		d := uint64(digits[i] - '0')
		if d > 9 || n > (limit-d)/10 {
			return 0, false
		}
		n = n*10 + d
	}
	if negative {
		// Unsigned subtraction lets MinInt64 be represented as well.
		return int64(-n), true
	}
	return int64(n), true
}
