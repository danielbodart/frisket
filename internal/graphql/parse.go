// Package graphql names what a GraphQL request would do: which operation it
// is, and which fields are at that operation's root. It knows GraphQL, and
// nothing of any one API's schema.
//
// It is strict where the upstream's reader may not be. A document is read to
// the October 2021 grammar and no further, and anything two lexers could
// disagree about is refused rather than resolved: outside a string, only
// printable ASCII, space, tab, CRLF and LF -- no BOM, no U+2028, no NBSP, and
// no CR alone, which the spec ends a comment at and graphql-ruby, GitHub's
// reader, does not; in a comment, printable ASCII and tab; in a string, valid
// UTF-8 with no control character but tab, no escaped surrogate, and none of
// the draft spec's \u{...} escapes. Refused, a request is one frisket cannot
// classify, and its route's GraphQL rule says what happens to it.
package graphql

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Operation is one operation in a document: its type, its name, and the
// fields at its root, reached through fragment spreads and inline fragments,
// by name and never by alias, each once, in the order they first appear.
type Operation struct {
	// Type is query, mutation or subscription.
	Type string
	// Name is empty for an anonymous operation.
	Name   string
	Fields []string
}

// MaxDepth bounds nested selection sets, lists, objects and list types.
const MaxDepth = 64

type kind int

const (
	eof kind = iota
	punct
	name
	intValue
	floatValue
	stringValue
)

type token struct {
	kind kind
	text string // punctuator or name; raw for numbers; "" for strings
	pos  int
}

type lexer struct {
	src string
	pos int
}

func (l *lexer) errf(format string, a ...any) error {
	return fmt.Errorf("at %d: %s", l.pos, fmt.Sprintf(format, a...))
}

// next skips what the spec ignores -- space, tab, line terminators, commas and
// comments -- and returns the token after it.
func (l *lexer) next() (token, error) {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\r' && !strings.HasPrefix(l.src[l.pos:], "\r\n"):
			// A lone CR ends a line to the spec and not to graphql-ruby, which
			// reads a comment on past it: two readings of one document.
			return token{}, l.errf("a CR without an LF")
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			l.pos++
			continue
		case c == '#':
			// To the end of the line, printable ASCII and tab only: a comment
			// another lexer ended early would make code of the rest.
			for l.pos++; l.pos < len(l.src) && l.src[l.pos] != '\n' && l.src[l.pos] != '\r'; l.pos++ {
				if b := l.src[l.pos]; b != '\t' && (b < 0x20 || b > 0x7e) {
					return token{}, l.errf("byte %#x in a comment", b)
				}
			}
			continue
		}
		break
	}
	if l.pos >= len(l.src) {
		return token{kind: eof, pos: l.pos}, nil
	}
	start := l.pos
	c := l.src[l.pos]
	switch {
	case strings.IndexByte("!$&():=@[]{|}", c) >= 0:
		l.pos++
		return token{punct, string(c), start}, nil
	case c == '.':
		if strings.HasPrefix(l.src[l.pos:], "...") {
			l.pos += 3
			return token{punct, "...", start}, nil
		}
		return token{}, l.errf("a lone '.'")
	case isNameStart(c):
		for l.pos++; l.pos < len(l.src) && isNameContinue(l.src[l.pos]); l.pos++ {
		}
		return token{name, l.src[start:l.pos], start}, nil
	case c == '-' || isDigit(c):
		return l.number()
	case c == '"':
		if strings.HasPrefix(l.src[l.pos:], `"""`) {
			return l.blockString()
		}
		return l.string()
	}
	return token{}, l.errf("byte %#x", c)
}

func (l *lexer) number() (token, error) {
	start := l.pos
	if l.src[l.pos] == '-' {
		l.pos++
	}
	switch {
	case l.pos < len(l.src) && l.src[l.pos] == '0':
		l.pos++
		if l.pos < len(l.src) && isDigit(l.src[l.pos]) {
			return token{}, l.errf("a leading zero")
		}
	case l.pos < len(l.src) && isDigit(l.src[l.pos]):
		l.digits()
	default:
		return token{}, l.errf("a '-' that is not a number")
	}
	k := intValue
	if l.pos < len(l.src) && l.src[l.pos] == '.' {
		l.pos++
		if l.digits() == 0 {
			return token{}, l.errf("a fraction with no digits")
		}
		k = floatValue
	}
	if l.pos < len(l.src) && (l.src[l.pos] == 'e' || l.src[l.pos] == 'E') {
		l.pos++
		if l.pos < len(l.src) && (l.src[l.pos] == '+' || l.src[l.pos] == '-') {
			l.pos++
		}
		if l.digits() == 0 {
			return token{}, l.errf("an exponent with no digits")
		}
		k = floatValue
	}
	// The spec's lookahead: a number is never followed by '.', a digit or a
	// name, so "1.2.3" and "0x1" are errors rather than two tokens.
	if l.pos < len(l.src) && (l.src[l.pos] == '.' || isNameStart(l.src[l.pos])) {
		return token{}, l.errf("a number running into %q", l.src[l.pos])
	}
	return token{k, l.src[start:l.pos], start}, nil
}

func (l *lexer) digits() int {
	n := 0
	for ; l.pos < len(l.src) && isDigit(l.src[l.pos]); l.pos++ {
		n++
	}
	return n
}

func (l *lexer) string() (token, error) {
	start := l.pos
	for l.pos++; l.pos < len(l.src); {
		c := l.src[l.pos]
		switch {
		case c == '"':
			l.pos++
			return token{stringValue, "", start}, nil
		case c == '\\':
			if l.pos+1 >= len(l.src) {
				return token{}, l.errf("an unfinished escape")
			}
			e := l.src[l.pos+1]
			if strings.IndexByte(`"\/bfnrt`, e) >= 0 {
				l.pos += 2
				continue
			}
			if e != 'u' || l.pos+6 > len(l.src) {
				return token{}, l.errf("escape \\%c", e)
			}
			var r rune
			for _, h := range l.src[l.pos+2 : l.pos+6] {
				d := hexVal(byte(h))
				if d < 0 {
					return token{}, l.errf("escape \\u%s", l.src[l.pos+2:l.pos+6])
				}
				r = r<<4 | rune(d)
			}
			if r >= 0xd800 && r <= 0xdfff {
				return token{}, l.errf("an escaped surrogate")
			}
			l.pos += 6
		case c < 0x20 && c != '\t':
			return token{}, l.errf("control byte %#x in a string", c)
		case c < 0x80:
			l.pos++
		default:
			r, n := utf8.DecodeRuneInString(l.src[l.pos:])
			if r == utf8.RuneError {
				return token{}, l.errf("invalid UTF-8 in a string")
			}
			l.pos += n
		}
	}
	return token{}, l.errf("an unterminated string")
}

func (l *lexer) blockString() (token, error) {
	start := l.pos
	for l.pos += 3; l.pos < len(l.src); {
		switch {
		case strings.HasPrefix(l.src[l.pos:], `\"""`):
			l.pos += 4
		case strings.HasPrefix(l.src[l.pos:], `"""`):
			l.pos += 3
			return token{stringValue, "", start}, nil
		default:
			c := l.src[l.pos]
			if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
				return token{}, l.errf("control byte %#x in a block string", c)
			}
			r, n := utf8.DecodeRuneInString(l.src[l.pos:])
			if r == utf8.RuneError {
				return token{}, l.errf("invalid UTF-8 in a block string")
			}
			l.pos += n
		}
	}
	return token{}, l.errf("an unterminated block string")
}

func isNameStart(c byte) bool    { return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isNameContinue(c byte) bool { return isNameStart(c) || isDigit(c) }
func isDigit(c byte) bool        { return c >= '0' && c <= '9' }

func hexVal(c byte) int {
	switch {
	case isDigit(c):
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// selection is one entry of a selection set, kept only as far as a root
// needs: a field's name, a spread's fragment, an inline fragment's set.
type selection struct {
	field  string
	spread string
	inline []selection
}

type parser struct {
	lex   lexer
	tok   token
	depth int
}

func (p *parser) advance() error {
	t, err := p.lex.next()
	p.tok = t
	return err
}

func (p *parser) is(text string) bool {
	return p.tok.kind == punct && p.tok.text == text
}

func (p *parser) keyword(text string) bool {
	return p.tok.kind == name && p.tok.text == text
}

func (p *parser) expect(text string) error {
	if !p.is(text) {
		return p.unexpected(text)
	}
	return p.advance()
}

func (p *parser) unexpected(want string) error {
	got := p.tok.text
	switch p.tok.kind {
	case eof:
		got = "the end"
	case stringValue:
		got = "a string"
	}
	return fmt.Errorf("at %d: %s where %s belongs", p.tok.pos, got, want)
}

func (p *parser) name() (string, error) {
	if p.tok.kind != name {
		return "", p.unexpected("a name")
	}
	s := p.tok.text
	return s, p.advance()
}

func (p *parser) enter() error {
	if p.depth++; p.depth > MaxDepth {
		return errors.New("nested too deeply")
	}
	return nil
}

func (p *parser) leave() { p.depth-- }

// Parse reads an executable document and names its operations.
func Parse(doc string) ([]Operation, error) {
	p := &parser{lex: lexer{src: doc}}
	if err := p.advance(); err != nil {
		return nil, err
	}
	type op struct {
		Operation
		root []selection
	}
	var ops []op
	fragments := map[string][]selection{}
	opNames := map[string]bool{}
	anonymous := false
	for p.tok.kind != eof {
		switch {
		case p.is("{"):
			set, err := p.selectionSet()
			if err != nil {
				return nil, err
			}
			ops = append(ops, op{Operation: Operation{Type: "query"}, root: set})
			anonymous = true
		case p.keyword("query"), p.keyword("mutation"), p.keyword("subscription"):
			o := op{Operation: Operation{Type: p.tok.text}}
			if err := p.advance(); err != nil {
				return nil, err
			}
			if p.tok.kind == name {
				o.Name = p.tok.text
				if opNames[o.Name] {
					return nil, fmt.Errorf("two operations named %s", o.Name)
				}
				opNames[o.Name] = true
				if err := p.advance(); err != nil {
					return nil, err
				}
			} else {
				anonymous = true
			}
			if p.is("(") {
				if err := p.variableDefinitions(); err != nil {
					return nil, err
				}
			}
			if err := p.directives(false); err != nil {
				return nil, err
			}
			set, err := p.selectionSet()
			if err != nil {
				return nil, err
			}
			o.root = set
			ops = append(ops, o)
		case p.keyword("fragment"):
			if err := p.advance(); err != nil {
				return nil, err
			}
			n, err := p.fragmentName()
			if err != nil {
				return nil, err
			}
			if _, ok := fragments[n]; ok {
				return nil, fmt.Errorf("two fragments named %s", n)
			}
			if !p.keyword("on") {
				return nil, p.unexpected("on")
			}
			if err := p.advance(); err != nil {
				return nil, err
			}
			if _, err := p.name(); err != nil {
				return nil, err
			}
			if err := p.directives(false); err != nil {
				return nil, err
			}
			set, err := p.selectionSet()
			if err != nil {
				return nil, err
			}
			fragments[n] = set
		default:
			return nil, p.unexpected("an operation or a fragment")
		}
	}
	if len(ops) == 0 {
		return nil, errors.New("no operation")
	}
	if anonymous && len(ops) > 1 {
		return nil, errors.New("an anonymous operation among others")
	}
	out := make([]Operation, len(ops))
	r := &roots{fragments: fragments}
	for i, o := range ops {
		fields, err := r.of(o.root)
		if err != nil {
			return nil, err
		}
		o.Fields = fields
		out[i] = o.Operation
	}
	return out, nil
}

// maxFollowed bounds the selections followed to find the fields at every
// operation's root, together.
const maxFollowed = 1 << 14

// roots finds the fields at an operation's root: each once, in the order they
// first appear, through inline fragments and fragment spreads, and through
// each fragment once. Followed once per path to it, a chain of fragments each
// spreading the next twice would name 2^n fields in a document of n lines --
// a million in under a kilobyte.
type roots struct {
	fragments map[string][]selection
	followed  int
	fields    []string
	seen      map[string]bool
	// visited are the fragments already followed from this root, and
	// spreading those being followed now: a spread of one of those is a
	// cycle, which the spec forbids and a server refuses.
	visited, spreading map[string]bool
}

func (r *roots) of(set []selection) ([]string, error) {
	r.fields, r.seen = nil, map[string]bool{}
	r.visited, r.spreading = map[string]bool{}, map[string]bool{}
	if err := r.walk(set); err != nil {
		return nil, err
	}
	return r.fields, nil
}

func (r *roots) walk(set []selection) error {
	for _, s := range set {
		if r.followed++; r.followed > maxFollowed {
			return errors.New("too many selections to follow")
		}
		switch {
		case s.field != "":
			if !r.seen[s.field] {
				r.seen[s.field] = true
				r.fields = append(r.fields, s.field)
			}
		case s.spread != "":
			if r.spreading[s.spread] {
				return fmt.Errorf("fragment %s spreads itself", s.spread)
			}
			if r.visited[s.spread] {
				continue
			}
			f, ok := r.fragments[s.spread]
			if !ok {
				return fmt.Errorf("no fragment %s", s.spread)
			}
			r.visited[s.spread], r.spreading[s.spread] = true, true
			if err := r.walk(f); err != nil {
				return err
			}
			delete(r.spreading, s.spread)
		default:
			if err := r.walk(s.inline); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *parser) fragmentName() (string, error) {
	if p.keyword("on") {
		return "", p.unexpected("a fragment name")
	}
	return p.name()
}

func (p *parser) selectionSet() ([]selection, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	if err := p.expect("{"); err != nil {
		return nil, err
	}
	var set []selection
	for {
		var s selection
		switch {
		case p.is("..."):
			if err := p.advance(); err != nil {
				return nil, err
			}
			if p.tok.kind == name && !p.keyword("on") {
				s.spread = p.tok.text
				if err := p.advance(); err != nil {
					return nil, err
				}
				if err := p.directives(false); err != nil {
					return nil, err
				}
				break
			}
			if p.keyword("on") {
				if err := p.advance(); err != nil {
					return nil, err
				}
				if _, err := p.name(); err != nil {
					return nil, err
				}
			}
			if err := p.directives(false); err != nil {
				return nil, err
			}
			inner, err := p.selectionSet()
			if err != nil {
				return nil, err
			}
			s.inline = inner
		case p.tok.kind == name:
			n := p.tok.text
			if err := p.advance(); err != nil {
				return nil, err
			}
			if p.is(":") {
				if err := p.advance(); err != nil {
					return nil, err
				}
				var err error
				if n, err = p.name(); err != nil {
					return nil, err
				}
			}
			s.field = n
			if p.is("(") {
				if err := p.arguments(false); err != nil {
					return nil, err
				}
			}
			if err := p.directives(false); err != nil {
				return nil, err
			}
			if p.is("{") {
				if _, err := p.selectionSet(); err != nil {
					return nil, err
				}
			}
		default:
			return nil, p.unexpected("a field or a fragment")
		}
		set = append(set, s)
		if p.is("}") {
			return set, p.advance()
		}
	}
}

func (p *parser) arguments(constant bool) error {
	if err := p.expect("("); err != nil {
		return err
	}
	seen := map[string]bool{}
	for {
		n, err := p.name()
		if err != nil {
			return err
		}
		if seen[n] {
			return fmt.Errorf("argument %s twice", n)
		}
		seen[n] = true
		if err := p.expect(":"); err != nil {
			return err
		}
		if err := p.value(constant); err != nil {
			return err
		}
		if p.is(")") {
			return p.advance()
		}
	}
}

func (p *parser) directives(constant bool) error {
	for p.is("@") {
		if err := p.advance(); err != nil {
			return err
		}
		if _, err := p.name(); err != nil {
			return err
		}
		if p.is("(") {
			if err := p.arguments(constant); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *parser) variableDefinitions() error {
	if err := p.expect("("); err != nil {
		return err
	}
	for {
		if err := p.expect("$"); err != nil {
			return err
		}
		if _, err := p.name(); err != nil {
			return err
		}
		if err := p.expect(":"); err != nil {
			return err
		}
		if err := p.typeRef(); err != nil {
			return err
		}
		if p.is("=") {
			if err := p.advance(); err != nil {
				return err
			}
			if err := p.value(true); err != nil {
				return err
			}
		}
		if err := p.directives(true); err != nil {
			return err
		}
		if p.is(")") {
			return p.advance()
		}
	}
}

func (p *parser) typeRef() error {
	if err := p.enter(); err != nil {
		return err
	}
	defer p.leave()
	if p.is("[") {
		if err := p.advance(); err != nil {
			return err
		}
		if err := p.typeRef(); err != nil {
			return err
		}
		if err := p.expect("]"); err != nil {
			return err
		}
	} else if _, err := p.name(); err != nil {
		return err
	}
	if p.is("!") {
		return p.advance()
	}
	return nil
}

func (p *parser) value(constant bool) error {
	if err := p.enter(); err != nil {
		return err
	}
	defer p.leave()
	switch {
	case p.is("$") && !constant:
		if err := p.advance(); err != nil {
			return err
		}
		_, err := p.name()
		return err
	case p.tok.kind == intValue, p.tok.kind == floatValue, p.tok.kind == stringValue, p.tok.kind == name:
		return p.advance()
	case p.is("["):
		if err := p.advance(); err != nil {
			return err
		}
		for !p.is("]") {
			if err := p.value(constant); err != nil {
				return err
			}
		}
		return p.advance()
	case p.is("{"):
		if err := p.advance(); err != nil {
			return err
		}
		seen := map[string]bool{}
		for !p.is("}") {
			n, err := p.name()
			if err != nil {
				return err
			}
			if seen[n] {
				return fmt.Errorf("object field %s twice", n)
			}
			seen[n] = true
			if err := p.expect(":"); err != nil {
				return err
			}
			if err := p.value(constant); err != nil {
				return err
			}
		}
		return p.advance()
	}
	return p.unexpected("a value")
}
