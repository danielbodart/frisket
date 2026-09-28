package intercept

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielbodart/frisket/internal/dns"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// SessionKey is the public half of a key made for the session, which the
// sandbox's clients sign with. A JWT-bearer grant it signed, posted to one of
// Grants, is answered here with the route's placeholder, and a bearer JWT it
// signed is the placeholder (PLAN.md, decision 13).
type SessionKey struct {
	Key *rsa.PublicKey
	// Issuer is the iss every JWT it signs must carry, and the only sub one
	// may: the service account the session is.
	Issuer string
	// Grants are the token URLs answered here, each a host and a path:
	// "oauth2.googleapis.com/token". Every host is one this route serves.
	Grants []string
}

const (
	jwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	jwtSkew   = 5 * time.Minute
	// A client's own JWT lives an hour, and is re-signed before it ends.
	jwtMaxLife = time.Hour + jwtSkew
	// grantExpiresIn is what an answered grant says: Google's own.
	grantExpiresIn = 3599
	maxGrantBody   = 64 << 10
	maxVerified    = 4096
	minKeyBits     = 2048
)

// A JWT the session key signed whose claims are not the session's. Fixed
// text: a reason is logged and sent back, and never quotes the token.
var (
	errNotOurs      = errors.New("not signed by the session key")
	errClaims       = errors.New("session key JWT: claims are not a JWT's")
	errIssuer       = errors.New("session key JWT: issuer is not the session's")
	errSubject      = errors.New("session key JWT: subject is not the session's")
	errExpired      = errors.New("session key JWT: expired")
	errLifetime     = errors.New("session key JWT: issued in the future, or lives longer than an hour")
	errAudience     = errors.New("session key JWT: audience is not this host")
	errNoAudience   = errors.New("session key JWT: neither an audience nor a scope")
	errGrantAud     = errors.New("session key JWT: audience is not a token URL")
	errGrantMethod  = errors.New("grant: not a POST")
	errGrantForm    = errors.New("grant: not one form of one grant_type and one assertion")
	errGrantType    = errors.New("grant: grant_type is not jwt-bearer")
	errGrantUnsound = errors.New("grant: assertion not signed by the session key")
)

// ParsePublicKey reads a PEM "PUBLIC KEY", RSA, of 2048 bits or more.
func ParsePublicKey(text string) (*rsa.PublicKey, error) {
	b, rest := pem.Decode([]byte(text))
	if b == nil || b.Type != "PUBLIC KEY" {
		return nil, errors.New("session key: not a PEM PUBLIC KEY")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("session key: data after the key")
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("session key: %w", err)
	}
	rk, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("session key: %T, not RSA", k)
	}
	if rk.N.BitLen() < minKeyBits {
		return nil, fmt.Errorf("session key: %d bits, fewer than %d", rk.N.BitLen(), minKeyBits)
	}
	return rk, nil
}

type sessionKey struct {
	SessionKey
	grants map[string]bool
	auds   map[string]bool

	mu   sync.Mutex
	seen map[[sha256.Size]byte]verified
}

type verified struct {
	exp   time.Time
	aud   jwt.Audience
	scope bool
}

type claims struct {
	jwt.Claims
	Scope          string `json:"scope,omitempty"`
	TargetAudience string `json:"target_audience,omitempty"`
}

func compileSessionKey(k *SessionKey, route string, serves func(string) bool) (*sessionKey, error) {
	if k.Key == nil || k.Key.N.BitLen() < minKeyBits {
		return nil, fmt.Errorf("route %s: session key: an RSA key of %d bits or more", route, minKeyBits)
	}
	if k.Issuer == "" || strings.ContainsAny(k.Issuer, " \t\r\n") {
		return nil, fmt.Errorf("route %s: session key: an issuer is required, one word", route)
	}
	c := &sessionKey{SessionKey: *k, grants: map[string]bool{}, auds: map[string]bool{}, seen: map[[sha256.Size]byte]verified{}}
	for _, g := range k.Grants {
		host, path, ok := strings.Cut(g, "/")
		if !ok || host != dns.Normalize(host) || !dns.ValidQueryName(host) || strings.ContainsAny(path, "?#") {
			return nil, fmt.Errorf("route %s: session key grant %q: host/path", route, g)
		}
		if !serves(host) {
			return nil, fmt.Errorf("route %s: session key grant %q: %s is not this route's", route, g, host)
		}
		c.grants[g] = true
		c.auds["https://"+g] = true
	}
	return c, nil
}

// verify checks tok is RS256 and signed by the key, whatever its header
// says, and then that it is the session's and in date. errNotOurs is a token
// the key did not sign; any other error is one it did.
func (k *sessionKey) verify(tok string, now time.Time) (claims, error) {
	var c claims
	sig, err := jose.ParseSignedCompact(tok, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return c, errNotOurs
	}
	payload, err := sig.Verify(k.Key)
	if err != nil {
		return c, errNotOurs
	}
	if json.Unmarshal(payload, &c) != nil {
		return c, errClaims
	}
	switch {
	case c.Issuer != k.Issuer:
		return c, errIssuer
	case c.Subject != "" && c.Subject != k.Issuer:
		return c, errSubject
	case c.Expiry == nil || c.IssuedAt == nil:
		return c, errLifetime
	case !now.Before(c.Expiry.Time()):
		return c, errExpired
	case c.IssuedAt.Time().After(now.Add(jwtSkew)) || c.Expiry.Time().Sub(c.IssuedAt.Time()) > jwtMaxLife:
		return c, errLifetime
	case c.NotBefore != nil && c.NotBefore.Time().After(now.Add(jwtSkew)):
		return c, errLifetime
	}
	return c, nil
}

// bearer is whether tok, sent to host, is a JWT the key signed, and if it
// is, why it is not the placeholder: "" when it is. A token is verified once
// and remembered until it expires; its audience is checked every time.
func (k *sessionKey) bearer(tok, host string, now time.Time) (bool, string) {
	sum := sha256.Sum256([]byte(tok))
	k.mu.Lock()
	v, ok := k.seen[sum]
	k.mu.Unlock()
	if !ok || !now.Before(v.exp) {
		c, err := k.verify(tok, now)
		if errors.Is(err, errNotOurs) {
			return false, ""
		}
		if err != nil {
			return true, err.Error()
		}
		v = verified{exp: c.Expiry.Time(), aud: c.Audience, scope: c.Scope != ""}
		k.remember(sum, v, now)
	}
	switch {
	case len(v.aud) == 0 && v.scope:
		return true, ""
	case len(v.aud) == 0:
		return true, errNoAudience.Error()
	case len(v.aud) == 1 && v.aud[0] == "https://"+host+"/":
		return true, ""
	}
	return true, errAudience.Error()
}

func (k *sessionKey) remember(sum [sha256.Size]byte, v verified, now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.seen) >= maxVerified {
		for s, e := range k.seen {
			if !now.Before(e.exp) || len(k.seen) >= maxVerified {
				delete(k.seen, s)
			}
		}
	}
	k.seen[sum] = v
}

func (k *sessionKey) cached() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.seen)
}

// answer is a request to one of the grant URLs, answered here and never sent
// on: the placeholder for an assertion the key signed, or an ID token signed
// by nobody for one asking for target_audience. It returns why it refused.
func (k *sessionKey) answer(w http.ResponseWriter, r *http.Request, placeholder string, now time.Time) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fail := func(code string, err error) error {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "frisket: " + err.Error()})
		return err
	}
	if r.Method != http.MethodPost {
		return fail("invalid_request", errGrantMethod)
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxGrantBody)
	if err := r.ParseForm(); err != nil || len(r.PostForm["grant_type"]) != 1 || len(r.PostForm["assertion"]) > 1 {
		return fail("invalid_request", errGrantForm)
	}
	if r.PostForm.Get("grant_type") != jwtBearer {
		return fail("unsupported_grant_type", errGrantType)
	}
	c, err := k.verify(r.PostForm.Get("assertion"), now)
	switch {
	case errors.Is(err, errNotOurs):
		err = errGrantUnsound
	case err == nil && (len(c.Audience) != 1 || !k.auds[c.Audience[0]]):
		err = errGrantAud
	}
	if err != nil {
		return fail("invalid_grant", err)
	}
	if c.TargetAudience != "" {
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": k.idToken(c.TargetAudience, now)})
		return nil
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": placeholder,
		"expires_in":   grantExpiresIn,
		"token_type":   "Bearer",
	})
	return nil
}

// idToken is shaped like Google's, so a client can read its audience and
// expiry, and signed by nobody.
func (k *sessionKey) idToken(aud string, now time.Time) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	iat := now.Unix()
	return enc(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "frisket-placeholder"}) + "." +
		enc(map[string]any{
			"iss": "https://accounts.google.com", "aud": aud, "azp": k.Issuer, "sub": k.Issuer,
			"email": k.Issuer, "email_verified": true, "iat": iat, "exp": iat + grantExpiresIn + 1,
		}) + "." + base64.RawURLEncoding.EncodeToString([]byte("signed by nobody"))
}
