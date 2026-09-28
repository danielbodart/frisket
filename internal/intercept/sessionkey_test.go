package intercept

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/credential"
	"github.com/go-jose/go-jose/v4"
	"pgregory.net/rapid"
)

const (
	issuer    = "sa@project.iam.gserviceaccount.test"
	apiName   = "storage.gapi.test"
	tokenURL  = "https://oauth2.gapi.test/token"
	legacyURL = "https://www.gapi.test/oauth2/v4/token"
)

var testKeys = sync.OnceValue(func() [2]*rsa.PrivateKey {
	var out [2]*rsa.PrivateKey
	for i := range out {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		out[i] = k
	}
	return out
})

func sessionPriv() *rsa.PrivateKey { return testKeys()[0] }
func otherPriv() *rsa.PrivateKey   { return testKeys()[1] }

// sign is a JWT as a Google client makes one, by whatever key and algorithm.
func sign(t testing.TB, alg jose.SignatureAlgorithm, key any, claims map[string]any) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := s.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// claimsAt are a self-signed JWT's claims, as Python's clients send them,
// issued at now.
func claimsAt(now time.Time, aud string) map[string]any {
	c := map[string]any{"iss": issuer, "sub": issuer, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	if aud != "" {
		c["aud"] = aud
	}
	return c
}

func with(c map[string]any, kv ...any) map[string]any {
	out := map[string]any{}
	for k, v := range c {
		out[k] = v
	}
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(out, kv[i].(string))
			continue
		}
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}

func unsigned(header, claims map[string]any) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(header) + "." + enc(claims) + "."
}

func publicPEM(t testing.TB, k *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func testSessionKey() *SessionKey {
	return &SessionKey{Key: &sessionPriv().PublicKey, Issuer: issuer, Grants: []string{"oauth2.gapi.test/token", "www.gapi.test/oauth2/v4/token"}}
}

// gapiRoute is Google's shape: every name below a suffix, the service
// account's token, and the session's key. Its scope admits GETs under /v1
// and nothing at the token URLs.
func gapiRoute(up *namedUpstream, cred credential.Source) Route {
	return Route{
		Name: "gapi", Host: "*.gapi.test", Upstream: "https://*.gapi.test", UpstreamCAs: up.pool(),
		Credential: cred, Inject: Bearer(), Placeholder: placeholder, SessionKey: testSessionKey(),
		Scope: Scope{Paths: []PathRule{{Methods: []string{"GET"}, Prefix: "/v1"}}},
	}
}

func servesGAPI(name string) bool { return strings.HasSuffix(name, ".gapi.test") }

func newGAPIFixture(t *testing.T) (*fixture, *namedUpstream, *journal) {
	t.Helper()
	j := &journal{}
	up := newNamedUpstream(t, "gapi.test")
	cred, _ := tokenFile(t, j, realToken)
	return newNamedFixture(t, j, up, gapiRoute(up, cred)), up, j
}

// A BEARER JWT THE SESSION KEY SIGNED, FOR THIS HOST, IS THE PLACEHOLDER
// (decision 13's second form). One any other key signed, or signed by any
// algorithm but RS256 -- whatever key its header names or implies -- is the
// client's own, and goes on untouched. One the session key signed whose
// claims are not the session's is refused here, and never sent.
func TestABearerJWTTheSessionKeySignedIsThePlaceholder(t *testing.T) {
	f, up, j := newGAPIFixture(t)
	c := f.client(t, true)
	now := time.Now()
	own := claimsAt(now, "https://"+apiName+"/")
	pubDER, err := x509.MarshalPKIXPublicKey(&sessionPriv().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	hmacKey := []byte(publicPEM(t, &sessionPriv().PublicKey))

	const passed, refused = "passed", "refused"
	for _, tc := range []struct {
		name, tok, want string
	}{
		{"its audience this host", sign(t, jose.RS256, sessionPriv(), own), CredentialInjected},
		{"a scope and no audience", sign(t, jose.RS256, sessionPriv(), with(own, "aud", nil, "scope", "https://www.googleapis.com/auth/cloud-platform")), CredentialInjected},
		{"no subject", sign(t, jose.RS256, sessionPriv(), with(own, "sub", nil)), CredentialInjected},

		{"another key", sign(t, jose.RS256, otherPriv(), own), passed},
		{"HS256 keyed by the public key's PEM", sign(t, jose.HS256, hmacKey, own), passed},
		{"HS256 keyed by the public key's DER", sign(t, jose.HS256, pubDER, own), passed},
		{"alg none", unsigned(map[string]any{"alg": "none", "typ": "JWT"}, own), passed},
		{"PS256 by the session key", sign(t, jose.PS256, sessionPriv(), own), passed},
		{"RS512 by the session key", sign(t, jose.RS512, sessionPriv(), own), passed},
		{"not a JWT", "ya29.a0AfB_byC-not-ours", passed},
		{"a JWT with its signature cut", strings.TrimRight(sign(t, jose.RS256, sessionPriv(), own), "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"), passed},

		{"another issuer", sign(t, jose.RS256, sessionPriv(), with(own, "iss", "evil@x.test")), refused},
		{"another subject", sign(t, jose.RS256, sessionPriv(), with(own, "sub", "person@x.test")), refused},
		{"expired", sign(t, jose.RS256, sessionPriv(), with(own, "iat", now.Add(-2*time.Hour).Unix(), "exp", now.Add(-time.Hour).Unix())), refused},
		{"living a day", sign(t, jose.RS256, sessionPriv(), with(own, "exp", now.Add(24*time.Hour).Unix())), refused},
		{"issued an hour ahead", sign(t, jose.RS256, sessionPriv(), with(own, "iat", now.Add(time.Hour).Unix(), "exp", now.Add(90*time.Minute).Unix())), refused},
		{"no iat", sign(t, jose.RS256, sessionPriv(), with(own, "iat", nil)), refused},
		{"no exp", sign(t, jose.RS256, sessionPriv(), with(own, "exp", nil)), refused},
		{"not yet valid", sign(t, jose.RS256, sessionPriv(), with(own, "nbf", now.Add(30*time.Minute).Unix())), refused},
		{"another host the route serves as its audience", sign(t, jose.RS256, sessionPriv(), with(own, "aud", "https://pubsub.gapi.test/")), CredentialInjected},

		{"a host the route does not serve as its audience", sign(t, jose.RS256, sessionPriv(), with(own, "aud", "https://elsewhere.test/")), refused},
		{"the route's suffix as its audience", sign(t, jose.RS256, sessionPriv(), with(own, "aud", "https://gapi.test/")), refused},
		{"an http audience", sign(t, jose.RS256, sessionPriv(), with(own, "aud", "http://"+apiName+"/")), refused},
		{"this host's audience with a path", sign(t, jose.RS256, sessionPriv(), with(own, "aud", "https://"+apiName+"/v1")), refused},
		{"two audiences", sign(t, jose.RS256, sessionPriv(), with(own, "aud", []string{"https://" + apiName + "/", "https://x.test/"})), refused},
		{"the token URL's audience", sign(t, jose.RS256, sessionPriv(), with(own, "aud", tokenURL)), refused},
		{"neither audience nor scope", sign(t, jose.RS256, sessionPriv(), with(own, "aud", nil)), refused},
		{"a scope that is not a string", sign(t, jose.RS256, sessionPriv(), with(own, "aud", nil, "scope", []string{"x"})), refused},
		{"claims that are not an object", sign(t, jose.RS256, sessionPriv(), nil), refused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(up.requests())
			lines := len(j.lines(t, "request"))
			req := newRequest(t, "GET", "https://"+apiName+"/v1/b/o", nil)
			req.Header.Set("Authorization", "Bearer "+tc.tok)
			res, body := get(t, c, req)
			l := j.waitLines(t, "request", lines+1)[lines]
			seen := up.requests()
			switch tc.want {
			case refused:
				if res.StatusCode != http.StatusForbidden || !strings.Contains(body, "session key JWT") || len(seen) != before {
					t.Fatalf("%d %q, upstream saw %d", res.StatusCode, body, len(seen)-before)
				}
				if l["decision"] != DecisionRefused || !strings.HasPrefix(l["reason"].(string), "session key JWT") {
					t.Errorf("request line: %v", l)
				}
				return
			case passed:
				if got := seen[len(seen)-1].Header.Get("Authorization"); got != "Bearer "+tc.tok {
					t.Errorf("sent upstream as %q", got)
				}
			default:
				if got := seen[len(seen)-1].Header.Get("Authorization"); got != "Bearer "+realToken {
					t.Errorf("sent upstream as %q", got)
				}
			}
			if res.StatusCode != 200 || l["credential"] != tc.want {
				t.Errorf("%d, request line %v", res.StatusCode, l)
			}
		})
	}
	if strings.Contains(j.String(), realToken) || strings.Contains(j.String(), "eyJ") {
		t.Error("a credential or a JWT is in the log")
	}
}

// A client calling a regional host signs its JWT for the API's global host,
// which the route also serves: that is the placeholder there too.
func TestAJWTForTheGlobalHostIsThePlaceholderAtARegionalOne(t *testing.T) {
	f, up, _ := newGAPIFixture(t)
	c := f.client(t, true)
	tok := sign(t, jose.RS256, sessionPriv(), claimsAt(time.Now(), "https://aiplatform.gapi.test/"))
	for _, host := range []string{"us-central1-aiplatform.gapi.test", "aiplatform.us.rep.gapi.test"} {
		req := newRequest(t, "GET", "https://"+host+"/v1/projects/p/locations/l/models", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		res, _ := get(t, c, req)
		seen := up.requests()
		if res.StatusCode != 200 || seen[len(seen)-1].Header.Get("Authorization") != "Bearer "+realToken {
			t.Errorf("%s: %d", host, res.StatusCode)
		}
	}
}

// A JWT the key signed is verified once and remembered until it expires --
// clients reuse one for an hour.
func TestAVerifiedJWTIsRememberedUntilItExpires(t *testing.T) {
	k, err := compileSessionKey(testSessionKey(), "gapi", servesGAPI)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok := sign(t, jose.RS256, sessionPriv(), claimsAt(now, "https://"+apiName+"/"))
	if ours, why := k.bearer(tok, now); !ours || why != "" {
		t.Fatalf("bearer = %v %q", ours, why)
	}
	// Were it verified again, it would be refused: the key no longer
	// matches. Remembered, it is still the placeholder.
	k.Key = &otherPriv().PublicKey
	if ours, why := k.bearer(tok, now.Add(time.Minute)); !ours || why != "" || k.cached() != 1 {
		t.Fatalf("remembered: bearer = %v %q, %d cached", ours, why, k.cached())
	}
	k.Key = &sessionPriv().PublicKey
	if ours, why := k.bearer(tok, now.Add(time.Hour)); !ours || why != errExpired.Error() {
		t.Fatalf("past its exp: bearer = %v %q", ours, why)
	}

	for i := range maxVerified + 100 {
		exp := now.Add(time.Hour)
		if i%2 == 0 {
			exp = now.Add(-time.Second)
		}
		k.remember(sha256.Sum256([]byte{byte(i), byte(i >> 8)}), verified{exp: exp}, now)
	}
	if n := k.cached(); n > maxVerified {
		t.Fatalf("%d remembered, more than %d", n, maxVerified)
	}
}

// A JWT-BEARER GRANT THE SESSION KEY SIGNED IS ANSWERED HERE, with the
// placeholder, whatever the scope says, and nothing is sent upstream: at
// either token URL, with either as its audience, as Node's storage library
// does. One asking for target_audience gets an ID token signed by nobody.
func TestAGrantIsAnsweredWithThePlaceholder(t *testing.T) {
	f, up, j := newGAPIFixture(t)
	c := f.client(t, false)
	now := time.Now()
	grant := func(at, aud string, extra ...any) (*http.Response, map[string]any) {
		t.Helper()
		form := url.Values{"grant_type": {jwtBearer}, "assertion": {sign(t, jose.RS256, sessionPriv(), with(claimsAt(now, aud), extra...))}}
		req := newRequest(t, "POST", at, strings.NewReader(form.Encode()))
		req.Header.Del("Authorization")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, body := get(t, c, req)
		var out map[string]any
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("%s: %q is not JSON", at, body)
		}
		return res, out
	}
	for _, tc := range [][2]string{{tokenURL, tokenURL}, {legacyURL, legacyURL}, {tokenURL, legacyURL}, {legacyURL, tokenURL}} {
		res, out := grant(tc[0], tc[1], "scope", "https://www.googleapis.com/auth/cloud-platform")
		if res.StatusCode != 200 || out["access_token"] != placeholder || out["expires_in"] != float64(3599) || out["token_type"] != "Bearer" {
			t.Errorf("POST %s, aud %s: %d %v", tc[0], tc[1], res.StatusCode, out)
		}
		if res.Header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
			t.Errorf("headers %v", res.Header)
		}
	}

	res, out := grant(tokenURL, tokenURL, "target_audience", "https://svc.run.test")
	idt, _ := out["id_token"].(string)
	parts := strings.Split(idt, ".")
	if res.StatusCode != 200 || len(parts) != 3 {
		t.Fatalf("an ID token grant: %d %v", res.StatusCode, out)
	}
	var claims struct {
		Aud string `json:"aud"`
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(b, &claims); err != nil || claims.Aud != "https://svc.run.test" || claims.Sub != issuer || claims.Exp <= now.Unix() {
		t.Errorf("the ID token's claims: %s", b)
	}

	if n := len(up.requests()); n != 0 {
		t.Fatalf("a grant reached the upstream: %d requests", n)
	}
	for _, l := range j.waitLines(t, "request", 5) {
		if l["credential"] != CredentialAnswered || l["decision"] != DecisionAllowed || l["rule"] != RuleGrant {
			t.Errorf("request line: %v", l)
		}
	}

	// The placeholder it answered with is the one replaced.
	get(t, c, newRequest(t, "GET", "https://"+apiName+"/v1/b/o", nil))
	if seen := up.requests(); len(seen) != 1 || seen[0].Header.Get("Authorization") != "Bearer "+realToken {
		t.Fatalf("the answered placeholder, used: %v", seen)
	}
}

// ANYTHING ELSE AT A GRANT URL IS 400, AND NOTHING LEAVES: a token URL is
// never forwarded, so an assertion frisket would not answer is never one
// Google sees either.
func TestAnythingElseAtAGrantURLIsRefusedHere(t *testing.T) {
	f, up, j := newGAPIFixture(t)
	c := f.client(t, true)
	now := time.Now()
	ok := sign(t, jose.RS256, sessionPriv(), claimsAt(now, tokenURL))
	form := func(kv ...string) string {
		v := url.Values{}
		for i := 0; i < len(kv); i += 2 {
			v.Add(kv[i], kv[i+1])
		}
		return v.Encode()
	}
	for _, tc := range []struct {
		name, method, url, contentType, body, error string
	}{
		{"a GET", "GET", tokenURL, "", "", "invalid_request"},
		{"a refresh token", "POST", tokenURL, "application/x-www-form-urlencoded", form("grant_type", "refresh_token", "refresh_token", "1//x"), "unsupported_grant_type"},
		{"no grant type", "POST", tokenURL, "application/x-www-form-urlencoded", form("assertion", ok), "invalid_request"},
		{"two grant types", "POST", tokenURL, "application/x-www-form-urlencoded", form("grant_type", jwtBearer, "grant_type", jwtBearer, "assertion", ok), "invalid_request"},
		{"two assertions", "POST", tokenURL, "application/x-www-form-urlencoded", form("grant_type", jwtBearer, "assertion", ok, "assertion", ok), "invalid_request"},
		{"JSON", "POST", tokenURL, "application/json", `{"grant_type":"` + jwtBearer + `","assertion":"` + ok + `"}`, "invalid_request"},
		{"no assertion", "POST", tokenURL, "application/x-www-form-urlencoded", form("grant_type", jwtBearer), "invalid_grant"},
		{"another key's assertion", "POST", tokenURL, "application/x-www-form-urlencoded", form("grant_type", jwtBearer, "assertion", sign(t, jose.RS256, otherPriv(), claimsAt(now, tokenURL))), "invalid_grant"},
		{"an HS256 assertion", "POST", tokenURL, "application/x-www-form-urlencoded", form("grant_type", jwtBearer, "assertion", sign(t, jose.HS256, []byte(publicPEM(t, &sessionPriv().PublicKey)), claimsAt(now, tokenURL))), "invalid_grant"},
		{"an API's audience", "POST", tokenURL, "application/x-www-form-urlencoded", form("grant_type", jwtBearer, "assertion", sign(t, jose.RS256, sessionPriv(), claimsAt(now, "https://"+apiName+"/"))), "invalid_grant"},
		{"no audience", "POST", tokenURL, "application/x-www-form-urlencoded", form("grant_type", jwtBearer, "assertion", sign(t, jose.RS256, sessionPriv(), with(claimsAt(now, ""), "scope", "x"))), "invalid_grant"},
		{"expired", "POST", tokenURL, "application/x-www-form-urlencoded", form("grant_type", jwtBearer, "assertion", sign(t, jose.RS256, sessionPriv(), with(claimsAt(now, tokenURL), "iat", now.Add(-2*time.Hour).Unix(), "exp", now.Add(-time.Hour).Unix()))), "invalid_grant"},
		{"a person's subject", "POST", tokenURL, "application/x-www-form-urlencoded", form("grant_type", jwtBearer, "assertion", sign(t, jose.RS256, sessionPriv(), with(claimsAt(now, tokenURL), "sub", "person@x.test"))), "invalid_grant"},
		{"too big", "POST", tokenURL, "application/x-www-form-urlencoded", form("grant_type", jwtBearer, "assertion", strings.Repeat("a", maxGrantBody)), "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := len(j.lines(t, "request"))
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			req := newRequest(t, tc.method, tc.url, body)
			req.Header.Set("Content-Type", tc.contentType)
			res, got := get(t, c, req)
			var out map[string]string
			if err := json.Unmarshal([]byte(got), &out); err != nil || res.StatusCode != http.StatusBadRequest || out["error"] != tc.error {
				t.Fatalf("%d %q, want 400 %s", res.StatusCode, got, tc.error)
			}
			if l := j.waitLines(t, "request", lines+1)[lines]; l["decision"] != DecisionRefused || l["rule"] != RuleGrant || l["credential"] != nil {
				t.Errorf("request line: %v", l)
			}
		})
	}
	if n := len(up.requests()); n != 0 {
		t.Fatalf("%d requests to a grant URL reached the upstream", n)
	}
}

// A TOKEN URL SPELT ANOTHER WAY IS STILL ONE: answered here, never sent on,
// even on a route whose scope would admit anything there.
func TestAGrantURLSpeltAnotherWayIsAnsweredHere(t *testing.T) {
	j := &journal{}
	up := newNamedUpstream(t, "gapi.test")
	cred, _ := tokenFile(t, j, realToken)
	rt := gapiRoute(up, cred)
	rt.Scope = Scope{Paths: []PathRule{{Methods: []string{"GET", "POST"}, Prefix: "/"}}}
	c := newNamedFixture(t, j, up, rt).client(t, true)
	now := time.Now()
	form := url.Values{"grant_type": {jwtBearer}, "assertion": {sign(t, jose.RS256, sessionPriv(), claimsAt(now, tokenURL))}}
	for _, target := range []string{
		tokenURL + "/", "https://oauth2.gapi.test/Token", "https://oauth2.gapi.test/token;x", "https://oauth2.gapi.test/token.",
		"https://oauth2.gapi.test/%74oken", legacyURL + "/", "https://www.gapi.test/oauth2%2Fv4%2Ftoken", "https://www.gapi.test/OAuth2/v4/token",
	} {
		req := newRequest(t, "POST", target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, body := get(t, c, req)
		if res.StatusCode != 200 || !strings.Contains(body, placeholder) {
			t.Errorf("POST %s: %d %q", target, res.StatusCode, body)
		}
	}
	for _, target := range []string{"https://oauth2.gapi.test//token", "https://oauth2.gapi.test/./token"} {
		req := newRequest(t, "POST", target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if res, _ := get(t, c, req); res.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s: %d, want 403", target, res.StatusCode)
		}
	}
	if n := len(up.requests()); n != 0 {
		t.Fatalf("%d requests to a grant URL reached the upstream", n)
	}
}

func TestNewRefusesABadSessionKey(t *testing.T) {
	cred, _ := tokenFile(t, &journal{}, realToken)
	up := &namedUpstream{ca: mustCA(t, "gapi.test")}
	good := gapiRoute(up, cred)
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	oauth := Route{Name: "oauth", Host: "oauth2.gapi.test", Upstream: "https://oauth2.gapi.test",
		Scope: Scope{Paths: []PathRule{{Methods: []string{"POST"}, Prefix: "/", Refuse: true}}}}
	for name, tc := range map[string]struct {
		mutate func(r *Route)
		also   []Route
	}{
		"no key":                       {mutate: func(r *Route) { r.SessionKey.Key = nil }},
		"a key of 1024 bits":           {mutate: func(r *Route) { r.SessionKey.Key = &small.PublicKey }},
		"no issuer":                    {mutate: func(r *Route) { r.SessionKey.Issuer = "" }},
		"a grant with no path":         {mutate: func(r *Route) { r.SessionKey.Grants = []string{"oauth2.gapi.test"} }},
		"a grant of a URL":             {mutate: func(r *Route) { r.SessionKey.Grants = []string{"https://oauth2.gapi.test/token"} }},
		"a grant with a query":         {mutate: func(r *Route) { r.SessionKey.Grants = []string{"oauth2.gapi.test/token?x=1"} }},
		"a grant in capitals":          {mutate: func(r *Route) { r.SessionKey.Grants = []string{"OAUTH2.gapi.test/token"} }},
		"a grant on another suffix":    {mutate: func(r *Route) { r.SessionKey.Grants = []string{"oauth2.other.test/token"} }},
		"a grant at the suffix itself": {mutate: func(r *Route) { r.SessionKey.Grants = []string{"gapi.test/token"} }},
		"a grant another route serves": {mutate: func(*Route) {}, also: []Route{oauth}},
		"no credential": {mutate: func(r *Route) {
			r.Credential, r.Inject, r.Placeholder = nil, nil, ""
		}},
		"a Basic injector": {mutate: func(r *Route) { r.Inject = BasicUser("x") }},
		"a bare header":    {mutate: func(r *Route) { r.Inject = HeaderNamed("X-Goog-Api-Key") }},
	} {
		r := good
		k := *good.SessionKey
		r.SessionKey = &k
		tc.mutate(&r)
		if ic, err := New(Config{Routes: append([]Route{r}, tc.also...), Log: log}); err == nil {
			_ = ic.Close()
			t.Errorf("%s: built, want a refusal", name)
		}
	}
	for name, text := range map[string]string{
		"not PEM":          "nope",
		"a private key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(sessionPriv())})),
		"a small key":      publicPEM(t, &small.PublicKey),
		"trailing data":    publicPEM(t, &sessionPriv().PublicKey) + "more",
		"an RSA PKCS1 key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&sessionPriv().PublicKey)})),
	} {
		if _, err := ParsePublicKey(text); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := ParsePublicKey(publicPEM(t, &sessionPriv().PublicKey)); err != nil {
		t.Fatal(err)
	}
}

func mustCA(t *testing.T, host string) *CA {
	t.Helper()
	ca, err := NewCA([]string{host})
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// WHAT THE SESSION KEY ADMITS IS EXACTLY THE MODEL: RS256 by that key, the
// session's issuer and no other subject, in date and at most an hour and a
// bit long, and either a served host's audience or a scope with none.
func TestTheSessionKeyAdmitsExactlyTheSessionsJWTs(t *testing.T) {
	k, err := compileSessionKey(testSessionKey(), "gapi", servesGAPI)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rapid.Check(t, func(rt *rapid.T) {
		byUs := rapid.Bool().Draw(rt, "byUs")
		iss := rapid.SampledFrom([]string{issuer, "evil@x.test", ""}).Draw(rt, "iss")
		sub := rapid.SampledFrom([]string{"", issuer, "person@x.test"}).Draw(rt, "sub")
		aud := rapid.SampledFrom([]string{"", "https://" + apiName + "/", "https://pubsub.gapi.test/", "https://elsewhere.test/", tokenURL}).Draw(rt, "aud")
		scope := rapid.SampledFrom([]string{"", "https://www.googleapis.com/auth/cloud-platform"}).Draw(rt, "scope")
		iat := now.Add(time.Duration(rapid.IntRange(-3*3600, 3600).Draw(rt, "iat")) * time.Second)
		life := time.Duration(rapid.IntRange(0, 3*3600).Draw(rt, "life")) * time.Second

		c := map[string]any{"iss": iss, "iat": iat.Unix(), "exp": iat.Add(life).Unix()}
		if sub != "" {
			c["sub"] = sub
		}
		if aud != "" {
			c["aud"] = aud
		}
		if scope != "" {
			c["scope"] = scope
		}
		key := otherPriv()
		if byUs {
			key = sessionPriv()
		}
		ours, why := k.bearer(sign(t, jose.RS256, key, c), now)

		exp := time.Unix(iat.Add(life).Unix(), 0)
		wantOurs := byUs
		admit := iss == issuer && (sub == "" || sub == issuer) && now.Before(exp) &&
			!time.Unix(iat.Unix(), 0).After(now.Add(jwtSkew)) && exp.Sub(time.Unix(iat.Unix(), 0)) <= jwtMaxLife &&
			(aud == "https://"+apiName+"/" || aud == "https://pubsub.gapi.test/" || aud == "" && scope != "")
		if ours != wantOurs || (wantOurs && (why == "") != admit) {
			rt.Fatalf("bearer = %v %q; want ours %v, admitted %v", ours, why, wantOurs, admit)
		}
	})
}

// Whatever the sandbox puts after "Bearer", the session key never panics,
// and admits only what it signed, as RS256, for the session.
func FuzzSessionKeyBearer(f *testing.F) {
	now := time.Now()
	own := claimsAt(now, "https://"+apiName+"/")
	f.Add(sign(f, jose.RS256, sessionPriv(), own))
	f.Add(sign(f, jose.RS256, otherPriv(), own))
	f.Add(sign(f, jose.HS256, []byte(strings.Repeat("k", 32)), own))
	f.Add(unsigned(map[string]any{"alg": "none"}, own))
	f.Add("eyJ.eyJ.")
	f.Add("a.b.c.d.e")
	k, err := compileSessionKey(testSessionKey(), "gapi", servesGAPI)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, tok string) {
		ours, why := k.bearer(tok, now)
		if !ours || why != "" {
			return
		}
		sig, err := jose.ParseSignedCompact(tok, []jose.SignatureAlgorithm{jose.RS256})
		if err != nil {
			t.Fatalf("admitted %q, which is not RS256: %v", tok, err)
		}
		payload, err := sig.Verify(&sessionPriv().PublicKey)
		if err != nil {
			t.Fatalf("admitted %q, which the session key did not sign", tok)
		}
		var c claims
		if json.Unmarshal(payload, &c) != nil || c.Issuer != issuer || c.Expiry == nil || !now.Before(c.Expiry.Time()) {
			t.Fatalf("admitted claims %s", payload)
		}
	})
}
