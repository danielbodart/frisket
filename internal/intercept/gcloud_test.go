package intercept

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// GOOGLE'S SHAPE, WHOLE: one wildcard route with the session key, verb and
// encoded-slash rules, and every request decided on the method an override
// names -- the grant, the JWT, the rule, the question and what goes upstream.
func TestAGoogleRouteDecidesOnTheOverriddenMethodEverywhere(t *testing.T) {
	protos(t, func(t *testing.T, h2 bool) {
		j := &journal{}
		up := newNamedUpstream(t, "gapi.test")
		cred, _ := tokenFile(t, j, realToken)
		rt := gapiRoute(up, cred)
		rt.Scope = Scope{Paths: []PathRule{
			{Methods: []string{"GET"}, Prefix: "/v1"},
			{Methods: []string{"GET"}, Path: "/v1/projects/*/secrets/*/versions/*:access", Refuse: true},
			{Methods: []string{"POST"}, Path: "/v1/projects/*/secrets/*:addVersion", Ask: true},
			{Methods: []string{"GET"}, Path: "/storage/v1/b/*/o/*", EncodedSlashes: true},
			{Methods: []string{"DELETE"}, Path: "/storage/v1/b/*/o/*", EncodedSlashes: true, Refuse: true},
		}}
		asker := &answers{answer: func(Question) (bool, error) { return true, nil }}
		f := newFixtureWith(t, j, Config{
			Routes:      []Route{rt},
			Log:         slog.New(slog.NewJSONHandler(j, nil)),
			Policy:      "test-policy",
			Asker:       asker,
			DialContext: up.dial,
		})
		c := f.client(t, h2)
		now := time.Now()
		const secrets = "https://secretmanager.gapi.test/v1/projects/p/secrets/s"
		jwt := func(host string) string {
			return "Bearer " + sign(t, jose.RS256, sessionPriv(), claimsAt(now, "https://"+host+"/"))
		}
		send := func(method, target, override, auth, body string) *http.Response {
			t.Helper()
			req := newRequest(t, method, target, strings.NewReader(body))
			if body == "" {
				req.Body = http.NoBody
			}
			if override != "" {
				req.Header.Set("X-HTTP-Method-Override", override)
			}
			req.Header.Set("Authorization", auth)
			res, _ := get(t, c, req)
			return res
		}

		form := url.Values{"grant_type": {jwtBearer}, "assertion": {sign(t, jose.RS256, sessionPriv(), claimsAt(now, tokenURL))}}
		req := newRequest(t, "GET", tokenURL, strings.NewReader(form.Encode()))
		req.Header.Del("Authorization")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-HTTP-Method-Override", "POST")
		res, body := get(t, c, req)
		var tok map[string]any
		if err := json.Unmarshal([]byte(body), &tok); err != nil || res.StatusCode != 200 || tok["access_token"] != placeholder {
			t.Fatalf("a grant sent as a GET naming POST: %d %q", res.StatusCode, body)
		}
		if res := send("POST", tokenURL+"?$httpMethod=GET", "", sandboxAuth, form.Encode()); res.StatusCode != http.StatusBadRequest {
			t.Errorf("a grant sent as a POST naming GET: %d, want 400", res.StatusCode)
		}

		if res := send("GET", secrets+"/versions/latest", "", jwt("secretmanager.gapi.test"), ""); res.StatusCode != 200 {
			t.Errorf("a read with the session's JWT: %d", res.StatusCode)
		}
		for _, target := range []string{"/versions/latest:access", "/versions/latest%3Aaccess", "/versions/1:ACCESS"} {
			if res := send("POST", secrets+target, "GET", jwt("secretmanager.gapi.test"), ""); res.StatusCode != http.StatusForbidden {
				t.Errorf("POST %s naming GET: %d, want the verb rule's refusal", target, res.StatusCode)
			}
		}
		if res := send("GET", secrets+"/versions/latest", "", jwt("elsewhere.test"), ""); res.StatusCode != http.StatusForbidden {
			t.Errorf("a JWT for a host the route does not serve: %d", res.StatusCode)
		}

		big := strings.Repeat("s", BodyPreview+100)
		if res := send("GET", secrets+":addVersion", "post", jwt("secretmanager.gapi.test"), big); res.StatusCode != 200 {
			t.Fatalf("an asked write sent as a GET naming POST: %d", res.StatusCode)
		}
		if len(asker.questions) != 1 {
			t.Fatalf("asked %d times", len(asker.questions))
		}
		if q := asker.questions[0]; q.Method != "POST" || q.Host != "secretmanager.gapi.test" || q.Path != "/v1/projects/p/secrets/s:addVersion" ||
			q.Body != big[:BodyPreview] || !q.BodyMore {
			t.Errorf("question: %s %s%s, %d bytes shown, more %v", q.Method, q.Host, q.Path, len(q.Body), q.BodyMore)
		}

		if res := send("GET", "https://storage.gapi.test/storage/v1/b/bkt/o/a%2Fb", "", "Bearer "+placeholder, ""); res.StatusCode != 200 {
			t.Errorf("an object with a slash in its name: %d", res.StatusCode)
		}
		if res := send("GET", "https://storage.gapi.test/storage/v1/b/bkt/o/a%2Fb?$httpMethod=DELETE", "", "Bearer "+placeholder, ""); res.StatusCode != http.StatusForbidden {
			t.Errorf("a GET naming DELETE of an object: %d", res.StatusCode)
		}

		seen := up.requests()
		if len(seen) != 3 {
			t.Fatalf("%d requests reached the upstream, want 3", len(seen))
		}
		for i, want := range []struct{ method, host, path string }{
			{"GET", "secretmanager.gapi.test", "/v1/projects/p/secrets/s/versions/latest"},
			{"POST", "secretmanager.gapi.test", "/v1/projects/p/secrets/s:addVersion"},
			{"GET", "storage.gapi.test", "/storage/v1/b/bkt/o/a%2Fb"},
		} {
			r := seen[i]
			if r.Method != want.method || r.TLS.ServerName != want.host || r.URL.EscapedPath() != want.path {
				t.Errorf("upstream %d: %s %s%s", i, r.Method, r.TLS.ServerName, r.URL.EscapedPath())
			}
			if r.Header.Get("Authorization") != "Bearer "+realToken {
				t.Errorf("upstream %d: Authorization %q", i, r.Header.Get("Authorization"))
			}
			if r.Header.Get("X-Http-Method-Override") != "" {
				t.Errorf("upstream %d saw the override", i)
			}
		}

		lines := j.waitLines(t, "request", 10)
		if l := lines[0]; l["credential"] != CredentialAnswered || l["method"] != "POST" || l["method_sent"] != "GET" || l["host"] != "oauth2.gapi.test" {
			t.Errorf("the grant's line: %v", l)
		}
		if l := lines[7]; l["method"] != "POST" || l["method_sent"] != "GET" || l["rule"] != RuleAsked || l["credential"] != CredentialInjected {
			t.Errorf("the asked write's line: %v", l)
		}
	})
}
