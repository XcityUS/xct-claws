package setup

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fastclaw-ai/fastclaw/internal/auth"
	"github.com/fastclaw-ai/fastclaw/internal/config"
	"github.com/fastclaw-ai/fastclaw/internal/scope"
	"github.com/fastclaw-ai/fastclaw/internal/users"
)

// stubIdP configures a fake OIDC IdP (discovery + token + userinfo).
type stubIdP struct {
	onToken      func(*http.Request)
	tokenJSON    string
	onUserinfo   func(*http.Request)
	userinfoJSON string
}

// newStubIdP spins up an httptest server that serves OIDC discovery pointing at
// its own /oauth/token and /oauth/userinfo. Caller defers Close().
func newStubIdP(t *testing.T, cfg *stubIdP) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"authorization_endpoint":%q,"token_endpoint":%q,"userinfo_endpoint":%q}`,
			srv.URL+"/oauth/authorize", srv.URL+"/oauth/token", srv.URL+"/oauth/userinfo")
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if cfg.onToken != nil {
			cfg.onToken(r)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, cfg.tokenJSON)
	})
	mux.HandleFunc("/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if cfg.onUserinfo != nil {
			cfg.onUserinfo(r)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, cfg.userinfoJSON)
	})
	srv = httptest.NewServer(mux)
	return srv
}

// TestOIDCCallbackProvisionsUserAndBindsKey drives the full callback against
// stub IdP (GoTrue) + xct-home key endpoints: code exchange → user provisioning
// → session issuance → user-scope "tokenhub" provider binding. This is the
// XCT Claw side of the cross-repo integration, exercised end-to-end in-process.
func TestOIDCCallbackProvisionsUserAndBindsKey(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newAuthTestServer(t, ctx)
	t.Setenv("FASTCLAW_HOME", t.TempDir())

	// Stub IdP: OIDC discovery + authorization_code token exchange + userinfo.
	var tokenBody, tokenCT string
	var userinfoAuth string
	idp := newStubIdP(t, &stubIdP{
		onToken: func(r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			tokenBody = string(b)
			tokenCT = r.Header.Get("Content-Type")
		},
		tokenJSON:    `{"access_token":"acc-tok","token_type":"bearer","expires_in":3600,"id_token":"x.y.z"}`,
		onUserinfo:   func(r *http.Request) { userinfoAuth = r.Header.Get("Authorization") },
		userinfoJSON: `{"sub":"sub-1","email":"User@Example.com"}`,
	})
	defer idp.Close()

	// Stub xct-home key endpoint: returns the user's Claws-scoped key.
	var gotAuth string
	keySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"key":"sk-claws-xyz","plan":"pro_monthly","models":["m1","m2"],"api_base":"https://tokenhub.xcity.one","claws_access":true}`)
	}))
	defer keySrv.Close()

	s.SetOIDC(&config.EnvOIDC{
		IssuerURL:   idp.URL,
		ClientID:    "xct-claws",
		RedirectURL: "https://claws.example/auth/oidc/callback",
		KeyEndpoint: keySrv.URL,
		Scopes:      "openid email tokenhub:key",
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=abc&state=st-1", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookie, Value: "st-1"})
	req.AddCookie(&http.Cookie{Name: oidcVerifierCookie, Value: "ver-1"})
	rr := httptest.NewRecorder()
	s.handleOIDCCallback(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "/overview" {
		t.Fatalf("redirect Location = %q, want /overview", loc)
	}
	// authorization_code grant, form-encoded, carrying code + PKCE verifier.
	if !strings.Contains(tokenCT, "x-www-form-urlencoded") {
		t.Fatalf("token Content-Type = %q, want form-urlencoded", tokenCT)
	}
	if !strings.Contains(tokenBody, "grant_type=authorization_code") ||
		!strings.Contains(tokenBody, "code_verifier=ver-1") ||
		!strings.Contains(tokenBody, "code=abc") {
		t.Fatalf("token exchange body wrong: %q", tokenBody)
	}
	if userinfoAuth != "Bearer acc-tok" {
		t.Fatalf("userinfo Authorization = %q, want Bearer acc-tok", userinfoAuth)
	}
	if gotAuth != "Bearer acc-tok" {
		t.Fatalf("key endpoint Authorization = %q, want Bearer acc-tok", gotAuth)
	}

	// Session cookie issued.
	var sess string
	for _, c := range rr.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			sess = c.Value
		}
	}
	if sess == "" {
		t.Fatal("no session cookie issued")
	}

	// User provisioned (email lowercased).
	rec, err := s.dataStore.GetUserByLogin(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("user not provisioned: %v", err)
	}
	if rec.Role != users.RoleUser {
		t.Fatalf("role = %q, want %q", rec.Role, users.RoleUser)
	}

	// Provider bound at user scope with the fetched key.
	provs, err := scope.Providers(ctx, s.dataStore, rec.ID, "")
	if err != nil {
		t.Fatalf("scope.Providers: %v", err)
	}
	p, ok := provs["tokenhub"]
	if !ok {
		t.Fatalf("tokenhub provider not bound; have %v", keys(provs))
	}
	if p.APIKey != "sk-claws-xyz" {
		t.Fatalf("provider APIKey = %q, want sk-claws-xyz", p.APIKey)
	}
	if p.APIType != "openai" {
		t.Fatalf("provider APIType = %q, want openai", p.APIType)
	}
	if p.APIBase != "https://tokenhub.xcity.one" {
		t.Fatalf("provider APIBase = %q", p.APIBase)
	}
	if len(p.Models) != 2 {
		t.Fatalf("provider Models = %d, want 2", len(p.Models))
	}
}

// TestOIDCCallbackRejectsStateMismatch: a forged/mismatched state must not log
// anyone in or create a user (CSRF guard).
func TestOIDCCallbackRejectsStateMismatch(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newAuthTestServer(t, ctx)
	s.SetOIDC(&config.EnvOIDC{
		IssuerURL:   "https://idp.invalid",
		ClientID:    "xct-claws",
		RedirectURL: "https://claws.example/auth/oidc/callback",
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=abc&state=attacker", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookie, Value: "real-state"})
	req.AddCookie(&http.Cookie{Name: oidcVerifierCookie, Value: "ver-1"})
	rr := httptest.NewRecorder()
	s.handleOIDCCallback(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "oidc_error=invalid_oidc_state") {
		t.Fatalf("redirect Location = %q, want oidc_error=invalid_oidc_state", loc)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == auth.SessionCookieName && c.Value != "" {
			t.Fatal("session cookie issued despite state mismatch")
		}
	}
}

// TestOIDCLoginRedirectsToAuthorize: the login route builds a correct authorize
// URL and plants the PKCE state + verifier cookies.
func TestOIDCLoginRedirectsToAuthorize(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newAuthTestServer(t, ctx)
	idp := newStubIdP(t, &stubIdP{tokenJSON: "{}", userinfoJSON: "{}"})
	defer idp.Close()
	s.SetOIDC(&config.EnvOIDC{
		IssuerURL:   idp.URL,
		ClientID:    "xct-claws",
		RedirectURL: "https://claws.xcity.one/auth/oidc/callback",
		Scopes:      "openid email",
	})

	rr := httptest.NewRecorder()
	s.handleOIDCLogin(rr, httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil))

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	loc := rr.Header().Get("Location")
	// Discovery resolves the authorize endpoint to the IdP's /oauth/authorize.
	for _, want := range []string{
		idp.URL + "/oauth/authorize?",
		"client_id=xct-claws",
		"code_challenge_method=S256",
		"response_type=code",
	} {
		if !strings.Contains(loc, want) {
			t.Fatalf("authorize URL %q missing %q", loc, want)
		}
	}
	var haveState, haveVerifier bool
	for _, c := range rr.Result().Cookies() {
		switch c.Name {
		case oidcStateCookie:
			haveState = c.Value != ""
		case oidcVerifierCookie:
			haveVerifier = c.Value != ""
		}
	}
	if !haveState || !haveVerifier {
		t.Fatalf("missing pkce cookies: state=%v verifier=%v", haveState, haveVerifier)
	}
	_ = ctx
}

func keys(m map[string]config.ProviderConfig) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
