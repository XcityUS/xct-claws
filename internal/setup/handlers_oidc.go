package setup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fastclaw-ai/fastclaw/internal/config"
	"github.com/fastclaw-ai/fastclaw/internal/scope"
	"github.com/fastclaw-ai/fastclaw/internal/store"
	"github.com/fastclaw-ai/fastclaw/internal/users"
)

// "Sign in with Xcity" — FastClaw as an OAuth 2.1 / OIDC client of an external
// IdP (auth.xcity.one / GoTrue). Two routes, registered only when the OIDC
// config is present (see EnvOIDC.Enabled):
//
//	GET /auth/oidc/login    — start authorization-code + PKCE, redirect to IdP
//	GET /auth/oidc/callback — exchange code, provision the user, issue a session,
//	                          then bind their xct-home TokenHub key as a provider
//
// Identity is the IdP's verified user (keyed by email here for the MVP — no
// schema change). The user becomes a first-class FastClaw `user` and owns their
// agents in the console; a user-scope "tokenhub" provider carries their key so
// every agent they create inherits it.

const (
	oidcStateCookie    = "fc_oidc_state"
	oidcVerifierCookie = "fc_oidc_verifier"
)

var oidcHTTPClient = &http.Client{Timeout: 15 * time.Second}

// handleOIDCLogin kicks off the authorization-code + PKCE flow.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil || !s.oidc.Enabled() {
		http.Error(w, "oidc not configured", http.StatusNotFound)
		return
	}
	verifier, challenge, err := pkcePair()
	if err != nil {
		http.Error(w, "oidc: pkce generation failed", http.StatusInternalServerError)
		return
	}
	state, err := randURLToken(24)
	if err != nil {
		http.Error(w, "oidc: state generation failed", http.StatusInternalServerError)
		return
	}
	setShortCookie(w, oidcStateCookie, state)
	setShortCookie(w, oidcVerifierCookie, verifier)

	q := url.Values{}
	q.Set("client_id", s.oidc.ClientID)
	q.Set("redirect_uri", s.oidc.RedirectURL)
	q.Set("response_type", "code")
	q.Set("scope", s.oidc.Scopes)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	http.Redirect(w, r, s.oidc.IssuerURL+"/authorize?"+q.Encode(), http.StatusFound)
}

// handleOIDCCallback completes the flow: validate state, exchange the code,
// provision the user + session, then best-effort bind their TokenHub key.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil || !s.oidc.Enabled() {
		http.Error(w, "oidc not configured", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		redirectLoginErr(w, r, e)
		return
	}
	code := q.Get("code")
	state := q.Get("state")
	stateCookie, _ := r.Cookie(oidcStateCookie)
	verifierCookie, _ := r.Cookie(oidcVerifierCookie)
	// One-shot cookies — clear them regardless of outcome.
	clearShortCookie(w, oidcStateCookie)
	clearShortCookie(w, oidcVerifierCookie)

	if code == "" || state == "" || stateCookie == nil || stateCookie.Value != state || verifierCookie == nil {
		redirectLoginErr(w, r, "invalid_oidc_state")
		return
	}

	tok, err := s.exchangeOIDCCode(r.Context(), code, verifierCookie.Value)
	if err != nil {
		slog.Warn("oidc: code exchange failed", "error", err)
		redirectLoginErr(w, r, "oidc_exchange_failed")
		return
	}
	email := strings.ToLower(strings.TrimSpace(tok.User.Email))
	if email == "" {
		redirectLoginErr(w, r, "oidc_no_email")
		return
	}

	acctID, err := s.ensureOIDCUser(r.Context(), email)
	if err != nil {
		slog.Warn("oidc: user provisioning failed", "error", err)
		redirectLoginErr(w, r, "oidc_user_failed")
		return
	}

	cookie, err := s.authResolver.IssueSession(r.Context(), acctID)
	if err != nil {
		slog.Warn("oidc: issue session failed", "error", err)
		redirectLoginErr(w, r, "oidc_session_failed")
		return
	}
	http.SetCookie(w, cookie)

	// Best-effort: bind the user's xct-home TokenHub key. A failure here (e.g.
	// no Claws entitlement → 403) must not block login — the user lands in the
	// console and can subscribe / retry. We just log it.
	if s.oidc.KeyEndpoint != "" {
		if berr := s.bindTokenHubKey(r.Context(), acctID, tok.AccessToken); berr != nil {
			slog.Warn("oidc: bind tokenhub key failed", "error", berr, "user", acctID)
		}
	}

	http.Redirect(w, r, "/overview", http.StatusFound)
}

// oidcTokenResponse is the subset of GoTrue's token response we consume.
type oidcTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	User         struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
}

// exchangeOIDCCode trades an authorization code + PKCE verifier for tokens at
// GoTrue's PKCE token endpoint.
func (s *Server) exchangeOIDCCode(ctx context.Context, code, verifier string) (*oidcTokenResponse, error) {
	body, _ := json.Marshal(map[string]string{"auth_code": code, "code_verifier": verifier})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.oidc.IssuerURL+"/token?grant_type=pkce", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}
	var tok oidcTokenResponse
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, errors.New("token endpoint returned empty access_token")
	}
	return &tok, nil
}

// ensureOIDCUser returns the FastClaw user id for an IdP email, creating a
// passwordless role=user account the first time it's seen. Idempotent.
func (s *Server) ensureOIDCUser(ctx context.Context, email string) (string, error) {
	if s.dataStore == nil || s.accounts == nil {
		return "", errors.New("auth not configured")
	}
	if rec, err := s.dataStore.GetUserByLogin(ctx, email); err == nil {
		return rec.ID, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	// New SSO user: synthesize a random password they'll never use (login is
	// SSO-only). Username = email keeps it unique and human-readable.
	pw, err := randURLToken(24)
	if err != nil {
		return "", err
	}
	acc, err := s.accounts.Create(ctx, users.CreateInput{
		Username:    email,
		Email:       email,
		Password:    pw,
		DisplayName: email,
		Role:        users.RoleUser,
	})
	if err != nil {
		// Race: a concurrent callback created the same email between our miss
		// and the insert — re-read and return that row.
		if again, qerr := s.dataStore.GetUserByLogin(ctx, email); qerr == nil {
			return again.ID, nil
		}
		return "", err
	}
	return acc.ID, nil
}

// keyEndpointResponse mirrors xct-home GET /api/me/integrations/key (200 body).
type keyEndpointResponse struct {
	Key         string   `json:"key"`
	Plan        string   `json:"plan"`
	Models      []string `json:"models"`
	APIBase     string   `json:"api_base"`
	ClawsAccess bool     `json:"claws_access"`
}

// bindTokenHubKey fetches the user's product-scoped TokenHub key from xct-home
// (using their access token) and saves it as a user-scope "tokenhub" provider,
// so every agent the user owns routes models through their own budget.
func (s *Server) bindTokenHubKey(ctx context.Context, userID, accessToken string) error {
	if s.dataStore == nil {
		return errors.New("store not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.oidc.KeyEndpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("key endpoint returned %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var kr keyEndpointResponse
	if err := json.Unmarshal(raw, &kr); err != nil {
		return fmt.Errorf("decode key response: %w", err)
	}
	if kr.Key == "" {
		return errors.New("key endpoint returned empty key")
	}
	models := make([]config.ModelEntry, 0, len(kr.Models))
	for _, m := range kr.Models {
		models = append(models, config.ModelEntry{ID: m, Name: m})
	}
	pcfg := config.ProviderConfig{
		APIKey:  kr.Key,
		APIBase: kr.APIBase,
		APIType: "openai",
		Models:  models,
	}
	if err := scope.SaveProviderByScope(ctx, s.dataStore, scope.User, userID, "tokenhub", pcfg); err != nil {
		return err
	}
	s.invalidateScope(scope.User, userID)
	return nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func pkcePair() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

func randURLToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setShortCookie(w http.ResponseWriter, name, val string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: val, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
}

func clearShortCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1})
}

// redirectLoginErr sends the browser back to the login page with an error code
// the SPA can surface.
func redirectLoginErr(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/?oidc_error="+url.QueryEscape(code), http.StatusFound)
}
