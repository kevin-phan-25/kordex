package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestOIDCSignatureIssuerAudienceAndExpiry(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var v any
		if r.URL.Path == "/.well-known/openid-configuration" {
			v = map[string]any{"issuer": issuer, "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}}
		} else {
			v = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}}
		}
		if err := json.NewEncoder(w).Encode(v); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	issuer = server.URL
	ctx := oidc.ClientContext(context.Background(), server.Client())
	verifier, err := New(ctx, issuer, "kordex")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, iss, aud, subject string
		expiry                  time.Time
		valid                   bool
	}{
		{name: "valid", iss: issuer, aud: "kordex", subject: "alice", expiry: time.Now().Add(time.Hour), valid: true},
		{name: "maximum subject length", iss: issuer, aud: "kordex", subject: strings.Repeat("a", 255), expiry: time.Now().Add(time.Hour), valid: true},
		{name: "issuer", iss: issuer + "/wrong", aud: "kordex", subject: "alice", expiry: time.Now().Add(time.Hour)},
		{name: "audience", iss: issuer, aud: "other", subject: "alice", expiry: time.Now().Add(time.Hour)},
		{name: "expired", iss: issuer, aud: "kordex", subject: "alice", expiry: time.Now().Add(-time.Hour)},
		{name: "empty subject", iss: issuer, aud: "kordex", expiry: time.Now().Add(time.Hour)},
		{name: "subject too long", iss: issuer, aud: "kordex", subject: strings.Repeat("a", 256), expiry: time.Now().Add(time.Hour)},
		{name: "non-ASCII subject", iss: issuer, aud: "kordex", subject: "álîce", expiry: time.Now().Add(time.Hour)},
		{name: "control character subject", iss: issuer, aud: "kordex", subject: "alice\x00admin", expiry: time.Now().Add(time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: tc.iss, Subject: tc.subject, Audience: jwt.Audience{tc.aud}, Expiry: jwt.NewNumericDate(tc.expiry)}).Serialize()
			if err != nil {
				t.Fatal(err)
			}
			subject, err := verifier.Verify(ctx, token)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.valid && subject != tc.subject {
				t.Fatalf("subject=%q, want %q", subject, tc.subject)
			}
			if tc.valid {
				verifiedSubject, expiry, verifyErr := verifier.VerifyWithExpiry(ctx, token)
				if verifyErr != nil || verifiedSubject != tc.subject || !expiry.Equal(time.Unix(tc.expiry.Unix(), 0)) {
					t.Fatalf("verified expiry subject=%q expiry=%v err=%v", verifiedSubject, expiry, verifyErr)
				}
			}
		})
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: otherKey}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	forged, err := jwt.Signed(otherSigner).Claims(jwt.Claims{Issuer: issuer, Subject: "alice", Audience: jwt.Audience{"kordex"}, Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour))}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifier.Verify(ctx, forged); err == nil {
		t.Fatal("OIDC verifier accepted a token signed by an unknown key")
	}
	accessSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test").WithHeader("typ", "at+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	accessToken, err := jwt.Signed(accessSigner).Claims(jwt.Claims{Issuer: issuer, Subject: "alice", Audience: jwt.Audience{"kordex"}, Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour))}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(ctx, accessToken); err == nil {
		t.Fatal("ID-token mode accepted a JWT explicitly typed as an access token")
	}
	for _, tc := range []struct {
		name  string
		aud   jwt.Audience
		azp   string
		valid bool
	}{
		{"single audience without azp", jwt.Audience{"kordex"}, "", true},
		{"single audience with another party", jwt.Audience{"kordex"}, "another-client", false},
		{"multiple audiences without party", jwt.Audience{"kordex", "other"}, "", false},
		{"multiple audiences with another party", jwt.Audience{"kordex", "other"}, "another-client", false},
		{"multiple audiences with expected party", jwt.Audience{"kordex", "other"}, "kordex", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: issuer, Subject: "alice", Audience: tc.aud, Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour))}).Claims(map[string]any{"azp": tc.azp}).Serialize()
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifier.Verify(ctx, token)
			if (err == nil) != tc.valid {
				t.Fatalf("authorized-party contract valid=%v err=%v", tc.valid, err)
			}
		})
	}
}

func TestRFC9068AccessTokenContract(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var v any
		if r.URL.Path == "/.well-known/openid-configuration" {
			v = map[string]any{"issuer": issuer, "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}}
		} else {
			v = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}}
		}
		if err := json.NewEncoder(w).Encode(v); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	issuer = server.URL
	ctx := oidc.ClientContext(context.Background(), server.Client())
	verifier, err := NewWithContract(ctx, issuer, "kordex-api", TokenContract{
		Mode: AccessTokenMode, AccessClientID: "kordex-dashboard", RequiredAccessScopes: []string{"kordex.read", "kordex.operate"},
	})
	if err != nil {
		t.Fatal(err)
	}
	accessSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test").WithHeader("typ", "at+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	idSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		signer   jose.Signer
		audience jwt.Audience
		clientID string
		tokenID  string
		scope    string
		expires  time.Time
		issuedAt bool
		valid    bool
	}{
		{name: "valid", signer: accessSigner, audience: jwt.Audience{"kordex-api"}, clientID: "kordex-dashboard", tokenID: "access-1", scope: "kordex.read kordex.operate", expires: time.Now().Add(time.Hour), issuedAt: true, valid: true},
		{name: "ID token type rejected", signer: idSigner, audience: jwt.Audience{"kordex-api"}, clientID: "kordex-dashboard", tokenID: "access-1", scope: "kordex.read kordex.operate", expires: time.Now().Add(time.Hour)},
		{name: "wrong API audience", signer: accessSigner, audience: jwt.Audience{"other-api"}, clientID: "kordex-dashboard", tokenID: "access-1", scope: "kordex.read kordex.operate", expires: time.Now().Add(time.Hour)},
		{name: "multiple audiences rejected", signer: accessSigner, audience: jwt.Audience{"kordex-api", "other-api"}, clientID: "kordex-dashboard", tokenID: "access-1", scope: "kordex.read kordex.operate", expires: time.Now().Add(time.Hour)},
		{name: "wrong OAuth client", signer: accessSigner, audience: jwt.Audience{"kordex-api"}, clientID: "another-client", tokenID: "access-1", scope: "kordex.read kordex.operate", expires: time.Now().Add(time.Hour)},
		{name: "missing token identifier", signer: accessSigner, audience: jwt.Audience{"kordex-api"}, clientID: "kordex-dashboard", scope: "kordex.read kordex.operate", expires: time.Now().Add(time.Hour)},
		{name: "missing required scope", signer: accessSigner, audience: jwt.Audience{"kordex-api"}, clientID: "kordex-dashboard", tokenID: "access-1", scope: "kordex.read", expires: time.Now().Add(time.Hour)},
		{name: "missing issued-at", signer: accessSigner, audience: jwt.Audience{"kordex-api"}, clientID: "kordex-dashboard", tokenID: "access-1", scope: "kordex.read kordex.operate", expires: time.Now().Add(time.Hour)},
		{name: "expired", signer: accessSigner, audience: jwt.Audience{"kordex-api"}, clientID: "kordex-dashboard", tokenID: "access-1", scope: "kordex.read kordex.operate", expires: time.Now().Add(-time.Hour)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stdClaims := jwt.Claims{Issuer: issuer, Subject: "alice", Audience: tc.audience, Expiry: jwt.NewNumericDate(tc.expires)}
			if tc.issuedAt {
				stdClaims.IssuedAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
			}
			token, err := jwt.Signed(tc.signer).Claims(stdClaims).Claims(map[string]any{
				"client_id": tc.clientID, "jti": tc.tokenID, "scope": tc.scope,
			}).Serialize()
			if err != nil {
				t.Fatal(err)
			}
			subject, err := verifier.Verify(ctx, token)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v subject=%q err=%v", tc.valid, subject, err)
			}
			if tc.valid && subject != "alice" {
				t.Fatalf("subject=%q, want alice", subject)
			}
		})
	}
}

func TestAccessTokenContractRejectsUnsafeConfiguration(t *testing.T) {
	for name, contract := range map[string]TokenContract{
		"no client":                {Mode: AccessTokenMode, RequiredAccessScopes: []string{"kordex.read"}},
		"same audience and client": {Mode: AccessTokenMode, AccessClientID: "kordex-api", RequiredAccessScopes: []string{"kordex.read"}},
		"no scopes":                {Mode: AccessTokenMode, AccessClientID: "kordex-dashboard"},
		"invalid scope":            {Mode: AccessTokenMode, AccessClientID: "kordex-dashboard", RequiredAccessScopes: []string{"kordex.read other"}},
		"access fields in ID mode": {Mode: IDTokenMode, AccessClientID: "kordex-dashboard"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewWithContract(context.Background(), "https://issuer.example.test", "kordex-api", contract); err == nil {
				t.Fatal("accepted invalid access-token contract")
			}
		})
	}
}
