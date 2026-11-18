package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		name, iss, aud string
		expiry         time.Time
		valid          bool
	}{
		{"valid", issuer, "kordex", time.Now().Add(time.Hour), true},
		{"issuer", issuer + "/wrong", "kordex", time.Now().Add(time.Hour), false},
		{"audience", issuer, "other", time.Now().Add(time.Hour), false},
		{"expired", issuer, "kordex", time.Now().Add(-time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: tc.iss, Subject: "alice", Audience: jwt.Audience{tc.aud}, Expiry: jwt.NewNumericDate(tc.expiry)}).Serialize()
			if err != nil {
				t.Fatal(err)
			}
			subject, err := verifier.Verify(ctx, token)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.valid && subject != "alice" {
				t.Fatal("subject mismatch")
			}
		})
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
