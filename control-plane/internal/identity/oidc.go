// Package identity validates explicitly configured OIDC bearer-token contracts.
package identity

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type TokenMode string

const (
	IDTokenMode     TokenMode = "id_token"
	AccessTokenMode TokenMode = "access_token"
)

type TokenContract struct {
	Mode                 TokenMode
	AccessClientID       string
	RequiredAccessScopes []string
}

type Verifier struct {
	verifier *oidc.IDTokenVerifier
	audience string
	contract TokenContract
}

func New(ctx context.Context, issuer, audience string) (*Verifier, error) {
	return NewWithContract(ctx, issuer, audience, TokenContract{Mode: IDTokenMode})
}

func NewWithContract(ctx context.Context, issuer, audience string, contract TokenContract) (*Verifier, error) {
	parsedIssuer, issuerErr := url.Parse(issuer)
	if issuerErr != nil || parsedIssuer.Scheme != "https" || parsedIssuer.Host == "" || parsedIssuer.User != nil || parsedIssuer.RawQuery != "" || parsedIssuer.Fragment != "" || issuer != strings.TrimSpace(issuer) || !validIdentifier(audience) {
		return nil, fmt.Errorf("invalid OIDC issuer or audience configuration")
	}
	if contract.Mode == "" {
		contract.Mode = IDTokenMode
	}
	if contract.Mode != IDTokenMode && contract.Mode != AccessTokenMode {
		return nil, fmt.Errorf("unsupported OIDC token mode")
	}
	if contract.Mode == IDTokenMode && (contract.AccessClientID != "" || len(contract.RequiredAccessScopes) != 0) {
		return nil, fmt.Errorf("access-token client and scopes require access_token mode")
	}
	if contract.Mode == AccessTokenMode {
		if !validIdentifier(contract.AccessClientID) || contract.AccessClientID == audience {
			return nil, fmt.Errorf("access-token mode requires a distinct configured client ID")
		}
		if len(contract.RequiredAccessScopes) == 0 {
			return nil, fmt.Errorf("access-token mode requires at least one required scope")
		}
		seen := make(map[string]struct{}, len(contract.RequiredAccessScopes))
		for _, scope := range contract.RequiredAccessScopes {
			if !validScope(scope) {
				return nil, fmt.Errorf("invalid required OIDC access-token scope")
			}
			if _, ok := seen[scope]; ok {
				return nil, fmt.Errorf("duplicate required OIDC access-token scope")
			}
			seen[scope] = struct{}{}
		}
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed")
	}
	return &Verifier{
		verifier: provider.Verifier(&oidc.Config{ClientID: audience, SupportedSigningAlgs: []string{"RS256", "ES256", "EdDSA"}}),
		audience: audience,
		contract: contract,
	}, nil
}

func (v *Verifier) Verify(ctx context.Context, token string) (string, error) {
	subject, _, err := v.VerifyWithExpiry(ctx, token)
	return subject, err
}

// VerifyWithExpiry returns only claims verified by the configured issuer,
// signature, algorithm, audience, and token-mode contract.
func (v *Verifier) VerifyWithExpiry(ctx context.Context, token string) (string, time.Time, error) {
	typ, err := tokenType(token)
	if err != nil || v.contract.Mode == AccessTokenMode && typ != "at+jwt" || v.contract.Mode == IDTokenMode && typ == "at+jwt" {
		return "", time.Time{}, fmt.Errorf("invalid OIDC token type")
	}
	id, err := v.verifier.Verify(ctx, token)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("invalid OIDC token")
	}
	if !validSubject(id.Subject) {
		return "", time.Time{}, fmt.Errorf("invalid OIDC subject")
	}
	if v.contract.Mode == AccessTokenMode {
		if err := verifyAccessClaims(id, v.audience, v.contract); err != nil {
			return "", time.Time{}, err
		}
	} else {
		var claims struct {
			AuthorizedParty string `json:"azp"`
		}
		if err := id.Claims(&claims); err != nil ||
			claims.AuthorizedParty != "" && claims.AuthorizedParty != v.audience ||
			len(id.Audience) > 1 && claims.AuthorizedParty != v.audience {
			return "", time.Time{}, fmt.Errorf("invalid OIDC authorized party")
		}
	}
	if id.Expiry.IsZero() {
		return "", time.Time{}, fmt.Errorf("invalid OIDC token expiry")
	}
	return id.Subject, id.Expiry, nil
}

// validSubject enforces the OIDC subject identifier's ASCII and length
// contract, and rejects control bytes before the value becomes a tenant
// membership key or audit actor. Subjects remain opaque and case-sensitive.
func validSubject(subject string) bool {
	if len(subject) == 0 || len(subject) > 255 {
		return false
	}
	for i := 0; i < len(subject); i++ {
		if subject[i] < 0x20 || subject[i] > 0x7e {
			return false
		}
	}
	return true
}

func tokenType(token string) (string, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA})
	if err != nil || len(parsed.Headers) != 1 {
		return "", fmt.Errorf("invalid OIDC token")
	}
	typ, ok := parsed.Headers[0].ExtraHeaders[jose.HeaderKey("typ")].(string)
	if !ok {
		typ = ""
	}
	return typ, nil
}

func verifyAccessClaims(id *oidc.IDToken, audience string, contract TokenContract) error {
	if id.IssuedAt.IsZero() || len(id.Audience) != 1 || id.Audience[0] != audience {
		return fmt.Errorf("invalid OIDC access-token issued-at or audience")
	}
	var claims struct {
		ClientID string `json:"client_id"`
		TokenID  string `json:"jti"`
		Scope    string `json:"scope"`
	}
	if err := id.Claims(&claims); err != nil || claims.ClientID != contract.AccessClientID || strings.TrimSpace(claims.TokenID) == "" {
		return fmt.Errorf("invalid OIDC access-token client or identifier")
	}
	granted := make(map[string]struct{})
	for _, scope := range strings.Fields(claims.Scope) {
		granted[scope] = struct{}{}
	}
	for _, required := range contract.RequiredAccessScopes {
		if _, ok := granted[required]; !ok {
			return fmt.Errorf("insufficient OIDC access-token scope")
		}
	}
	return nil
}

func validScope(scope string) bool {
	if scope == "" {
		return false
	}
	for _, r := range scope {
		if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 256 || value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
