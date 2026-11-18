// Package identity validates OIDC ID tokens against one configured issuer and audience.
package identity

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Verifier struct {
	verifier *oidc.IDTokenVerifier
	audience string
}

func New(ctx context.Context, issuer, audience string) (*Verifier, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed")
	}
	return &Verifier{verifier: provider.Verifier(&oidc.Config{ClientID: audience, SupportedSigningAlgs: []string{"RS256", "ES256", "EdDSA"}}), audience: audience}, nil
}
func (v *Verifier) Verify(ctx context.Context, token string) (string, error) {
	id, err := v.verifier.Verify(ctx, token)
	if err != nil {
		return "", fmt.Errorf("invalid OIDC token")
	}
	if id.Subject == "" || len(id.Subject) > 255 {
		return "", fmt.Errorf("invalid OIDC subject")
	}
	var claims struct {
		AuthorizedParty string `json:"azp"`
	}
	if err := id.Claims(&claims); err != nil ||
		claims.AuthorizedParty != "" && claims.AuthorizedParty != v.audience ||
		len(id.Audience) > 1 && claims.AuthorizedParty != v.audience {
		return "", fmt.Errorf("invalid OIDC authorized party")
	}
	return id.Subject, nil
}
