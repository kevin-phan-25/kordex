package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"kordex.local/api/protocol"
)

// IsTokenRevoked checks the exact bearer token digest. Expired revocation rows
// no longer affect authorization and may be removed by the bounded cleanup
// function when the next token is revoked.
func (s *Store) IsTokenRevoked(ctx context.Context, tokenHash []byte) (bool, error) {
	if len(tokenHash) != sha256.Size {
		return false, errors.New("invalid token digest")
	}
	var revoked bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS (
  SELECT 1 FROM oidc_token_revocations WHERE token_hash=$1 AND expires_at>clock_timestamp()
)`, tokenHash).Scan(&revoked)
	return revoked, err
}

// RevokeToken durably fences one already-verified bearer token through its
// issuer-verified expiry. The operation is idempotent and never stores the
// credential itself.
func (s *Store) RevokeToken(ctx context.Context, tokenHash []byte, expiresAt time.Time, subject, requestID string) error {
	if len(tokenHash) != sha256.Size || expiresAt.IsZero() || !validRevocationSubject(subject) || !protocol.ValidUUID(requestID) {
		return ErrInvalid
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT purge_expired_oidc_token_revocations()`); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `INSERT INTO oidc_token_revocations(token_hash,expires_at,subject,request_id)
SELECT $1,$2,$3,$4 WHERE $2>clock_timestamp() ON CONFLICT(token_hash) DO NOTHING`, tokenHash, expiresAt, subject, requestID)
	if err != nil {
		return classify(err)
	}
	if result.RowsAffected() == 0 {
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oidc_token_revocations WHERE token_hash=$1)`, tokenHash).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrInvalid
		}
	}
	return tx.Commit(ctx)
}

func validRevocationSubject(subject string) bool {
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
