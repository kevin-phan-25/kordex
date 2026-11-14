package runner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"kordex.local/agent/internal/client"
	"kordex.local/agent/internal/state"
	"kordex.local/api/protocol"
)

type Collector interface {
	ClusterUID(context.Context) (string, error)
	Collect(context.Context) (protocol.Report, error)
}
type Runner struct {
	Client          *client.Client
	Store           state.Store
	Collector       Collector
	EnrollmentToken string
	Logger          *slog.Logger
	Interval        time.Duration
}

func unauthorized(err error) bool {
	var e *client.APIError
	return errors.As(err, &e) && e.Status == 401
}

// Step is restart-safe: persist keys and monotonically increasing versions before sending.
func (r *Runner) Step(ctx context.Context) error {
	s, err := r.Store.Load(ctx)
	if err != nil {
		return fmt.Errorf("load durable agent state: %w", err)
	}
	uid, err := r.Collector.ClusterUID(ctx)
	if err != nil {
		return fmt.Errorf("read cluster identity: %w", err)
	}
	if (s.ClusterID != "" && s.ClusterID != r.Client.ClusterID) || (s.ClusterUID != "" && s.ClusterUID != uid) {
		return fmt.Errorf("stored identity belongs to a different cluster; explicit administrator recovery required")
	}
	if len(s.PrivateKey) == 0 {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		s.PrivateKey = key
		s.ClusterID = r.Client.ClusterID
		s.ClusterUID = uid
		if err = r.Store.Save(ctx, &s); err != nil {
			return err
		}
	}
	// A rotation response may have been lost. Probe the pending key before falling back.
	if len(s.PendingKey) > 0 {
		if _, err = r.Client.Identity(ctx, ed25519.PrivateKey(s.PendingKey)); err == nil {
			s.PrivateKey = s.PendingKey
			s.PendingKey = nil
			if err = r.Store.Save(ctx, &s); err != nil {
				return err
			}
		} else if !unauthorized(err) {
			return err
		}
	}
	private := ed25519.PrivateKey(s.PrivateKey)
	identity, err := r.Client.Identity(ctx, private)
	if unauthorized(err) {
		if r.EnrollmentToken == "" {
			return fmt.Errorf("identity rejected; enrollment or administrator recovery required")
		}
		identity, err = r.Client.Enroll(ctx, uid, r.EnrollmentToken, private)
		if err != nil {
			// Enrollment may have committed before its response was lost; never reuse a consumed token as a new identity.
			if recovered, recoveryErr := r.Client.Identity(ctx, private); recoveryErr == nil {
				identity = recovered
				err = nil
			}
		}
	}
	if err != nil {
		return err
	}
	if identity.ClusterID != s.ClusterID || identity.KeyID != protocol.KeyID(private.Public().(ed25519.PublicKey)) {
		return fmt.Errorf("management identity response mismatch")
	}
	if time.Until(identity.ExpiresAt) < protocol.KeyRotationInterval {
		if len(s.PendingKey) == 0 {
			_, next, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			s.PendingKey = next
			if err = r.Store.Save(ctx, &s); err != nil {
				return err
			}
		}
		next := ed25519.PrivateKey(s.PendingKey)
		encoded := protocol.EncodeKey(next.Public().(ed25519.PublicKey))
		input := protocol.Rotation{PublicKey: encoded, Proof: protocol.Proof(next, protocol.RotationMessage(s.ClusterID, identity.KeyID, encoded))}
		var rotated protocol.Identity
		if err = r.Client.Call(ctx, "POST", "/v1/agent/rotate", input, &rotated, private); err != nil {
			return err
		}
		if rotated.KeyID != protocol.KeyID(next.Public().(ed25519.PublicKey)) {
			return fmt.Errorf("rotated identity response mismatch")
		}
		s.PrivateKey = s.PendingKey
		s.PendingKey = nil
		if err = r.Store.Save(ctx, &s); err != nil {
			return err
		}
		private = ed25519.PrivateKey(s.PrivateKey)
	}
	report, err := r.Collector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collect inventory: %w", err)
	}
	if report.ClusterUID != uid {
		return fmt.Errorf("cluster identity changed during collection")
	}
	if s.Version == math.MaxInt64 {
		return fmt.Errorf("inventory version exhausted")
	}
	s.Version++
	report.Version = s.Version
	if err = r.Store.Save(ctx, &s); err != nil {
		return err
	}
	return r.Client.Call(ctx, "POST", "/v1/agent/report", report, nil, private)
}
func (r *Runner) Run(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	backoff := interval
	for {
		step, cancel := context.WithTimeout(ctx, 60*time.Second)
		err := r.Step(step)
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			r.Logger.Warn("agent cycle failed", "error", err.Error())
			backoff = min(backoff*2, 5*time.Minute)
		} else {
			r.Logger.Info("inventory synchronized")
			backoff = interval
		}
		// Cryptographic random jitter prevents synchronized reconnect storms.
		b := make([]byte, 1)
		if _, err = rand.Read(b); err != nil {
			return err
		}
		delay := backoff + time.Duration(b[0])*backoff/1024
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
