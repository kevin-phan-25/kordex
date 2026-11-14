// Package client implements outbound HTTPS; it never accesses the management database.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"kordex.local/api/protocol"
)

type APIError struct {
	Status int
	Code   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("management API status %d (%s)", e.Status, e.Code)
}

type Client struct {
	BaseURL   string
	HTTP      *http.Client
	ClusterID string
}

func New(base, cluster string, local bool, caPEM []byte) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("control plane URL must be an origin")
	}
	if !protocol.ValidUUID(cluster) {
		return nil, fmt.Errorf("invalid configured cluster ID")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if !local || u.Scheme != "http" || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return nil, fmt.Errorf("HTTPS required; local HTTP is limited to loopback")
		}
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if len(caPEM) > 0 && !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid management CA bundle")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	// Never forward signed identity headers across redirects.
	h := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{BaseURL: u.Scheme + "://" + u.Host, HTTP: h, ClusterID: cluster}, nil
}
func (c *Client) Call(ctx context.Context, method, path string, input, output any, key ed25519.PrivateKey) error {
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return err
		}
	}
	if len(body) > protocol.MaxReportBytes {
		return fmt.Errorf("inventory request exceeds size limit")
	}
	r, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	if len(key) > 0 {
		protocol.Sign(r, c.ClusterID, key, body, time.Now())
	}
	response, err := c.HTTP.Do(r)
	if err != nil {
		return fmt.Errorf("management transport unavailable")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var v struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(data, &v); err != nil {
			v.Error = "invalid_error_response"
		}
		return &APIError{Status: response.StatusCode, Code: v.Error}
	}
	if output != nil {
		if err = json.Unmarshal(data, output); err != nil {
			return fmt.Errorf("invalid management response")
		}
	}
	return nil
}
func (c *Client) Identity(ctx context.Context, key ed25519.PrivateKey) (protocol.Identity, error) {
	var v protocol.Identity
	err := c.Call(ctx, "GET", "/v1/agent/identity", nil, &v, key)
	return v, err
}
func (c *Client) Enroll(ctx context.Context, uid, token string, key ed25519.PrivateKey) (protocol.Identity, error) {
	e := protocol.Enrollment{ClusterID: c.ClusterID, ClusterUID: uid, Token: token, PublicKey: protocol.EncodeKey(key.Public().(ed25519.PublicKey))}
	e.Proof = protocol.Proof(key, protocol.EnrollmentMessage(e))
	var v protocol.Identity
	err := c.Call(ctx, "POST", "/v1/agent/enroll", e, &v, nil)
	return v, err
}
