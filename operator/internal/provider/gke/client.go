// Package gke provides the narrow Google Kubernetes Engine node-pool API used
// by the provider-native maintenance workflow. It deliberately exposes no
// arbitrary URL or resource methods.
package gke

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"kordex.local/api/protocol"
)

const defaultBaseURL = "https://container.googleapis.com/v1"
const metadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

type TokenSource interface {
	Token(context.Context) (string, error)
}

// MetadataTokenSource uses the attached Google workload identity. It never
// reads service-account key files or accepts credentials from environment.
type MetadataTokenSource struct {
	Client  *http.Client
	mu      sync.Mutex
	token   string
	expires time.Time
}

func (s *MetadataTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Until(s.expires) > time.Minute {
		return s.token, nil
	}
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataTokenURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("get Google workload token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Google workload token endpoint returned HTTP %d", resp.StatusCode)
	}
	var value struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&value); err != nil {
		return "", fmt.Errorf("decode Google workload token: %w", err)
	}
	if value.AccessToken == "" || value.ExpiresIn < 60 || value.TokenType != "Bearer" {
		return "", errors.New("Google workload token response is invalid")
	}
	s.token, s.expires = value.AccessToken, time.Now().Add(time.Duration(value.ExpiresIn)*time.Second)
	return s.token, nil
}

type NodePool struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Status        string `json:"status"`
	StatusMessage string `json:"statusMessage,omitempty"`
	Etag          string `json:"etag"`
	Config        struct {
		ImageType string `json:"imageType"`
	} `json:"config"`
	UpgradeSettings struct {
		MaxSurge       int    `json:"maxSurge"`
		MaxUnavailable int    `json:"maxUnavailable"`
		Strategy       string `json:"strategy"`
	} `json:"upgradeSettings"`
}
type OperationError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type Operation struct {
	Name          string          `json:"name"`
	Status        string          `json:"status"`
	OperationType string          `json:"operationType"`
	TargetLink    string          `json:"targetLink"`
	StartTime     string          `json:"startTime"`
	EndTime       string          `json:"endTime,omitempty"`
	StatusMessage string          `json:"statusMessage,omitempty"`
	Error         *OperationError `json:"error,omitempty"`
}
type operationList struct {
	Operations []Operation `json:"operations"`
}

type Client struct {
	BaseURL string
	HTTP    *http.Client
	Tokens  TokenSource
}

func NewClient() *Client {
	return &Client{BaseURL: defaultBaseURL, HTTP: &http.Client{Timeout: 15 * time.Second}, Tokens: &MetadataTokenSource{}}
}

func (c *Client) GetNodePool(ctx context.Context, ref protocol.GKENodePoolReference) (NodePool, error) {
	var out NodePool
	err := c.do(ctx, http.MethodGet, c.poolPath(ref), nil, &out)
	if err == nil && (out.Name != ref.NodePool || out.Version == "" || out.Etag == "" || out.Config.ImageType == "") {
		return out, errors.New("GKE returned incomplete node-pool state")
	}
	return out, err
}

// UpdateNodePool submits one optimistic-concurrency guarded node-pool version
// change. Callers must durably record intent before invoking it and recover an
// ambiguous response through ListOperations; they must never blindly retry.
func (c *Client) UpdateNodePool(ctx context.Context, ref protocol.GKENodePoolReference, version, imageType, etag string) (Operation, error) {
	if version == "" || imageType == "" || etag == "" {
		return Operation{}, errors.New("GKE node-pool version, image type, and etag are required")
	}
	body := struct {
		Name        string `json:"name"`
		NodeVersion string `json:"nodeVersion"`
		ImageType   string `json:"imageType"`
		Etag        string `json:"etag"`
	}{Name: ref.NodePool, NodeVersion: version, ImageType: imageType, Etag: etag}
	var out Operation
	err := c.do(ctx, http.MethodPut, c.poolPath(ref), body, &out)
	if err == nil && out.Name == "" {
		return out, errors.New("GKE update returned no operation identity")
	}
	return out, err
}

func (c *Client) GetOperation(ctx context.Context, ref protocol.GKENodePoolReference, name string) (Operation, error) {
	if !validOperationName(name, ref) {
		return Operation{}, errors.New("GKE operation identity is outside the authorized project and location")
	}
	var out Operation
	err := c.do(ctx, http.MethodGet, "/"+name, nil, &out)
	if err == nil && out.Name != name {
		return out, errors.New("GKE operation identity mismatch")
	}
	return out, err
}

func (c *Client) ListOperations(ctx context.Context, ref protocol.GKENodePoolReference) ([]Operation, error) {
	path := "/projects/" + url.PathEscape(ref.Project) + "/locations/" + url.PathEscape(ref.Location) + "/operations"
	var out operationList
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out.Operations, err
}

func (c *Client) poolPath(ref protocol.GKENodePoolReference) string {
	return "/projects/" + url.PathEscape(ref.Project) + "/locations/" + url.PathEscape(ref.Location) + "/clusters/" + url.PathEscape(ref.Cluster) + "/nodePools/" + url.PathEscape(ref.NodePool)
}

func (c *Client) do(ctx context.Context, method, path string, body, result any) error {
	if c.Tokens == nil {
		return errors.New("GKE workload identity is not configured")
	}
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = defaultBaseURL
	}
	u, err := url.Parse(base + path)
	if err != nil || u.Scheme != "https" || u.Host != "container.googleapis.com" {
		return errors.New("GKE API endpoint must be the Google Container API over HTTPS")
	}
	var input io.Reader
	if body != nil {
		payload, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			return marshalErr
		}
		input = strings.NewReader(string(payload))
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), input)
	if err != nil {
		return err
	}
	token, err := c.Tokens.Token(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GKE API request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var detail struct {
			Error struct {
				Message string `json:"message"`
				Status  string `json:"status"`
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 32<<10)).Decode(&detail)
		if detail.Error.Status != "" {
			return fmt.Errorf("GKE API HTTP %d (%s): %s", resp.StatusCode, detail.Error.Status, safeMessage(detail.Error.Message))
		}
		return fmt.Errorf("GKE API returned HTTP %d", resp.StatusCode)
	}
	if result == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return err
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(result); err != nil {
		return fmt.Errorf("decode GKE API response: %w", err)
	}
	return nil
}

func validOperationName(name string, ref protocol.GKENodePoolReference) bool {
	parts := strings.Split(name, "/")
	return len(parts) == 6 && parts[0] == "projects" && parts[1] == ref.Project && parts[2] == "locations" && parts[3] == ref.Location && parts[4] == "operations" && parts[5] != ""
}

func safeMessage(s string) string {
	if len(s) > 512 {
		return s[:512]
	}
	return s
}
