// SPDX-License-Identifier: MPL-2.0

package xaisecrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
)

const (
	defaultAPIEndpoint     = "https://management-api.x.ai"
	defaultHTTPTimeout     = 30 * time.Second
	defaultPropagationWait = 10 * time.Second
	defaultPropagationPoll = 250 * time.Millisecond
	maxErrorBody           = 2048
	userAgent              = "vault-plugin-secrets-xai"
)

// Client talks to the xAI Management API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	teamID     string
	logger     hclog.Logger
	now        func() time.Time
	pollWait   time.Duration
}

// CreateAPIKeyRequest is the payload for minting an inference API key.
type CreateAPIKeyRequest struct {
	Name       string
	ACLs       []string
	QPS        *int
	QPM        *int
	TPM        *int
	ExpireTime *time.Time
}

// APIKey is a newly created inference key. APIKey is only present at creation.
type APIKey struct {
	APIKey         string
	APIKeyID       string
	Name           string
	RedactedAPIKey string
	TeamID         string
}

// ManagementKeyInfo is returned by management-key validation.
type ManagementKeyInfo struct {
	APIKeyID string
	TeamID   string
	Scope    string
	ScopeID  string
	UserID   string
}

type createAPIKeyBody struct {
	Name       string   `json:"name"`
	ACLs       []string `json:"acls,omitempty"`
	ACLStrings []string `json:"aclStrings,omitempty"`
	QPS        *int     `json:"qps,omitempty"`
	QPM        *int     `json:"qpm,omitempty"`
	TPM        *int     `json:"tpm,omitempty"`
	ExpireTime *string  `json:"expireTime,omitempty"`
}

type apiKeyResponse struct {
	APIKey         string   `json:"apiKey"`
	APIKeyID       string   `json:"apiKeyId"`
	Name           string   `json:"name"`
	RedactedAPIKey string   `json:"redactedApiKey"`
	TeamID         string   `json:"teamId"`
	Disabled       bool     `json:"disabled"`
	ACLStrings     []string `json:"aclStrings"`
	ACLs           []string `json:"acls"`
}

type validationResponse struct {
	APIKeyID     string   `json:"apiKeyId"`
	TeamID       string   `json:"teamId"`
	Scope        string   `json:"scope"`
	ScopeID      string   `json:"scopeId"`
	ScopeIDSnake string   `json:"scope_id"`
	UserID       string   `json:"userId"`
	ACLs         []string `json:"acls"`
}

type propagationResponse struct {
	ICPropagation map[string]bool `json:"icPropagation"`
}

type httpError struct {
	Status int
	Body   string
}

func (e *httpError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("xAI Management API HTTP %d: %s", e.Status, e.Body)
	}
	return fmt.Sprintf("xAI Management API HTTP %d", e.Status)
}

func (v validationResponse) resolvedTeamID() string {
	if v.TeamID != "" {
		return v.TeamID
	}
	if v.ScopeID != "" {
		return v.ScopeID
	}
	return v.ScopeIDSnake
}

func newClient(endpoint, apiKey, teamID string, logger hclog.Logger) *Client {
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	if endpoint == "" {
		endpoint = defaultAPIEndpoint
	}
	return &Client{
		httpClient: &http.Client{Timeout: defaultHTTPTimeout},
		baseURL:    strings.TrimRight(endpoint, "/"),
		apiKey:     apiKey,
		teamID:     teamID,
		logger:     logger,
		now:        time.Now,
		pollWait:   defaultPropagationPoll,
	}
}

// Validate checks that the management key is accepted and returns its metadata.
func (c *Client) Validate(ctx context.Context) (*ManagementKeyInfo, error) {
	var resp validationResponse
	if err := c.doJSON(ctx, http.MethodGet, []string{"auth", "management-keys", "validation"}, nil, &resp); err != nil {
		return nil, err
	}
	return &ManagementKeyInfo{
		APIKeyID: resp.APIKeyID,
		TeamID:   resp.resolvedTeamID(),
		Scope:    resp.Scope,
		ScopeID:  firstNonEmpty(resp.ScopeID, resp.ScopeIDSnake),
		UserID:   resp.UserID,
	}, nil
}

// CreateAPIKey mints an inference API key on the configured team.
func (c *Client) CreateAPIKey(ctx context.Context, in CreateAPIKeyRequest) (*APIKey, error) {
	if c.teamID == "" {
		return nil, errors.New("team_id is not configured")
	}
	if strings.TrimSpace(in.Name) == "" {
		return nil, errors.New("API key name is required")
	}

	body := createAPIKeyBody{
		Name:       in.Name,
		ACLs:       in.ACLs,
		ACLStrings: in.ACLs,
		QPS:        in.QPS,
		QPM:        in.QPM,
		TPM:        in.TPM,
	}
	if in.ExpireTime != nil {
		stamp := in.ExpireTime.UTC().Format(time.RFC3339)
		body.ExpireTime = &stamp
	}

	var resp apiKeyResponse
	if err := c.doJSON(ctx, http.MethodPost, []string{"auth", "teams", c.teamID, "api-keys"}, body, &resp); err != nil {
		return nil, err
	}
	if resp.APIKey == "" || resp.APIKeyID == "" {
		return nil, errors.New("create API key response missing apiKey or apiKeyId")
	}
	if len(in.ACLs) > 0 && len(resp.ACLStrings) == 0 && len(resp.ACLs) == 0 {
		return nil, fmt.Errorf("xAI created API key %s without the requested ACLs", resp.APIKeyID)
	}
	return &APIKey{
		APIKey:         resp.APIKey,
		APIKeyID:       resp.APIKeyID,
		Name:           resp.Name,
		RedactedAPIKey: resp.RedactedAPIKey,
		TeamID:         resp.TeamID,
	}, nil
}

// DeleteAPIKey permanently deletes an inference API key. A missing key is not an error.
func (c *Client) DeleteAPIKey(ctx context.Context, apiKeyID string) error {
	if apiKeyID == "" {
		return errors.New("api_key_id is required")
	}
	err := c.doJSON(ctx, http.MethodDelete, []string{"auth", "api-keys", apiKeyID}, nil, nil)
	if err == nil || isNotFound(err) {
		return nil
	}
	return err
}

// WaitForPropagation polls until the key is visible on inference clusters or timeout elapses.
func (c *Client) WaitForPropagation(ctx context.Context, apiKeyID string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = defaultPropagationWait
	}
	deadline := c.now().Add(timeout)
	poll := c.pollWait
	if poll <= 0 {
		poll = defaultPropagationPoll
	}

	for {
		done, err := c.propagated(ctx, apiKeyID)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if !c.now().Before(deadline) {
			return fmt.Errorf("timed out waiting for API key %s to propagate", apiKeyID)
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *Client) propagated(ctx context.Context, apiKeyID string) (bool, error) {
	var resp propagationResponse
	if err := c.doJSON(ctx, http.MethodGet, []string{"auth", "api-keys", apiKeyID, "propagation"}, nil, &resp); err != nil {
		return false, err
	}
	if len(resp.ICPropagation) == 0 {
		return true, nil
	}
	for _, ok := range resp.ICPropagation {
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func (c *Client) doJSON(ctx context.Context, method string, parts []string, body any, out any) error {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("invalid api_endpoint: %w", err)
	}
	full := u.JoinPath(parts...)

	var rdr io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, full.String(), rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &httpError{Status: resp.StatusCode, Body: truncateString(string(data), maxErrorBody)}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func isNotFound(err error) bool {
	var he *httpError
	return errors.As(err, &he) && he.Status == http.StatusNotFound
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
