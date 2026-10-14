// SPDX-License-Identifier: MPL-2.0

package xaisecrets

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func testBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := Backend()
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	return b, config.StorageView
}

func TestConfigRoundTrip(t *testing.T) {
	mock := newMockXAI("mgmt-secret", "team-1")
	srv := mock.start(t)
	b, storage := testBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"management_api_key": "mgmt-secret",
			"api_endpoint":       srv.URL,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data["team_id"] != "team-1" {
		t.Fatalf("inferred team_id = %v", resp.Data["team_id"])
	}
	if _, exists := resp.Data["management_api_key"]; exists {
		t.Fatal("management_api_key must not be returned")
	}
	if resp.Data["management_api_key_id"] != "mgmt-key-1" {
		t.Fatalf("management_api_key_id = %v", resp.Data["management_api_key_id"])
	}
}

func TestConfigRejectsInvalidEndpoint(t *testing.T) {
	b, storage := testBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"management_api_key": "mgmt-secret",
			"api_endpoint":       "ftp://example.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected invalid endpoint error")
	}
}

func TestDynamicCredsIssueAndRevoke(t *testing.T) {
	mock := newMockXAI("mgmt-secret", "team-1")
	srv := mock.start(t)
	b, storage := testBackend(t)

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"management_api_key": "mgmt-secret",
			"team_id":            "team-1",
			"api_endpoint":       srv.URL,
		},
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/lumen",
		Storage:   storage,
		Data: map[string]interface{}{
			"acls":              []string{"api-key:model:*", "api-key:endpoint:chat"},
			"ttl":               3600,
			"max_ttl":           86400,
			"set_native_expiry": true,
			"qpm":               100,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/lumen",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data["ttl"].(int64) != 3600 {
		t.Fatalf("ttl = %v", resp.Data["ttl"])
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "lumen" {
		t.Fatalf("listed roles = %v", resp.Data["keys"])
	}

	credResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/lumen",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if credResp == nil || credResp.IsError() {
		t.Fatalf("creds error: %+v", credResp)
	}
	if credResp.Data["api_key"] == nil || credResp.Data["api_key_id"] == nil {
		t.Fatalf("missing credential fields: %+v", credResp.Data)
	}
	if credResp.Secret == nil {
		t.Fatal("expected a lease")
	}
	if credResp.Secret.TTL != time.Hour {
		t.Fatalf("lease ttl = %s", credResp.Secret.TTL)
	}
	apiKeyID, _ := credResp.Secret.InternalData["api_key_id"].(string)
	if apiKeyID == "" {
		t.Fatal("lease internal data missing api_key_id")
	}

	mock.mu.Lock()
	if len(mock.createBodies) != 1 {
		t.Fatalf("create calls = %d", len(mock.createBodies))
	}
	body := mock.createBodies[0]
	if _, ok := body["expireTime"]; !ok {
		t.Fatal("expected expireTime on create payload")
	}
	mock.mu.Unlock()

	revResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Storage:   storage,
		Secret:    credResp.Secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	if revResp != nil && revResp.IsError() {
		t.Fatal(revResp.Error())
	}
	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.deleted) != 1 || mock.deleted[0] != apiKeyID {
		t.Fatalf("deleted = %v, want %s", mock.deleted, apiKeyID)
	}
}

func TestRoleTTLValidation(t *testing.T) {
	b, storage := testBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad",
		Storage:   storage,
		Data: map[string]interface{}{
			"ttl":     86400,
			"max_ttl": 3600,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected ttl validation error")
	}
}

func TestCredsUnknownRole(t *testing.T) {
	b, storage := testBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/missing",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected missing role error")
	}
}
