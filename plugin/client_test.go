// SPDX-License-Identifier: MPL-2.0

package xaisecrets

import (
	"context"
	"testing"
	"time"
)

func TestClientValidateCreateDelete(t *testing.T) {
	mock := newMockXAI("mgmt-secret", "team-1")
	srv := mock.start(t)
	client := newClient(srv.URL, "mgmt-secret", "team-1", nil)
	client.pollWait = time.Millisecond

	info, err := client.Validate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.TeamID != "team-1" {
		t.Fatalf("team id = %q", info.TeamID)
	}

	exp := time.Now().Add(time.Hour)
	key, err := client.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		Name:       "vault-lumen-abcd1234",
		ACLs:       []string{"api-key:model:*", "api-key:endpoint:chat"},
		ExpireTime: &exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if key.APIKey == "" || key.APIKeyID == "" {
		t.Fatalf("incomplete key: %+v", key)
	}
	if err := client.WaitForPropagation(context.Background(), key.APIKeyID, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteAPIKey(context.Background(), key.APIKeyID); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteAPIKey(context.Background(), key.APIKeyID); err != nil {
		t.Fatalf("second delete should be idempotent: %v", err)
	}
}

func TestClientUnauthorized(t *testing.T) {
	mock := newMockXAI("mgmt-secret", "team-1")
	srv := mock.start(t)
	client := newClient(srv.URL, "wrong", "team-1", nil)
	_, err := client.Validate(context.Background())
	if err == nil {
		t.Fatal("expected unauthorized error")
	}
}

func TestWaitForPropagationTimeout(t *testing.T) {
	mock := newMockXAI("mgmt-secret", "team-1")
	srv := mock.start(t)
	client := newClient(srv.URL, "mgmt-secret", "team-1", nil)
	client.pollWait = time.Millisecond

	key, err := client.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		Name: "vault-timeout",
		ACLs: defaultACLs,
	})
	if err != nil {
		t.Fatal(err)
	}
	mock.mu.Lock()
	mock.propagated[key.APIKeyID] = false
	mock.mu.Unlock()

	err = client.WaitForPropagation(context.Background(), key.APIKeyID, 20*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout")
	}
}

func TestSanitizeKeyName(t *testing.T) {
	got := sanitizeKeyName("vault lumen/role!")
	if got != "vault-lumen-role" {
		t.Fatalf("got %q", got)
	}
	if sanitizeKeyName("***") != "vault-key" {
		t.Fatalf("empty sanitize = %q", sanitizeKeyName("***"))
	}
}
