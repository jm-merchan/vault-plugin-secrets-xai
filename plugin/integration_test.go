//go:build integration

package xaisecrets

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestIntegrationCreateAndDelete(t *testing.T) {
	key := os.Getenv("XAI_MANAGEMENT_KEY")
	team := os.Getenv("XAI_TEAM_ID")
	if key == "" || team == "" {
		t.Skip("set XAI_MANAGEMENT_KEY and XAI_TEAM_ID to run integration tests")
	}

	client := newClient(defaultAPIEndpoint, key, team, nil)
	info, err := client.Validate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.TeamID != "" && info.TeamID != team {
		t.Logf("management key team %s differs from XAI_TEAM_ID %s", info.TeamID, team)
	}

	created, err := client.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		Name: "vault-plugin-integration",
		ACLs: []string{"api-key:model:*", "api-key:endpoint:chat"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.DeleteAPIKey(context.Background(), created.APIKeyID)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.WaitForPropagation(ctx, created.APIKeyID, 10*time.Second); err != nil {
		t.Logf("propagation warning: %v", err)
	}
	if err := client.DeleteAPIKey(context.Background(), created.APIKeyID); err != nil {
		t.Fatal(err)
	}
}
