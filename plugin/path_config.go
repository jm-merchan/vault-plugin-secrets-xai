// SPDX-License-Identifier: MPL-2.0

package xaisecrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

var errNotConfigured = errors.New("plugin is not configured; write xai/config first")

type pluginConfig struct {
	ManagementAPIKey   string `json:"management_api_key"`
	ManagementAPIKeyID string `json:"management_api_key_id"`
	TeamID             string `json:"team_id"`
	APIEndpoint        string `json:"api_endpoint"`
}

func (b *backend) pathConfig() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config$",
			Fields: map[string]*framework.FieldSchema{
				"management_api_key": {
					Type:        framework.TypeString,
					Description: "xAI Management API key from console.x.ai → Settings → Management Keys.",
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
				"team_id": {
					Type:        framework.TypeString,
					Description: "xAI team ID. If omitted, it is inferred from management-key validation.",
				},
				"api_endpoint": {
					Type:        framework.TypeString,
					Description: "xAI Management API base URL.",
					Default:     defaultAPIEndpoint,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigRead,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathConfigDelete,
				},
			},
			ExistenceCheck:  b.pathConfigExistenceCheck,
			HelpSynopsis:    "Configure the xAI Management API credentials.",
			HelpDescription: "Stores the management key used to create and revoke Grok inference API keys. The key is never returned on read.",
		},
	}
}

func (b *backend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return cfg != nil, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &pluginConfig{}
	}

	if raw, ok := data.GetOk("management_api_key"); ok {
		cfg.ManagementAPIKey = raw.(string)
	}
	if raw, ok := data.GetOk("team_id"); ok {
		cfg.TeamID = raw.(string)
	}
	if raw, ok := data.GetOk("api_endpoint"); ok {
		cfg.APIEndpoint = raw.(string)
	}
	if cfg.APIEndpoint == "" {
		cfg.APIEndpoint = defaultAPIEndpoint
	}

	if cfg.ManagementAPIKey == "" {
		return logical.ErrorResponse("management_api_key is required"), nil
	}
	if err := validateAPIEndpoint(cfg.APIEndpoint); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	client := newClient(cfg.APIEndpoint, cfg.ManagementAPIKey, cfg.TeamID, b.Logger())
	info, err := client.Validate(ctx)
	if err != nil {
		return logical.ErrorResponse("failed to validate management API key: %s", err.Error()), nil
	}
	if cfg.TeamID == "" {
		cfg.TeamID = info.TeamID
	}
	if cfg.TeamID == "" {
		return logical.ErrorResponse("team_id is required and could not be inferred from the management key"), nil
	}
	cfg.ManagementAPIKeyID = info.APIKeyID

	if err := storeConfig(ctx, req.Storage, cfg); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"api_endpoint":          cfg.APIEndpoint,
			"team_id":               cfg.TeamID,
			"management_api_key_id": cfg.ManagementAPIKeyID,
		},
	}, nil
}

func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, fmt.Errorf("error deleting config: %w", err)
	}
	return nil, nil
}

func getConfig(ctx context.Context, s logical.Storage) (*pluginConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}
	if entry == nil {
		return nil, nil
	}
	var cfg pluginConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, fmt.Errorf("error decoding config: %w", err)
	}
	return &cfg, nil
}

func storeConfig(ctx context.Context, s logical.Storage, cfg *pluginConfig) error {
	entry, err := logical.StorageEntryJSON(configStoragePath, cfg)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}
