// SPDX-License-Identifier: MPL-2.0

package xaisecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const secretTypeAPIKey = "xai_api_key"

func (b *backend) pathCreds() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role to use.",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "TTL for this credential. Must not exceed the role max_ttl.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathCredsCreate,
				},
			},
			HelpSynopsis:    "Generate a dynamic xAI API key.",
			HelpDescription: "Creates an inference API key via the Management API. Vault revokes the key when the lease expires.",
		},
	}
}

func (b *backend) pathCredsCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q does not exist", roleName), nil
	}

	client, err := b.clientFromStorage(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}

	suffix, err := generateRandomString(8)
	if err != nil {
		return nil, err
	}
	rawName, err := formatName(role.NameTemplate, nameTemplateData{
		RoleName:     roleName,
		RandomSuffix: suffix,
	})
	if err != nil {
		return nil, err
	}
	keyName := sanitizeKeyName(rawName)

	ttl := role.TTL
	if raw, ok := data.GetOk("ttl"); ok {
		requested := time.Duration(raw.(int)) * time.Second
		if requested > role.MaxTTL {
			return logical.ErrorResponse("ttl cannot exceed the role max_ttl"), nil
		}
		if requested > 0 {
			ttl = requested
		}
	}

	createReq := CreateAPIKeyRequest{
		Name: keyName,
		ACLs: role.ACLs,
		QPS:  role.QPS,
		QPM:  role.QPM,
		TPM:  role.TPM,
	}
	if role.SetNativeExpiry {
		exp := time.Now().Add(ttl)
		createReq.ExpireTime = &exp
	}

	key, err := client.CreateAPIKey(ctx, createReq)
	if err != nil {
		return nil, fmt.Errorf("error creating xAI API key: %w", err)
	}

	resp := b.Secret(secretTypeAPIKey).Response(
		map[string]interface{}{
			"api_key":    key.APIKey,
			"api_key_id": key.APIKeyID,
			"name":       key.Name,
		},
		map[string]interface{}{
			"api_key_id": key.APIKeyID,
		},
	)
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = role.MaxTTL

	if err := client.WaitForPropagation(ctx, key.APIKeyID, defaultPropagationWait); err != nil {
		resp.AddWarning(err.Error())
	}

	return resp, nil
}

func (b *backend) secretAPIKey() *framework.Secret {
	return &framework.Secret{
		Type: secretTypeAPIKey,
		Fields: map[string]*framework.FieldSchema{
			"api_key": {
				Type:        framework.TypeString,
				Description: "xAI inference API key.",
			},
			"api_key_id": {
				Type:        framework.TypeString,
				Description: "ID of the xAI API key, used for revocation.",
			},
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the xAI API key.",
			},
		},
		Revoke: b.secretAPIKeyRevoke,
	}
}

func (b *backend) secretAPIKeyRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	apiKeyID, _ := req.Secret.InternalData["api_key_id"].(string)
	if apiKeyID == "" {
		return nil, fmt.Errorf("internal error: api_key_id missing from lease data")
	}

	client, err := b.clientFromStorage(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}
	if err := client.DeleteAPIKey(ctx, apiKeyID); err != nil {
		return nil, fmt.Errorf("error deleting xAI API key: %w", err)
	}
	return nil, nil
}
