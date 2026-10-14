// SPDX-License-Identifier: MPL-2.0

package xaisecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

var defaultACLs = []string{"api-key:model:*", "api-key:endpoint:*"}

type roleEntry struct {
	NameTemplate    string        `json:"name_template"`
	ACLs            []string      `json:"acls"`
	TTL             time.Duration `json:"ttl"`
	MaxTTL          time.Duration `json:"max_ttl"`
	QPS             *int          `json:"qps,omitempty"`
	QPM             *int          `json:"qpm,omitempty"`
	TPM             *int          `json:"tpm,omitempty"`
	SetNativeExpiry bool          `json:"set_native_expiry"`
}

func (b *backend) pathRoles() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role.",
					Required:    true,
				},
				"name_template": {
					Type:        framework.TypeString,
					Description: "Template for the xAI API key name. Receives RoleName and RandomSuffix.",
					Default:     defaultNameTemplate,
				},
				"acls": {
					Type:        framework.TypeStringSlice,
					Description: "xAI API key ACLs (model and endpoint permissions).",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default TTL for credentials issued by this role.",
					Default:     "1h",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum TTL for credentials issued by this role.",
					Default:     "24h",
				},
				"qps": {
					Type:        framework.TypeInt,
					Description: "Optional queries-per-second limit for issued keys.",
				},
				"qpm": {
					Type:        framework.TypeInt,
					Description: "Optional queries-per-minute limit for issued keys.",
				},
				"tpm": {
					Type:        framework.TypeInt,
					Description: "Optional tokens-per-minute limit for issued keys.",
				},
				"set_native_expiry": {
					Type:        framework.TypeBool,
					Description: "If true, also set expireTime on the xAI key to match the Vault TTL.",
					Default:     true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
				},
			},
			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    "Manage roles that issue xAI API keys.",
			HelpDescription: "Each role defines name templating, ACLs, rate limits, and TTLs for dynamic Grok inference keys.",
		},
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRoleList,
				},
			},
			HelpSynopsis:    "List roles.",
			HelpDescription: "Lists all configured roles.",
		},
	}
}

func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{Data: roleResponseData(role)}, nil
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("role name is required"), nil
	}

	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &roleEntry{
			NameTemplate:    defaultNameTemplate,
			ACLs:            append([]string{}, defaultACLs...),
			TTL:             time.Hour,
			MaxTTL:          24 * time.Hour,
			SetNativeExpiry: true,
		}
	}

	if raw, ok := data.GetOk("name_template"); ok {
		role.NameTemplate = raw.(string)
	} else if role.NameTemplate == "" {
		role.NameTemplate = defaultNameTemplate
	}
	if err := validateNameTemplate(role.NameTemplate); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if raw, ok := data.GetOk("acls"); ok {
		role.ACLs = raw.([]string)
	}
	if len(role.ACLs) == 0 {
		role.ACLs = append([]string{}, defaultACLs...)
	}

	if raw, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(raw.(int)) * time.Second
	}
	if raw, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(raw.(int)) * time.Second
	}
	if role.TTL <= 0 {
		role.TTL = time.Hour
	}
	if role.MaxTTL <= 0 {
		role.MaxTTL = 24 * time.Hour
	}
	if role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	if raw, ok := data.GetOk("qps"); ok {
		v := raw.(int)
		role.QPS = &v
	}
	if raw, ok := data.GetOk("qpm"); ok {
		v := raw.(int)
		role.QPM = &v
	}
	if raw, ok := data.GetOk("tpm"); ok {
		v := raw.(int)
		role.TPM = &v
	}
	if raw, ok := data.GetOk("set_native_expiry"); ok {
		role.SetNativeExpiry = raw.(bool)
	}

	entry, err := logical.StorageEntryJSON(roleStoragePath(name), role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if err := req.Storage.Delete(ctx, roleStoragePath(name)); err != nil {
		return nil, fmt.Errorf("error deleting role: %w", err)
	}
	return nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, fmt.Errorf("error listing roles: %w", err)
	}
	return logical.ListResponse(roles), nil
}

func (b *backend) getRole(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("role name is required")
	}
	entry, err := s.Get(ctx, roleStoragePath(name))
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if entry == nil {
		return nil, nil
	}
	var role roleEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, fmt.Errorf("error decoding role: %w", err)
	}
	return &role, nil
}

func roleStoragePath(name string) string {
	return "roles/" + name
}

func roleResponseData(role *roleEntry) map[string]interface{} {
	out := map[string]interface{}{
		"name_template":     role.NameTemplate,
		"acls":              role.ACLs,
		"ttl":               int64(role.TTL.Seconds()),
		"max_ttl":           int64(role.MaxTTL.Seconds()),
		"set_native_expiry": role.SetNativeExpiry,
	}
	if role.QPS != nil {
		out["qps"] = *role.QPS
	}
	if role.QPM != nil {
		out["qpm"] = *role.QPM
	}
	if role.TPM != nil {
		out["tpm"] = *role.TPM
	}
	return out
}
