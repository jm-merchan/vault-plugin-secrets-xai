// SPDX-License-Identifier: MPL-2.0

package xaisecrets

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const backendHelp = `
The xAI secrets engine issues short-lived Grok inference API keys via the
xAI Management API and revokes them when the Vault lease expires.

Configure a management key (console.x.ai → Settings → Management Keys),
define roles with ACLs and TTLs, then read xai/creds/:name.
`

// Factory creates a new backend for Vault plugin loading.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend constructs the secrets engine without attaching a system view.
func Backend() *backend {
	b := &backend{}
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{configStoragePath},
		},
		Paths: framework.PathAppend(
			b.pathConfig(),
			b.pathRoles(),
			b.pathCreds(),
		),
		Secrets: []*framework.Secret{
			b.secretAPIKey(),
		},
		BackendType: logical.TypeLogical,
	}
	return b
}

type backend struct {
	*framework.Backend
}

func (b *backend) clientFromStorage(ctx context.Context, s logical.Storage) (*Client, error) {
	cfg, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.ManagementAPIKey == "" {
		return nil, errNotConfigured
	}
	return newClient(cfg.APIEndpoint, cfg.ManagementAPIKey, cfg.TeamID, b.Logger()), nil
}
